//! MSI update context is authoritative, not inferred from a display registry entry.
//! An existing copy must never fall back to a fresh installation when discovery fails.

use std::path::Path;

use crate::install::MsiScope;

const UNKNOWN_CONTEXT: &str = "Windows could not confirm who this app is installed for. No changes were made. Try the app's installer instead.";
const CONFLICTING_CONTEXT: &str = "This app is installed for both your account and everyone. Use its installer to choose which copy to update.";

/// Why the Windows Installer lookup gave no context.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProbeError {
    /// The lookup ran but gave no usable answer. The context is never guessed from that.
    Unknown,
    /// The same product is registered for this account and for everyone.
    Conflicting,
    /// The lookup could not run (a blocked shell, a timeout, a slow first start). Carries the real
    /// error so it can be logged.
    Unavailable(String),
}

/// The context an update must keep. Windows Installer's own registration decides. Only when that
/// lookup cannot run at all does the context come from the uninstall record the copy was found by
/// (`record_scope`): the machine's records are per-machine and the account's own are per-user. A
/// lookup that ran and gave no answer, or a copy registered twice, still stops the update.
pub(crate) fn update_scope(
    is_msi: bool,
    product_code: Option<&str>,
    probe: impl FnOnce(&str) -> Result<MsiScope, ProbeError>,
    record_scope: impl FnOnce(&str) -> Option<MsiScope>,
) -> Result<Option<MsiScope>, String> {
    if !is_msi {
        return Ok(None);
    }
    let code = product_code.filter(|code| valid_product_code(code)).ok_or(UNKNOWN_CONTEXT)?;
    match probe(code) {
        Ok(scope) => Ok(Some(scope)),
        Err(ProbeError::Conflicting) => Err(CONFLICTING_CONTEXT.into()),
        Err(ProbeError::Unknown) => Err(UNKNOWN_CONTEXT.into()),
        Err(ProbeError::Unavailable(reason)) => {
            log::warn!("Windows Installer context lookup for {code} could not run: {reason}");
            let scope = record_scope(code).ok_or(UNKNOWN_CONTEXT)?;
            log::info!("{code}: keeping the {scope:?} context of its uninstall record");
            Ok(Some(scope))
        }
    }
}

/// The one context every uninstall record of a product agrees on. Records that disagree (the copy is
/// registered for this account and for everyone) or no records at all give `None`, so the update stops.
pub(crate) fn single_scope(scopes: impl IntoIterator<Item = MsiScope>) -> Option<MsiScope> {
    let mut scopes = scopes.into_iter();
    let first = scopes.next()?;
    scopes.all(|scope| scope == first).then_some(first)
}

/// The context for a fresh install. A package that defaults to per-user cannot write to a folder this
/// account has no write access to (a custom folder under Program Files), so that install is machine-wide
/// and Windows asks for permission. Any other fresh install takes the package's own default.
pub(crate) fn fresh_scope(destination: Option<&Path>, writable: impl FnOnce(&Path) -> bool) -> Option<MsiScope> {
    destination.filter(|folder| !writable(folder)).map(|_| MsiScope::PerMachine)
}

pub(crate) fn valid_product_code(code: &str) -> bool {
    code.len() == 38
        && code.bytes().enumerate().all(|(index, byte)| match index {
            0 => byte == b'{',
            37 => byte == b'}',
            9 | 14 | 19 | 24 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn parse_contexts(output: &str) -> Result<MsiScope, ProbeError> {
    let mut scope = None;
    for line in output.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let context = match line {
            "1" | "2" => MsiScope::PerUser,
            "4" => MsiScope::PerMachine,
            _ => return Err(ProbeError::Unknown),
        };
        if scope.is_some_and(|previous| previous != context) {
            return Err(ProbeError::Conflicting);
        }
        scope = Some(context);
    }
    scope.ok_or(ProbeError::Unknown)
}

#[cfg(windows)]
pub(crate) fn probe(product_code: &str) -> Result<MsiScope, ProbeError> {
    use std::path::PathBuf;
    use std::time::Duration;

    if !valid_product_code(product_code) {
        return Err(ProbeError::Unknown);
    }
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|root| root.is_absolute())
        .ok_or_else(|| ProbeError::Unavailable("SystemRoot is not set to an absolute path".into()))?;
    let powershell = root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    // Only a validated GUID is interpolated. ProductsEx reads registration for the current
    // account and the machine, never another account and never Win32_Product (which repairs).
    let script = format!("$code='{product_code}';\n{}", include_str!("msi_context.ps1"));
    let mut command = crate::process::command(powershell);
    command.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    let output = crate::process::run_command(command, "Windows installation lookup", Duration::from_secs(10)).map_err(ProbeError::Unavailable)?;
    parse_contexts(&output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = "{12345678-1234-1234-1234-123456789ABC}";

    #[test]
    fn authoritative_machine_context_is_preserved() {
        assert_eq!(parse_contexts("4\r\n"), Ok(MsiScope::PerMachine));
    }

    #[test]
    fn managed_and_unmanaged_accounts_are_both_per_user() {
        assert_eq!(parse_contexts("1\n"), Ok(MsiScope::PerUser));
        assert_eq!(parse_contexts("2\n"), Ok(MsiScope::PerUser));
        assert_eq!(parse_contexts("1\n2\n"), Ok(MsiScope::PerUser));
    }

    #[test]
    fn missing_unknown_or_conflicting_contexts_are_not_guessed() {
        for output in ["", " \r\n", "0", "7", "user", "2\n4", "4\n1", "4\nnoise"] {
            assert!(parse_contexts(output).is_err(), "{output:?}");
        }
        assert_eq!(parse_contexts("4\n1"), Err(ProbeError::Conflicting));
        assert_eq!(parse_contexts("7"), Err(ProbeError::Unknown));
    }

    #[test]
    fn fresh_installs_do_not_probe_or_override_the_package_default() {
        assert_eq!(update_scope(false, None, |_| Err(ProbeError::Unknown), |_| None), Ok(None));
    }

    #[test]
    fn known_updates_keep_the_authoritative_context() {
        for scope in [MsiScope::PerUser, MsiScope::PerMachine] {
            assert_eq!(update_scope(true, Some(CODE), |_| Ok(scope), |_| None), Ok(Some(scope)));
        }
    }

    #[test]
    fn an_update_without_its_product_code_stops_before_probing() {
        let called = std::cell::Cell::new(false);
        assert!(
            update_scope(
                true,
                None,
                |_| {
                    called.set(true);
                    Ok(MsiScope::PerMachine)
                },
                |_| None
            )
            .is_err()
        );
        assert!(!called.get());
    }

    #[test]
    fn malformed_product_codes_stop_before_any_shell_call() {
        for code in ["", "not-a-guid", "{12345678-1234-1234-1234-123456789ABZ}", "';exit 0;#", "{12345678-1234-1234-1234-123456789ABC}\n"] {
            let called = std::cell::Cell::new(false);
            assert!(
                update_scope(
                    true,
                    Some(code),
                    |_| {
                        called.set(true);
                        Ok(MsiScope::PerMachine)
                    },
                    |_| None
                )
                .is_err()
            );
            assert!(!called.get(), "{code:?}");
        }
    }

    #[test]
    fn unavailable_context_never_becomes_a_fresh_install() {
        let unavailable = || Err(ProbeError::Unavailable("query failed".into()));
        assert!(update_scope(true, Some(CODE), |_| unavailable(), |_| None).is_err());
    }

    #[test]
    fn a_lookup_that_cannot_run_falls_back_to_the_uninstall_record() {
        for scope in [MsiScope::PerUser, MsiScope::PerMachine] {
            let seen = std::cell::RefCell::new(String::new());
            let result = update_scope(
                true,
                Some(CODE),
                |_| Err(ProbeError::Unavailable("PowerShell is blocked".into())),
                |code| {
                    *seen.borrow_mut() = code.to_owned();
                    Some(scope)
                },
            );
            assert_eq!(result, Ok(Some(scope)));
            assert_eq!(*seen.borrow(), CODE);
        }
    }

    #[test]
    fn an_answer_that_is_unclear_or_doubled_never_uses_the_uninstall_record() {
        for failure in [ProbeError::Unknown, ProbeError::Conflicting] {
            let result = update_scope(true, Some(CODE), |_| Err(failure), |_| panic!("must not consult the record"));
            assert!(result.is_err());
        }
    }

    #[test]
    fn a_blocked_lookup_without_a_record_stops_the_update() {
        let result = update_scope(true, Some(CODE), |_| Err(ProbeError::Unavailable("timed out".into())), |_| None);
        assert_eq!(result, Err(UNKNOWN_CONTEXT.to_string()));
    }

    #[test]
    fn records_in_two_contexts_give_no_fallback_scope() {
        assert_eq!(single_scope([]), None);
        assert_eq!(single_scope([MsiScope::PerUser]), Some(MsiScope::PerUser));
        assert_eq!(single_scope([MsiScope::PerMachine, MsiScope::PerMachine]), Some(MsiScope::PerMachine));
        assert_eq!(single_scope([MsiScope::PerMachine, MsiScope::PerUser]), None);
        assert_eq!(single_scope([MsiScope::PerUser, MsiScope::PerMachine, MsiScope::PerMachine]), None);
    }

    #[test]
    fn a_fresh_install_into_a_folder_the_account_cannot_write_is_machine_wide() {
        let folder = Path::new(r"C:\Program Files\Custom\PhotoCraft");
        assert_eq!(fresh_scope(Some(folder), |_| false), Some(MsiScope::PerMachine));
        assert_eq!(fresh_scope(Some(folder), |_| true), None);
        assert_eq!(fresh_scope(None, |_| panic!("no folder, nothing to test")), None);
    }
}
