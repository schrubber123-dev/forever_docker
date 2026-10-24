//! Game preparation and start: WTF config, Launch Options\WoW (auto-login), WowB.exe -launcherlogin.
//! macOS starts a copy of the game app instead: see macos.rs.

use crate::config::Settings;
use crate::i18n::tf;
use std::path::Path;
#[cfg(not(target_os = "macos"))]
use std::process::{Child, Command};

pub const WTF_NAME: &str = "ForeverLauncher.wtf";
#[cfg(not(target_os = "macos"))]
const LAUNCH_OPTIONS: &str = r"Software\Blizzard Entertainment\Battle.net\Launch Options\WoW";

/// WTF/ForeverLauncher.wtf: a copy of Config.wtf with the portal and the language set.
pub fn write_wtf(settings: &Settings) -> Result<(), String> {
    let dir = Path::new(&settings.game_dir).join("WTF");
    std::fs::create_dir_all(&dir).map_err(|e| tf("wtf_folder", &[&e]))?;
    let path = dir.join(WTF_NAME);
    let base = dir.join("Config.wtf");
    let text = std::fs::read_to_string(&path).or_else(|_| std::fs::read_to_string(&base)).unwrap_or_default();
    let wanted = [
        ("portal", settings.server.portal.clone()),
        ("textLocale", settings.locale.clone()),
        ("audioLocale", settings.locale.clone()),
    ];
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| !wanted.iter().any(|(k, _)| l.starts_with(&format!("SET {k} "))))
        .map(str::to_string)
        .collect();
    for (k, v) in wanted {
        lines.push(format!("SET {k} \"{v}\""));
    }
    std::fs::write(&path, lines.join("\r\n") + "\r\n").map_err(|e| format!("{} : {e}", path.display()))
}

/// Stores the login ticket where the client reads it with -launcherlogin.
#[cfg(windows)]
pub fn write_launch_options(_settings: &Settings, portal: &str, ticket: &str, game_account: &str) -> Result<(), String> {
    use windows::core::HSTRING;
    use windows::Win32::System::Registry::*;
    let blob = crate::dpapi::protect(ticket.as_bytes()).map_err(|e| {
        crate::windows_diagnostics::record("WEB_TOKEN DPAPI encryption FAILED"); e
    })?;
    unsafe {
        let mut key = HKEY::default();
        RegCreateKeyExW(HKEY_CURRENT_USER, &HSTRING::from(LAUNCH_OPTIONS), 0, None, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE, None, &mut key, None)
            .ok()
            .map_err(|e| {
                crate::windows_diagnostics::record(&format!("Launch Options registry open FAILED: {e}"));
                tf("registry", &[&e])
            })?;
        let set_str = |name: &str, value: &str| {
            let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
            let bytes = std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2);
            RegSetValueExW(key, &HSTRING::from(name), 0, REG_SZ, Some(bytes)).ok()
        };
        let r = set_str("CONNECTION_STRING", portal)
            .and_then(|_| set_str("GAME_ACCOUNT", game_account))
            .and_then(|_| RegSetValueExW(key, &HSTRING::from("WEB_TOKEN"), 0, REG_BINARY, Some(&blob)).ok());
        let result = r.map_err(|e| {
            crate::windows_diagnostics::record(&format!("Launch Options registry write FAILED: {e}"));
            tf("registry", &[&e])
        }).and_then(|_| {
            // Read back through the same registry API as the client. Never include ticket bytes
            // (encrypted or plaintext) in errors or logs.
            let read = |name: &str, expected_type, expected: &[u8]| -> Result<Vec<u8>, String> {
                let mut kind = REG_VALUE_TYPE::default();
                let mut bytes = vec![0u8; expected.len()];
                let mut size = bytes.len() as u32;
                let status = RegQueryValueExW(key, &HSTRING::from(name), None, Some(&mut kind), Some(bytes.as_mut_ptr()), Some(&mut size));
                let type_name = match kind { REG_SZ => "REG_SZ", REG_BINARY => "REG_BINARY", _ => "other" };
                crate::windows_diagnostics::record(&format!("{name} read-back: status={} type={type_name}({}) length_bytes={size}", status.0, kind.0));
                status.ok().map_err(|e| format!("Launch Options/{name} read-back failed: {e}"))?;
                if kind != expected_type || size as usize != expected.len() || bytes != expected {
                    crate::windows_diagnostics::record(&format!("{name} read-back comparison FAILED"));
                    return Err(format!("Launch Options/{name} read-back type or data mismatch"));
                }
                Ok(bytes)
            };
            let mut errors = Vec::new();
            for (name, value) in [("CONNECTION_STRING", portal), ("GAME_ACCOUNT", game_account)] {
                let bytes: Vec<u8> = value.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect();
                if let Err(e) = read(name, REG_SZ, &bytes) { errors.push(e); }
            }
            match read("WEB_TOKEN", REG_BINARY, &blob) {
                Ok(stored) => {
                    let result = crate::dpapi::verify(&stored, ticket.as_bytes());
                    crate::windows_diagnostics::record(if result.is_ok() { "WEB_TOKEN DPAPI decrypt verification SUCCESS" } else { "WEB_TOKEN DPAPI decrypt verification FAILED" });
                    if let Err(e) = result { errors.push(e); }
                }
                Err(e) => {
                    crate::windows_diagnostics::record("WEB_TOKEN DPAPI decrypt verification NOT RUN: registry read-back failed");
                    errors.push(e);
                }
            }
            if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
        });
        let _ = RegCloseKey(key);
        result
    }
}

/// Linux: the same values in the prefix registry, through `reg import` (the Wine DPAPI blob is built here).
#[cfg(target_os = "linux")]
pub fn write_launch_options(settings: &Settings, portal: &str, ticket: &str, game_account: &str) -> Result<(), String> {
    use crate::dpapi::{wine, WEB_TOKEN_ENTROPY};
    let blob = wine::protect(ticket.as_bytes(), wine::PROTON_USER, &WEB_TOKEN_ENTROPY);
    let hexdata: Vec<String> = blob.iter().map(|b| format!("{b:02x}")).collect();
    let content = format!(
        "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\{LAUNCH_OPTIONS}]\r\n\"WEB_TOKEN\"=hex:{}\r\n\"GAME_ACCOUNT\"=\"{game_account}\"\r\n\"CONNECTION_STRING\"=\"{portal}\"\r\n",
        hexdata.join(",")
    );
    // regedit files are UTF-16 LE with a BOM; Wine sees the Linux file system as Z:
    let mut bytes = vec![0xFF, 0xFE];
    for u in content.encode_utf16() {
        bytes.extend(u.to_le_bytes());
    }
    let dir = crate::config::config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let file = dir.join("launch-options.reg");
    std::fs::write(&file, bytes).map_err(|e| e.to_string())?;
    let wine_path = format!("Z:{}", file.to_string_lossy().replace('/', "\\"));
    let res = crate::system::run_in_prefix(settings, &["reg", "import", &wine_path]);
    let _ = std::fs::remove_file(&file);
    res
}

#[cfg(windows)]
pub fn spawn(settings: &Settings) -> Result<Child, String> {
    use std::os::windows::process::CommandExt;
    use windows::Win32::System::Threading::CREATE_SUSPENDED;

    let baseline = crate::windows_diagnostics::before_launch();
    crate::windows_diagnostics::record(
        "Standalone PoC: creating WowB suspended without -launcherlogin; no DLL injection"
    );
    let mut child = Command::new(settings.exe())
        .args(["-config", WTF_NAME])
        .current_dir(&settings.game_dir)
        .creation_flags(CREATE_SUSPENDED.0)
        .spawn()
        .map_err(|e| tf("launch_failed", &[&"WowB.exe", &e]))?;

    if let Err(e) = crate::standalone::patch_and_resume(child.id(), settings) {
        crate::windows_diagnostics::record(&format!("Standalone PoC FAILED before resume: {e}"));
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    crate::windows_diagnostics::after_launch(child.id(), baseline);
    Ok(child)
}

#[cfg(target_os = "linux")]
pub fn spawn(settings: &Settings) -> Result<Child, String> {
    let (runner, mut env) = crate::system::runner(settings)?;
    let mut cmd: Vec<String> = runner;
    cmd.push(settings.exe().to_string_lossy().into_owned());
    cmd.extend(["-launcherlogin", "-config", WTF_NAME].map(String::from));
    let l = &settings.linux;
    if l.gamescope && crate::system::which("gamescope") {
        // gamescope starts its own Xwayland with a US keyboard unless told otherwise
        let (layout, variant) = l.keyboard.split_once('+').unwrap_or((l.keyboard.as_str(), ""));
        if !layout.is_empty() {
            env.push(("XKB_DEFAULT_LAYOUT".into(), layout.into()));
        }
        if !variant.is_empty() {
            env.push(("XKB_DEFAULT_VARIANT".into(), variant.into()));
        }
        let mut wrapped = vec!["gamescope".to_string()];
        wrapped.extend(l.gamescope_args.split_whitespace().map(String::from));
        wrapped.push("--".into());
        wrapped.extend(cmd);
        cmd = wrapped;
    }
    crate::system::clean_env(&mut Command::new(&cmd[0]))
        .args(&cmd[1..])
        .envs(env)
        .current_dir(&settings.game_dir)
        .spawn()
        .map_err(|e| tf("launch_failed", &[&cmd[0], &e]))
}
