//! Windows-only, deliberately allowlisted diagnostics: never record tokens or environment values.
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_FILES};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

static LOG: Mutex<Option<File>> = Mutex::new(None);

pub fn begin() -> Result<std::path::PathBuf, String> {
    let path = crate::config::config_dir().join("windows-launch-diagnostics.log");
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| format!("Diagnostic log folder: {e}"))?;
    let mut file = OpenOptions::new().create(true).append(true).open(&path)
        .map_err(|e| format!("Diagnostic log: {e}"))?;
    writeln!(file, "\n=== Play session; revision={} ===", option_env!("FOREVER_DIAGNOSTIC_REVISION").unwrap_or("local build, revision not supplied"))
        .map_err(|e| format!("Diagnostic log: {e}"))?;
    *LOG.lock().unwrap() = Some(file);
    let mut names: Vec<_> = std::env::vars_os().map(|(n, _)| n.to_string_lossy().into_owned())
        .filter(|n| n.to_ascii_uppercase().starts_with("BNET_")).collect();
    names.sort();
    record(&format!("Inherited BNET_* names only: {names:?}"));
    record("Observation: registry reads do not prove endpoint use. Investigating absent private-server TCP/1119 connection.");
    Ok(path)
}

pub fn record(message: &str) {
    if let Some(file) = LOG.lock().unwrap().as_mut() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
        // Each line is flushed by File::write; no user/account/token strings are accepted by callers.
        let _ = writeln!(file, "[{now} ms since Unix epoch] {message}");
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Process {
    name: &'static str,
    pid: u32,
    parent: u32,
}

fn processes() -> Result<Vec<Process>, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).map_err(|e| e.to_string())?;
        let result = (|| {
            let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
            let mut next = Process32FirstW(snapshot, &mut entry);
            let mut out = Vec::new();
            loop {
                if let Err(e) = next {
                    if e.code() == ERROR_NO_MORE_FILES.to_hresult() { break; }
                    return Err(e.to_string());
                }
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                let name = if name.eq_ignore_ascii_case("Agent.exe") { Some("Agent.exe") }
                    else if name.eq_ignore_ascii_case("WowB.exe") { Some("WowB.exe") } else { None };
                if let Some(name) = name {
                    out.push(Process { name, pid: entry.th32ProcessID, parent: entry.th32ParentProcessID });
                }
                next = Process32NextW(snapshot, &mut entry);
            }
            out.sort();
            Ok(out)
        })();
        let _ = CloseHandle(snapshot);
        result
    }
}

pub fn before_launch() -> Option<Vec<Process>> {
    match processes() {
        Ok(list) => { record(&format!("Before WowB spawn: {list:?} (empty means neither process observed)")); Some(list) }
        Err(e) => { record(&format!("Before WowB spawn: process snapshot FAILED: {e}")); None }
    }
}

pub fn after_launch(pid: u32, baseline: Option<Vec<Process>>) {
    record(&format!("Spawned WowB.exe pid={pid}; args=-launcherlogin -config ForeverLauncher.wtf"));
    std::thread::spawn(move || {
        record("Process observation started: 60 seconds, 250ms polling; brief processes may be missed; appearances do not prove Agent causation/relaunch.");
        let mut previous = baseline;
        for _ in 0..240 {
            match processes() {
                Ok(list) => {
                    if previous.as_ref() != Some(&list) {
                        if let Some(old) = &previous {
                            for p in list.iter().filter(|p| !old.contains(p)) { record(&format!("Process appeared: {p:?}")); }
                            for p in old.iter().filter(|p| !list.contains(p)) { record(&format!("Process disappeared: {p:?}")); }
                        } else { record(&format!("First available process snapshot: {list:?}")); }
                        previous = Some(list);
                    }
                }
                Err(e) => { record(&format!("Process observation FAILED: {e}")); return; }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        record("Process observation completed (60 seconds). Use Procmon for exact process-start/relaunch evidence.");
    });
}
