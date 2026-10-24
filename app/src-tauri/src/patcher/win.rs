//! Windows: ReadProcessMemory / WriteProcessMemory on the WowB.exe process started by the launcher.

use super::Memory;
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE,
    PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_NOACCESS,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

#[link(name = "ntdll")]
extern "system" {
    fn NtSuspendProcess(process_handle: HANDLE) -> i32;
    fn NtResumeProcess(process_handle: HANDLE) -> i32;
}

// Minimal Arctium-compatible certificate validation anchors.  These are
// runtime-only patches for the private Forever server PoC; WowB.exe on disk is
// never modified.
const WC: i16 = -1;
const INTEGRITY_PATTERN: &[i16] = &[
    0x44, 0x89, WC, 0x24, WC, 0x44, 0x89, WC, 0x24, WC, 0x89, WC, 0x24, WC,
    0x48, 0x89, WC, 0x24, WC, 0x53, 0x56, 0x57,
];
const CERT_BUNDLE_BRANCH_PATTERN: &[i16] = &[0x75, 0x06, 0x48, WC, WC, 0x60, 0x5F, 0xC3];
const CERT_COMMON_NAME_PATTERN: &[i16] = &[0x80, WC, 0x2A, 0x75, WC, 0x32, 0xC0, 0x48];
const CERT_CHAIN_PATTERN: &[i16] = &[
    0x32, 0xDB, 0xEB, 0x02, 0xB3, 0x01, 0x48, 0x83, WC, WC, 0x00, 0x00, 0x00, 0x00,
];

pub struct ProcessMemory {
    pid: u32,
    handle: HANDLE,
}

unsafe impl Send for ProcessMemory {}

impl Drop for ProcessMemory {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

impl ProcessMemory {
    pub fn open(pid: u32) -> Option<Self> {
        let access = PROCESS_VM_READ
            | PROCESS_VM_WRITE
            | PROCESS_VM_OPERATION
            | PROCESS_QUERY_INFORMATION
            | PROCESS_SUSPEND_RESUME;
        let handle = unsafe { OpenProcess(access, false, pid) }.ok()?;
        Some(Self { pid, handle })
    }


    fn image_regions(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut addr: usize = 0;
        loop {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            let n = unsafe {
                VirtualQueryEx(
                    self.handle,
                    Some(addr as *const c_void),
                    &mut info,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if n == 0 {
                break;
            }
            let base = info.BaseAddress as usize;
            let blocked = (info.Protect.0 & (PAGE_NOACCESS.0 | PAGE_GUARD.0)) != 0;
            if info.State == MEM_COMMIT && info.Type == MEM_IMAGE && !blocked {
                out.push((base as u64, (base + info.RegionSize) as u64));
            }
            let next = base.saturating_add(info.RegionSize);
            if next <= addr {
                break;
            }
            addr = next;
        }
        out
    }

    fn pattern_hits(&self, pattern: &[i16]) -> Vec<u64> {
        const CHUNK: usize = 8 * 1024 * 1024;
        let mut hits = Vec::new();

        for (lo, hi) in self.image_regions() {
            let mut off = lo;
            while off < hi {
                let remaining = (hi - off) as usize;
                let take = CHUNK.min(remaining);
                let Some(buf) = <Self as Memory>::read(self, off, take) else { break };
                if buf.len() < pattern.len() {
                    break;
                }

                for local in 0..=buf.len() - pattern.len() {
                    let matched = pattern.iter().enumerate().all(|(i, p)| {
                        *p < 0 || buf[local + i] == *p as u8
                    });
                    if matched {
                        hits.push(off + local as u64);
                    }
                }

                if take < CHUNK || buf.len() <= pattern.len() {
                    break;
                }
                off = off.saturating_add((buf.len() - (pattern.len() - 1)) as u64);
            }
        }

        hits.sort_unstable();
        hits.dedup();
        hits
    }

    fn patch_code(&self, address: u64, bytes: &[u8]) -> Result<(), String> {
        let mut old = Default::default();
        unsafe {
            VirtualProtectEx(
                self.handle,
                address as *const c_void,
                bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old,
            )
            .map_err(|e| format!("VirtualProtectEx failed at 0x{address:X}: {e}"))?;
        }

        let mut written = 0usize;
        let write = unsafe {
            WriteProcessMemory(
                self.handle,
                address as *const c_void,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                Some(&mut written),
            )
        };

        let mut ignored = Default::default();
        let restore = unsafe {
            VirtualProtectEx(
                self.handle,
                address as *const c_void,
                bytes.len(),
                old,
                &mut ignored,
            )
        };

        write.map_err(|e| format!("WriteProcessMemory failed at 0x{address:X}: {e}"))?;
        restore.map_err(|e| format!("restoring page protection failed at 0x{address:X}: {e}"))?;
        if written != bytes.len() {
            return Err(format!("short code write at 0x{address:X}: {written}/{}", bytes.len()));
        }
        match <Self as Memory>::read(self, address, bytes.len()) {
            Some(after) if after == bytes => Ok(()),
            _ => Err(format!("code write verification failed at 0x{address:X}")),
        }
    }

    fn patch_pattern(
        &self,
        label: &str,
        pattern: &[i16],
        mutate: fn(&mut [u8]),
        report: &mut Vec<String>,
    ) -> Result<usize, String> {
        let hits = self.pattern_hits(pattern);
        report.push(format!("TLS cert PoC: {label} hits={}", hits.len()));
        let mut applied = 0usize;

        for address in hits {
            let Some(mut bytes) = <Self as Memory>::read(self, address, pattern.len()) else {
                continue;
            };
            if bytes.len() != pattern.len() {
                continue;
            }
            mutate(&mut bytes);
            self.patch_code(address, &bytes)?;
            applied += 1;
            report.push(format!("TLS cert PoC: {label} patched at 0x{address:X}"));
        }
        Ok(applied)
    }

    /// Runtime-only certificate-validation PoC for Forever 70450.
    ///
    /// The game is allowed to initialise/decrypt normally. We then wait until
    /// one of the known certificate-validation code anchors becomes visible,
    /// suspend the process briefly, patch only validated pattern matches, and
    /// resume it. No DLL is injected and WowB.exe is not changed on disk.
    pub fn apply_tls_cert_poc(&self) -> Result<Vec<String>, String> {
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + Duration::from_secs(120);
        let mut seen = (0usize, 0usize, 0usize);

        loop {
            seen = (
                self.pattern_hits(CERT_BUNDLE_BRANCH_PATTERN).len(),
                self.pattern_hits(CERT_COMMON_NAME_PATTERN).len(),
                self.pattern_hits(CERT_CHAIN_PATTERN).len(),
            );
            if seen.0 + seen.1 + seen.2 > 0 {
                break;
            }
            if !<Self as Memory>::alive(self) {
                return Err("WowB closed before TLS certificate patterns became visible".into());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "no 70450 TLS certificate patterns found after 120s, including the manual login window (bundle={}, common-name={}, chain={})",
                    seen.0, seen.1, seen.2
                ));
            }
            std::thread::sleep(Duration::from_millis(250));
        }

        let suspended = unsafe { NtSuspendProcess(self.handle) };
        if suspended < 0 {
            return Err(format!(
                "NtSuspendProcess failed before TLS cert patch, NTSTATUS=0x{:08X}",
                suspended as u32
            ));
        }

        let mut report = vec![format!(
            "TLS cert PoC: decrypted cert code visible (bundle={}, common-name={}, chain={}); process suspended",
            seen.0, seen.1, seen.2
        )];

        let patch_result = (|| -> Result<(), String> {
            let mut total = 0usize;

            total += self.patch_pattern(
                "Integrity",
                INTEGRITY_PATTERN,
                |bytes| {
                    if bytes.len() >= 3 {
                        bytes[0] = 0xC2;
                        bytes[1] = 0x00;
                        bytes[2] = 0x00;
                    }
                },
                &mut report,
            )?;

            total += self.patch_pattern(
                "CertBundle branch",
                CERT_BUNDLE_BRANCH_PATTERN,
                |bytes| {
                    if bytes.len() >= 2 {
                        bytes[0] = 0x90;
                        bytes[1] = 0x90;
                    }
                },
                &mut report,
            )?;

            total += self.patch_pattern(
                "CertCommonName",
                CERT_COMMON_NAME_PATTERN,
                |bytes| {
                    if bytes.len() >= 2 {
                        bytes[0] = 0xB0;
                        bytes[1] = 0x01;
                    }
                },
                &mut report,
            )?;

            total += self.patch_pattern(
                "CertChain",
                CERT_CHAIN_PATTERN,
                |bytes| {
                    if bytes.len() >= 4 {
                        bytes[0] = 0xB3;
                        bytes[1] = 0x01;
                        bytes[2] = 0xEB;
                        bytes[3] = 0x02;
                    }
                },
                &mut report,
            )?;

            if total == 0 {
                return Err("certificate anchors vanished before patching".into());
            }
            report.push(format!("TLS cert PoC: applied {total} runtime code patch(es)"));
            Ok(())
        })();

        let resumed = unsafe { NtResumeProcess(self.handle) };
        if resumed < 0 {
            return Err(format!(
                "NtResumeProcess failed after TLS cert patch, NTSTATUS=0x{:08X}",
                resumed as u32
            ));
        }
        report.push("TLS cert PoC: WowB resumed".into());

        patch_result?;
        Ok(report)
    }

    pub fn rss(&self) -> u64 {
        let mut c = PROCESS_MEMORY_COUNTERS::default();
        unsafe {
            if GetProcessMemoryInfo(self.handle, &mut c, std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32).is_ok() {
                return c.WorkingSetSize as u64 / 4096;
            }
        }
        0
    }
}

impl Memory for ProcessMemory {
    fn regions(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut addr: usize = 0;
        loop {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            let n = unsafe {
                VirtualQueryEx(self.handle, Some(addr as *const c_void), &mut info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>())
            };
            if n == 0 {
                break;
            }
            let base = info.BaseAddress as usize;
            // 70450 does not keep the region-group key store under one stable
            // protection value for its whole lifetime. The old code required exact
            // PAGE_READWRITE, which can miss the store when Windows/Arxan gives the
            // allocation another readable MEM_PRIVATE protection or modifier.
            //
            // ReadProcessMemory is still the authority: include committed private
            // regions except explicit NOACCESS/GUARD and let failed reads be skipped.
            // The patcher only writes after validating the complete 12-entry key-store
            // structure, so broadening discovery does not broaden what can be patched.
            let blocked = (info.Protect.0 & (PAGE_NOACCESS.0 | PAGE_GUARD.0)) != 0;
            if info.State == MEM_COMMIT && info.Type == MEM_PRIVATE && !blocked {
                out.push((base as u64, (base + info.RegionSize) as u64));
            }
            let next = base.saturating_add(info.RegionSize);
            if next <= addr {
                break;
            }
            addr = next;
        }
        out
    }

    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut got = 0usize;
        unsafe {
            let _ = ReadProcessMemory(self.handle, addr as *const c_void, buf.as_mut_ptr() as *mut c_void, len, Some(&mut got));
        }
        if got == 0 {
            return None;
        }
        buf.truncate(got);
        Some(buf)
    }

    fn write(&self, addr: u64, data: &[u8]) -> bool {
        let mut written = 0usize;
        unsafe {
            WriteProcessMemory(self.handle, addr as *const c_void, data.as_ptr() as *const c_void, data.len(), Some(&mut written)).is_ok()
                && written == data.len()
        }
    }

    fn alive(&self) -> bool {
        let mut code = 0u32;
        unsafe { GetExitCodeProcess(self.handle, &mut code).is_ok() && code == STILL_ACTIVE.0 as u32 }
    }

    fn pid(&self) -> u32 {
        self.pid
    }
}

/// The running WowB.exe using the most memory.
pub fn find_client() -> Option<ProcessMemory> {
    let mut best: Option<(u64, ProcessMemory)> = None;
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut ok = Process32FirstW(snap, &mut entry).is_ok();
        while ok {
            let len = entry.szExeFile.iter().position(|c| *c == 0).unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            if name.eq_ignore_ascii_case("WowB.exe") {
                if let Some(p) = ProcessMemory::open(entry.th32ProcessID) {
                    let rss = p.rss();
                    if best.as_ref().map_or(true, |(r, _)| rss > *r) {
                        best = Some((rss, p));
                    }
                }
            }
            ok = Process32NextW(snap, &mut entry).is_ok();
        }
        let _ = CloseHandle(snap);
    }
    best.map(|(_, p)| p)
}
