//! Windows-only proof of concept for a Battle.net-independent 70450 launch.
//!
//! The process is created suspended by game.rs. Before it is resumed we patch
//! the two TrinityCore auth keys that Arctium/wow-patcher patch in the mapped
//! client image. No DLL is injected and no on-disk game file is modified.

#![cfg(windows)]

use crate::config::Settings;
use memchr::memmem;
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{
    VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

#[link(name = "ntdll")]
extern "system" {
    fn NtResumeProcess(process_handle: HANDLE) -> i32;
}

// Stock Battle.net ConnectTo/ChangeProtocol RSA modulus prefix.
// Arctium-compatible patchers use this eight-byte anchor to locate the full
// 256-byte modulus in the mapped image.
const CONNECT_TO_PREFIX: &[u8] = &[0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5];

// Stock client crypto Ed25519 key used by modern Classic-family clients.
const STOCK_CRYPTO_ED25519: &[u8; 32] = &[
    0x15, 0xD6, 0x18, 0xBD, 0x7D, 0xB5, 0x77, 0xBD, 0x9A, 0x8D, 0x45, 0x76, 0x9C, 0x59, 0xE4, 0xFC,
    0x63, 0x16, 0x33, 0xBF, 0x44, 0x73, 0x98, 0xA4, 0xB4, 0x89, 0xB4, 0xC2, 0x6F, 0xBC, 0x03, 0xAD,
];

// TrinityCore RSA modulus used by its modern Battle.net implementation.
// Public key material; mirrored by wowemulation-dev/wow-patcher's TrinityCore
// defaults. Keeping it here makes the PoC self-contained and offline.
const TRINITY_RSA_MODULUS: &[u8; 256] = &[
    0x5F, 0xD6, 0x80, 0x0B, 0xA7, 0xFF, 0x01, 0x40, 0xC7, 0xBC, 0x8E, 0xF5, 0x6B, 0x27, 0xB0, 0xBF,
    0xF0, 0x1D, 0x1B, 0xFE, 0xDD, 0x0B, 0x1F, 0x3D, 0xB6, 0x6F, 0x1A, 0x48, 0x0D, 0xFB, 0x51, 0x08,
    0x65, 0x58, 0x4F, 0xDB, 0x5C, 0x6E, 0xCF, 0x64, 0xCB, 0xC1, 0x6B, 0x2E, 0xB8, 0x0F, 0x5D, 0x08,
    0x5D, 0x89, 0x06, 0xA9, 0x77, 0x8B, 0x9E, 0xAA, 0x04, 0xB0, 0x83, 0x10, 0xE2, 0x15, 0x4D, 0x08,
    0x77, 0xD4, 0x7A, 0x0E, 0x5A, 0xB0, 0xBB, 0x00, 0x61, 0xD7, 0xA6, 0x75, 0xDF, 0x06, 0x64, 0x88,
    0xBB, 0xB9, 0xCA, 0xB0, 0x18, 0x8B, 0x54, 0x13, 0xE2, 0xCB, 0x33, 0xDF, 0x17, 0xD8, 0xDA, 0xA9,
    0xA5, 0x60, 0xA3, 0x1F, 0x4E, 0x27, 0x05, 0x98, 0x6F, 0xAA, 0xEE, 0x14, 0x3B, 0xF3, 0x97, 0xA8,
    0x12, 0x02, 0x94, 0x0D, 0x84, 0xDC, 0x0E, 0xF1, 0x76, 0x23, 0x95, 0x36, 0x13, 0xF9, 0xA9, 0xC5,
    0x48, 0xDB, 0xDA, 0x86, 0xBE, 0x29, 0x22, 0x54, 0x44, 0x9D, 0x9F, 0x80, 0x7B, 0x07, 0x80, 0x30,
    0xEA, 0xD2, 0x83, 0xCC, 0xCE, 0x37, 0xD1, 0xD1, 0xCF, 0x85, 0xBE, 0x91, 0x25, 0xCE, 0xC0, 0xCC,
    0x55, 0xC8, 0xC0, 0xFB, 0x38, 0xC5, 0x49, 0x03, 0x6A, 0x02, 0xA9, 0x9F, 0x9F, 0x86, 0xFB, 0xC7,
    0xCB, 0xC6, 0xA5, 0x82, 0xA2, 0x30, 0xC2, 0xAC, 0xE6, 0x98, 0xDA, 0x83, 0x64, 0x43, 0x7F, 0x0D,
    0x13, 0x18, 0xEB, 0x90, 0x53, 0x5B, 0x37, 0x6B, 0xE6, 0x0D, 0x80, 0x1E, 0xEF, 0xED, 0xC7, 0xB8,
    0x68, 0x9B, 0x4C, 0x09, 0x7B, 0x60, 0xB2, 0x57, 0xD8, 0x59, 0x8D, 0x7F, 0xEA, 0xCD, 0xEB, 0xC4,
    0x60, 0x9F, 0x45, 0x7A, 0xA9, 0x26, 0x8A, 0x2F, 0x85, 0x0C, 0xF2, 0x19, 0xC6, 0x53, 0x92, 0xF7,
    0xF0, 0xB8, 0x32, 0xCB, 0x5B, 0x66, 0xCE, 0x51, 0x54, 0xB4, 0xC3, 0xD3, 0xD4, 0xDC, 0xB3, 0xEE,
];

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn open_process(pid: u32) -> Result<ProcessHandle, String> {
    let access = PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_SUSPEND_RESUME;
    unsafe { OpenProcess(access, false, pid) }
        .map(ProcessHandle)
        .map_err(|e| format!("OpenProcess standalone PoC failed: {e}"))
}

fn read(handle: HANDLE, address: usize, len: usize) -> Option<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    let mut got = 0usize;
    unsafe {
        let _ = ReadProcessMemory(
            handle,
            address as *const c_void,
            bytes.as_mut_ptr() as *mut c_void,
            len,
            Some(&mut got),
        );
    }
    if got == 0 {
        return None;
    }
    bytes.truncate(got);
    Some(bytes)
}

fn image_hits(handle: HANDLE, needle: &[u8]) -> Vec<usize> {
    let finder = memmem::Finder::new(needle);
    let mut hits = Vec::new();
    let mut address = 0usize;
    const CHUNK: usize = 2 * 1024 * 1024;

    loop {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let n = unsafe {
            VirtualQueryEx(
                handle,
                Some(address as *const c_void),
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if n == 0 {
            break;
        }
        let base = info.BaseAddress as usize;
        let size = info.RegionSize;
        if info.State == MEM_COMMIT && info.Type == MEM_IMAGE && size >= needle.len() {
            let mut offset = 0usize;
            while offset < size {
                let wanted = CHUNK.min(size - offset);
                let Some(bytes) = read(handle, base + offset, wanted) else { break };
                for hit in finder.find_iter(&bytes) {
                    hits.push(base + offset + hit);
                }
                if bytes.len() < wanted || bytes.len() <= needle.len() {
                    break;
                }
                offset = offset.saturating_add(bytes.len() - (needle.len() - 1));
            }
        }
        let next = base.saturating_add(size);
        if next <= address {
            break;
        }
        address = next;
    }
    hits.sort_unstable();
    hits.dedup();
    hits
}

fn write_verified(handle: HANDLE, address: usize, data: &[u8]) -> Result<(), String> {
    let mut old = Default::default();
    unsafe {
        VirtualProtectEx(handle, address as *const c_void, data.len(), PAGE_READWRITE, &mut old)
            .map_err(|e| format!("VirtualProtectEx standalone PoC failed: {e}"))?;
    }
    let mut written = 0usize;
    let write_result = unsafe {
        WriteProcessMemory(
            handle,
            address as *const c_void,
            data.as_ptr() as *const c_void,
            data.len(),
            Some(&mut written),
        )
    };
    let mut ignored = Default::default();
    let restore_result = unsafe { VirtualProtectEx(handle, address as *const c_void, data.len(), old, &mut ignored) };
    write_result.map_err(|e| format!("WriteProcessMemory standalone PoC failed: {e}"))?;
    restore_result.map_err(|e| format!("Restoring page protection failed: {e}"))?;
    if written != data.len() {
        return Err(format!("Standalone PoC short write: {written}/{}", data.len()));
    }
    match read(handle, address, data.len()) {
        Some(after) if after == data => Ok(()),
        _ => Err("Standalone PoC write verification failed".into()),
    }
}

fn patch_unique(handle: HANDLE, label: &str, needle: &[u8], replacement: &[u8]) -> Result<(), String> {
    let hits = image_hits(handle, needle);
    crate::windows_diagnostics::record(&format!("Standalone PoC {label}: stock pattern hits={}", hits.len()));
    match hits.as_slice() {
        [address] => {
            // Refuse to write across an unreadable window.
            if read(handle, *address, replacement.len()).is_none() {
                return Err(format!("{label}: replacement window is unreadable"));
            }
            write_verified(handle, *address, replacement)?;
            crate::windows_diagnostics::record(&format!("Standalone PoC {label}: patched at 0x{address:X}"));
            Ok(())
        }
        [] => {
            let current = image_hits(handle, replacement);
            if current.len() == 1 {
                crate::windows_diagnostics::record(&format!("Standalone PoC {label}: replacement already present"));
                Ok(())
            } else {
                Err(format!("{label}: expected exactly one stock pattern, found none (replacement hits={})", current.len()))
            }
        }
        _ => Err(format!("{label}: expected exactly one stock pattern, found {}", hits.len())),
    }
}

fn parse_server_key(settings: &Settings) -> Result<[u8; 32], String> {
    let bytes = hex::decode(settings.server.public_key.trim()).map_err(|_| "Server public key is not valid hex".to_string())?;
    bytes.try_into().map_err(|_| "Server public key must contain exactly 32 bytes".to_string())
}

/// Applies the minimal private-auth data patches before the suspended 70450
/// process is allowed to execute, then resumes the whole process.
///
/// This is intentionally a proof of concept: it does not patch code, disable
/// integrity checks, inject a DLL, or modify WowB.exe on disk.
pub fn patch_and_resume(pid: u32, settings: &Settings) -> Result<(), String> {
    let process = open_process(pid)?;
    crate::windows_diagnostics::record("Standalone PoC: suspended WowB opened; applying pre-auth data patches");

    patch_unique(process.0, "ConnectTo RSA", CONNECT_TO_PREFIX, TRINITY_RSA_MODULUS)?;
    let server_key = parse_server_key(settings)?;
    patch_unique(process.0, "Crypto Ed25519", STOCK_CRYPTO_ED25519, &server_key)?;

    let status = unsafe { NtResumeProcess(process.0) };
    if status < 0 {
        return Err(format!("NtResumeProcess failed, NTSTATUS=0x{:08X}", status as u32));
    }
    crate::windows_diagnostics::record("Standalone PoC: pre-auth patches verified; WowB resumed without -launcherlogin");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trinity_key_material_has_expected_sizes() {
        assert_eq!(TRINITY_RSA_MODULUS.len(), 256);
        assert_eq!(STOCK_CRYPTO_ED25519.len(), 32);
        assert_eq!(CONNECT_TO_PREFIX.len(), 8);
    }

    #[test]
    fn default_server_key_matches_trinity_ed25519_default() {
        let settings = Settings::default();
        assert_eq!(
            parse_server_key(&settings).unwrap(),
            [
                0x02, 0x59, 0x6F, 0x0D, 0x0C, 0x06, 0x1A, 0x8B, 0x30, 0x74, 0x59, 0x88, 0xFD, 0x72, 0xC5, 0x9E,
                0x29, 0xEC, 0x36, 0x7F, 0xB0, 0xF3, 0x41, 0xF2, 0x8E, 0x0F, 0x08, 0xD0, 0x37, 0xBA, 0xFC, 0x69,
            ]
        );
    }
}
