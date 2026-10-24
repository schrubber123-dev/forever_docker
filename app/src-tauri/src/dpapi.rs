//! Encryption of the login ticket stored in Launch Options\WoW\WEB_TOKEN.
//!
//! Windows: the real CryptProtectData. Linux: the game runs under Wine, whose CryptProtectData is deterministic
//! (dlls/crypt32/protectdata.c), so the blob is built here directly.

/// Entropy Battle.net uses for WEB_TOKEN (Shauren/tc-client-launcher, LauncherShared.h).
pub const WEB_TOKEN_ENTROPY: [u8; 16] = [0xC8, 0x76, 0xF4, 0xAE, 0x4C, 0x95, 0x2E, 0xFE, 0xF2, 0xFA, 0x0F, 0x54, 0x19, 0xC0, 0x9C, 0x43];

#[cfg(windows)]
pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: plain.len() as u32, pbData: plain.as_ptr() as *mut u8 };
        let entropy = CRYPT_INTEGER_BLOB { cbData: 16, pbData: WEB_TOKEN_ENTROPY.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(&input, windows::core::w!("ForeverLauncher"), Some(&entropy), None, None,
                         CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            .map_err(|e| format!("CryptProtectData : {e}"))?;
        let blob = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(out.pbData as _));
        Ok(blob)
    }
}

/// Verify a stored ticket in the current Windows user context without exposing it.
#[cfg(windows)]
pub fn verify(blob: &[u8], expected: &[u8]) -> Result<(), String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: blob.len() as u32, pbData: blob.as_ptr() as *mut u8 };
        let entropy = CRYPT_INTEGER_BLOB { cbData: WEB_TOKEN_ENTROPY.len() as u32, pbData: WEB_TOKEN_ENTROPY.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(&input, None, Some(&entropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
            .map_err(|e| format!("WEB_TOKEN DPAPI verification failed: {e}"))?;
        let matches = std::slice::from_raw_parts(out.pbData, out.cbData as usize) == expected;
        let _ = LocalFree(HLOCAL(out.pbData as _));
        if matches { Ok(()) } else { Err("WEB_TOKEN DPAPI plaintext mismatch".into()) }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    #[test]
    fn ticket_round_trip_in_current_user_context() {
        let ticket = b"TC-test-ticket";
        let blob = super::protect(ticket).unwrap();
        super::verify(&blob, ticket).unwrap();
        assert!(super::verify(&blob, b"different-ticket").is_err());
        assert!(super::verify(b"invalid DPAPI blob", ticket).is_err());
    }
}

#[cfg(not(windows))]
pub mod wine {
    #[cfg(test)]
    use cbc::cipher::BlockDecryptMut;
    use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use sha1::{Digest, Sha1};

    type Enc = cbc::Encryptor<des::TdesEde3>;
    #[cfg(test)]
    type Dec = cbc::Decryptor<des::TdesEde3>;

    const SECRET: &[u8] = b"I'm hunting wabbits";
    const MAGIC: &[u8] = b"Wine Crypt32 ok\0";
    const CALG_3DES: u32 = 0x6603;
    const CALG_SHA1: u32 = 0x8004;
    /// GetUserNameA() inside a Proton prefix.
    pub const PROTON_USER: &str = "steamuser";

    fn sha1(parts: &[&[u8]]) -> [u8; 20] {
        let mut h = Sha1::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    /// SHA1(user name incl. NUL + secret + salt + entropy), expanded to 24 bytes like CryptDeriveKey.
    fn derive_key(user: &str, salt: &[u8], entropy: &[u8]) -> [u8; 24] {
        let h = sha1(&[user.as_bytes(), b"\0", SECRET, salt, entropy]);
        let (mut b1, mut b2) = ([0x36u8; 64], [0x5cu8; 64]);
        for (i, x) in h.iter().enumerate() {
            b1[i] ^= x;
            b2[i] ^= x;
        }
        let mut key = [0u8; 24];
        key[..20].copy_from_slice(&sha1(&[&b1]));
        key[20..].copy_from_slice(&sha1(&[&b2])[..4]);
        key
    }

    fn u32le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    pub fn protect(plain: &[u8], user: &str, entropy: &[u8]) -> Vec<u8> {
        let salt: [u8; 16] = rand::random();
        let key = derive_key(user, &salt, entropy);
        let cipher = Enc::new(&key.into(), &[0u8; 8].into()).encrypt_padded_vec_mut::<Pkcs7>(plain);
        let descr = [0u8, 0u8]; // empty UTF-16 description
        let fp = sha1(&[plain]);
        let mut out = Vec::with_capacity(160 + cipher.len());
        out.extend(u32le(1));
        out.extend(MAGIC);
        out.extend(u32le(1));
        out.extend(MAGIC);
        out.extend(u32le(0));
        out.extend(u32le(descr.len() as u32));
        out.extend(descr);
        out.extend(u32le(CALG_3DES));
        out.extend(u32le(168));
        out.extend(u32le(MAGIC.len() as u32));
        out.extend(MAGIC);
        out.extend(u32le(0));
        out.extend(u32le(CALG_SHA1));
        out.extend(u32le(160));
        out.extend(u32le(salt.len() as u32));
        out.extend(salt);
        out.extend(u32le(cipher.len() as u32));
        out.extend(&cipher);
        out.extend(u32le(fp.len() as u32));
        out.extend(fp);
        out
    }

    #[cfg(test)]
    pub fn unprotect(blob: &[u8], user: &str, entropy: &[u8]) -> Option<Vec<u8>> {
        struct Cursor<'a>(&'a [u8], usize);
        impl Cursor<'_> {
            fn dword(&mut self) -> Option<u32> {
                let v = u32::from_le_bytes(self.0.get(self.1..self.1 + 4)?.try_into().ok()?);
                self.1 += 4;
                Some(v)
            }
            fn bytes(&mut self, n: usize) -> Option<&[u8]> {
                let v = self.0.get(self.1..self.1 + n)?;
                self.1 += n;
                Some(v)
            }
            fn blob(&mut self) -> Option<&[u8]> {
                let n = self.dword()? as usize;
                self.bytes(n)
            }
        }
        let mut c = Cursor(blob, 0);
        c.dword()?; // count0
        c.bytes(16)?; // info0
        c.dword()?; // count1
        c.bytes(16)?; // info1
        c.dword()?; // null0
        c.blob()?; // description
        c.dword()?; // cipher alg
        c.dword()?; // cipher key length
        c.blob()?; // data0
        c.dword()?; // null1
        c.dword()?; // hash alg
        c.dword()?; // hash length
        let salt = c.blob()?.to_vec();
        let cipher = c.blob()?.to_vec();
        let fp = c.blob()?.to_vec();
        let key = derive_key(user, &salt, entropy);
        let plain = Dec::new(&key.into(), &[0u8; 8].into()).decrypt_padded_vec_mut::<Pkcs7>(&cipher).ok()?;
        (sha1(&[&plain]).as_slice() == fp.as_slice()).then_some(plain)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trip() {
            let e = super::super::WEB_TOKEN_ENTROPY;
            let ticket = b"TC-0123456789ABCDEF0123456789ABCDEF01234567";
            let blob = protect(ticket, PROTON_USER, &e);
            assert_eq!(&blob[..20], b"\x01\0\0\0Wine Crypt32 ok\0");
            assert_eq!(unprotect(&blob, PROTON_USER, &e).as_deref(), Some(&ticket[..]));
            assert!(unprotect(&blob, PROTON_USER, &[]).is_none());
        }

        /// Blob made by launcher/proto/winedpapi.py, the version validated in game (auto-login worked).
        #[test]
        fn reads_python_prototype_blob() {
            let blob = hex::decode("0100000057696e652043727970743332206f6b000100000057696e652043727970743332206f6b000000000002000000000003660000a80000001000000057696e652043727970743332206f6b000000000004800000a000000010000000e72ef6f0d85e80b88770acb7f1077f1930000000fc21ef7a10acec2ead81cb6a12a4d5b53b2d4dca39c68a32aa62435a075bcb47d843621d121441e884891c8d561c76c3140000004e3368afd9088e061cfd66a026f41af7bbfc480f").unwrap();
            let e = super::super::WEB_TOKEN_ENTROPY;
            assert_eq!(unprotect(&blob, PROTON_USER, &e).as_deref(), Some(&b"TC-0123456789ABCDEF0123456789ABCDEF01234567"[..]));
        }
    }
}
