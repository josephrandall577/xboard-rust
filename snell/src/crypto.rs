use std::io;

use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce as RingNonce, UnboundKey};

use crate::error;
use crate::{AEAD_TAG_LEN, NONCE_LEN};

/// Derives the 16-byte AES-128-GCM key for a salt.
///
/// Surge 6.7.0 (11520): FUN_1000123d0: AEAD keys are derived with these Argon2id parameters.
pub fn derive_key(psk: &[u8], salt: &[u8]) -> [u8; 16] {
    let params = Params::new(8, 3, 1, Some(32)).expect("snell: invalid argon2 parameters");
    let mut output = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(psk, salt, &mut output)
        .expect("snell: argon2 key derivation failed");
    let mut key = [0u8; 16];
    key.copy_from_slice(&output[..16]);
    key
}

/// AES-128-GCM with the Go `cipher.AEAD` sealing conventions.
pub struct Aead(LessSafeKey);

pub type Nonce = [u8; NONCE_LEN];

fn authentication_failed() -> io::Error {
    error::new_error("cipher: message authentication failed")
}

impl Aead {
    pub fn new(key: &[u8]) -> io::Result<Self> {
        UnboundKey::new(&AES_128_GCM, key)
            .map(|key| Aead(LessSafeKey::new(key)))
            .map_err(|_| error::new_invalid(format!("crypto/aes: invalid key size {}", key.len())))
    }

    /// `Seal(buf[:0], nonce, buf[:len(buf)-16], aad)` in place: `buf` holds the
    /// plaintext followed by 16 bytes that receive the tag.
    pub fn seal_in_place(&self, nonce: &Nonce, aad: &[u8], buf: &mut [u8]) {
        let plain_len = buf.len() - AEAD_TAG_LEN;
        let (plain, tag_out) = buf.split_at_mut(plain_len);
        let tag = self
            .0
            .seal_in_place_separate_tag(RingNonce::assume_unique_for_key(*nonce), Aad::from(aad), plain)
            .expect("snell: aes-gcm encryption failed");
        tag_out.copy_from_slice(tag.as_ref());
    }

    /// `Open(buf[:0], nonce, buf, aad)` in place: returns the plaintext length.
    pub fn open_in_place(&self, nonce: &Nonce, aad: &[u8], buf: &mut [u8]) -> io::Result<usize> {
        if buf.len() < AEAD_TAG_LEN {
            return Err(authentication_failed());
        }
        self.0
            .open_in_place(RingNonce::assume_unique_for_key(*nonce), Aad::from(aad), buf)
            .map(|plain| plain.len())
            .map_err(|_| authentication_failed())
    }
}

/// A fresh random salt.
pub(crate) fn random_salt() -> [u8; crate::SALT_LEN] {
    let mut salt = [0u8; crate::SALT_LEN];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut salt);
    salt
}

/// `snell.NewAEAD`.
pub fn new_aead(key: &[u8]) -> io::Result<Aead> {
    Aead::new(key)
}

/// Increments a little-endian nonce counter.
///
/// Surge 6.7.0 (11520): FUN_100012944: nonce is u64le(counter) || 0x00000000.
pub fn increase_nonce(nonce: &mut [u8]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}
