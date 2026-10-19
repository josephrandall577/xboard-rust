//! v6 default-mode traffic shaping profile, salt block and padding mixing.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

use crate::{AEAD_TAG_LEN, HEADER_CIPHER_LEN};

// Surge 6.7.0 (11520): FUN_1000130ac: derives v6 profile values with this SplitMix64 gamma.
const GOLDEN_GAMMA: u64 = 0x9e3779b97f4a7c15;

pub(crate) const SALT_LEN: usize = 16;

// Surge 6.7.0 (11520): FUN_1000130ac: uses these PRF labels for v6 profile derivation.
const LABEL_PADDING: u32 = 0;
const LABEL_BIT_PERCENT: u32 = 1;
const LABEL_MOTIF: u32 = 2;
const LABEL_MIX_OFFSET: u32 = 3;
const LABEL_SALT: u32 = 3;
const LABEL_PROFILE_ID: u32 = 5;
const LABEL_GENERATOR: u32 = 6;
const LABEL_PAD_MIN: u32 = 7;
const LABEL_PAD_MAX: u32 = 8;
const LABEL_PAD_COUNT: u32 = 9;
const LABEL_PAD_INTERVAL: u32 = 10;
const LABEL_SMALL_LIMIT: u32 = 11;
const LABEL_BIT_MIN: u32 = 12;
const LABEL_BIT_MAX: u32 = 13;
const LABEL_PREFIX_MIN: u32 = 14;
const LABEL_PREFIX_MAX: u32 = 15;
const LABEL_MIX_MODE: u32 = 16;
const LABEL_MIX_ROUNDS: u32 = 17;
const LABEL_MIX_STRIDE: u32 = 18;
const LABEL_MIX_OFFSET_BASE: u32 = 19;
const LABEL_MIX_BLOCK: u32 = 20;
const LABEL_CHUNK_POLICY: u32 = 21;
const LABEL_CHUNK_INITIAL: u32 = 22;
const LABEL_CHUNK_FIRST_CAP: u32 = 22;
const LABEL_CHUNK_MAX: u32 = 23;
const LABEL_CHUNK_STEP: u32 = 24;
const LABEL_CHUNK_JITTER: u32 = 25;
const LABEL_CHUNK_BUCKET: u32 = 26;
const LABEL_IDLE_RESET: u32 = 27;
const LABEL_WRITE_POLICY: u32 = 28;
const LABEL_WRITE_FIRST: u32 = 29;
const LABEL_WRITE_BUCKET: u32 = 30;
const LABEL_WRITE_SEQ: u32 = 31;
const LABEL_WRITE_JITTER: u32 = 32;
const LABEL_RECORD_PREFIX: u32 = 33;
const LABEL_PAYLOAD_PAD: u32 = 34;
const LABEL_WRITE_TARGET: u32 = 35;
const LABEL_WRITE_JITTER_V: u32 = 36;
const LABEL_WRITE_NEXT: u32 = 37;
const LABEL_CHUNK_SIZE: u32 = 38;
const LABEL_CHUNK_JITTER_V: u32 = 39;

// Surge 6.7.0 (11520): FUN_1000130ac: uses these domain separators for handshake and chunk profile values.
const HANDSHAKE_DOMAIN: u32 = 0x7053;
const MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
const CHUNK_INITIAL_DOMAIN: u32 = 0xf17c;

// Surge 6.7.0 (11520): FUN_1000130ac: uses these namespace seeds for v6 profile derivation.
const NS_SEED_PROFILE: u64 = 0xb46c2e7d9a1538f1;
const NS_SEED_PREFIX: u64 = 0x5d9217c083e64ab9;
const NS_SEED_MOTIF: u64 = 0xa71f0c54d8396e2b;
const NS_SEED_SALT: u64 = 0x3e8a91b52740f6cd;
const NS_SEED_MIX: u64 = 0xc9f4260b7d1e835a;
const NS_SEED_CHUNK: u64 = 0x62d0b5e19c4a783f;
const NS_SEED_WRITE: u64 = 0x917b3c48e6a205d4;

// Surge 6.7.0 (11520): FUN_100014910/FUN_1000149c4: uses these arithmetic constants for v6 profile PRFs.
const DOMAIN_MUL: u64 = 0xd6e8feb86659fd93;
const NAMESPACE_ADD: u64 = 0xa0761d6478bd642f;
const COEF_B: u64 = 0x589965cc75374cc3;
const ADD_B: u64 = 0x33a213ec50ffe2e9;
const COEF_A: u64 = 0xe7037ed1a0b428db;
const ADD_A: u64 = 0x8f3907f7b2b80c35;
const MAX_EXTRA_PADDING: i64 = 0x02da;

// Surge 6.7.0 (11520): FUN_100015274/FUN_1000140bc: shuffles and masks v6 default-mode salts with this namespace xor.
const SALT_NS_XOR: u64 = 0xdaa66d2c7ddf743f;

// Surge 6.7.0 (11520): FUN_1000130ac: profileSeed is the BLAKE2b prefix mixed with the PSK to derive the profile secret.
const PROFILE_SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e, 0x4a, 0x91, 0x25,
    0xfd, 0xb8, 0x03, 0x77, 0xac,
];

// Surge 6.7.0 (11520): FUN_100014f98: generator 0 maps low nibbles through this bit-rotation table.
const BIT_ROTATE_TABLE: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, //
    0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24, //
    0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0, //
    0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78, 0xf0, //
    0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f, //
    0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb, //
    0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f,
];

fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

fn prf32_fold(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let x = namespace
        ^ b.wrapping_mul(COEF_B).wrapping_add(ADD_B)
        ^ (label as u64).wrapping_mul(GOLDEN_GAMMA)
        ^ a.wrapping_mul(COEF_A).wrapping_add(ADD_A);
    let y = splitmix64(x);
    (y ^ (y >> 32)) as u32
}

fn pick(raw: u32, lo: i64, hi: i64) -> i64 {
    assert!(hi >= lo, "snell: invalid profile range");
    lo + (raw as u64 % (hi - lo + 1) as u64) as i64
}

fn pick_u32(raw: u32, lo: u32, hi: u32) -> u32 {
    assert!(hi >= lo, "snell: invalid profile range");
    lo + raw % (hi - lo + 1)
}

#[derive(Clone, Copy, Debug)]
struct Namespaces {
    profile: u64,
    prefix: u64,
    motif: u64,
    salt: u64,
    mix: u64,
    chunk: u64,
    write: u64,
}

fn derive_namespace(secret: &[u8; 32], label: u32, seed_const: u64) -> u64 {
    let word = |index: usize| u64::from_le_bytes(secret[index * 8..index * 8 + 8].try_into().unwrap());
    let (s0, s1, s2, s3) = (word(0), word(1), word(2), word(3));
    let mixed = (label as u64).wrapping_mul(DOMAIN_MUL)
        ^ seed_const.wrapping_add(NAMESPACE_ADD)
        ^ s0
        ^ s1.wrapping_add(GOLDEN_GAMMA)
        ^ s2.rotate_left(17)
        ^ s3.rotate_right(11);
    splitmix64(mixed)
}

impl Namespaces {
    fn new(secret: &[u8; 32]) -> Self {
        Namespaces {
            profile: derive_namespace(secret, LABEL_PROFILE_ID, NS_SEED_PROFILE),
            prefix: derive_namespace(secret, LABEL_PADDING, NS_SEED_PREFIX),
            motif: derive_namespace(secret, LABEL_MOTIF, NS_SEED_MOTIF),
            salt: derive_namespace(secret, LABEL_SALT, NS_SEED_SALT),
            mix: derive_namespace(secret, LABEL_MIX_MODE, NS_SEED_MIX),
            chunk: derive_namespace(secret, LABEL_CHUNK_POLICY, NS_SEED_CHUNK),
            write: derive_namespace(secret, LABEL_WRITE_POLICY, NS_SEED_WRITE),
        }
    }

    fn for_label(&self, label: u32) -> u64 {
        match label {
            LABEL_PADDING | LABEL_BIT_PERCENT | LABEL_PREFIX_MIN | LABEL_PREFIX_MAX | LABEL_RECORD_PREFIX
            | LABEL_PAYLOAD_PAD => self.prefix,
            LABEL_MOTIF => self.motif,
            LABEL_MIX_OFFSET
            | LABEL_MIX_MODE
            | LABEL_MIX_ROUNDS
            | LABEL_MIX_STRIDE
            | LABEL_MIX_OFFSET_BASE
            | LABEL_MIX_BLOCK => self.mix,
            LABEL_CHUNK_POLICY | LABEL_CHUNK_INITIAL | LABEL_CHUNK_MAX | LABEL_CHUNK_STEP | LABEL_CHUNK_JITTER
            | LABEL_CHUNK_BUCKET | LABEL_CHUNK_SIZE | LABEL_CHUNK_JITTER_V => self.chunk,
            LABEL_WRITE_POLICY | LABEL_WRITE_FIRST | LABEL_WRITE_BUCKET | LABEL_WRITE_SEQ | LABEL_WRITE_JITTER
            | LABEL_WRITE_TARGET | LABEL_WRITE_JITTER_V | LABEL_WRITE_NEXT => self.write,
            _ => self.profile,
        }
    }

    fn prf32(&self, label: u32, a: u32, b: u32) -> u32 {
        prf32_fold(self.for_label(label), label, a as u64, b as u64)
    }

    fn prf_bytes(&self, label: u32, a: u32, output: &mut [u8]) {
        let mut seed = self.for_label(label)
            ^ (a as u64).wrapping_mul(DOMAIN_MUL).wrapping_add(0xb57de1f3f82cb33f)
            ^ (label as u64).wrapping_mul(0xa24baed4963ee407)
            ^ (output.len() as u64).wrapping_mul(0x165667b19e3779f9).wrapping_add(0x0d4cd3e7b14a36d7);
        let mut offset = 0;
        while offset < output.len() {
            seed = seed.wrapping_add(GOLDEN_GAMMA);
            let block = splitmix64(seed);
            let mut shift = 0;
            while shift < 64 && offset < output.len() {
                output[offset] = (block >> shift) as u8;
                offset += 1;
                shift += 8;
            }
        }
    }

    fn prf_static(&self, label: u32, domain: u32) -> u32 {
        prf32_fold(self.for_label(label), label, 0, domain as u64)
    }
}

/// The traffic shaping profile derived from a PSK.
#[derive(Clone, Debug)]
pub struct Profile {
    namespaces: Namespaces,

    generator: u32,
    pad_min: i64,
    pad_max: i64,
    pad_count: u32,
    pad_interval: u32,
    small_limit: i64,
    bit_min: u32,
    bit_max: u32,
    prefix_min_record: i64,
    prefix_max_record: i64,
    mix_mode: u32,
    mix_rounds: u32,
    mix_stride: i64,
    mix_offset_base: i64,
    mix_block: i64,
    chunk_policy: u32,
    pub(crate) chunk_initial: i64,
    pub(crate) first_record_cap: i64,
    pub(crate) chunk_max: i64,
    chunk_step: i64,
    chunk_jitter: i64,
    pub(crate) idle_reset_sec: i64,
    write_policy: u32,
    write_first: u32,
    chunk_buckets: [i64; 8],
    write_buckets: [i64; 8],
    write_seq: [i64; 8],
    write_jitter: i64,
    write_jitter_pct: i64,
    g1: i64,
    g2: i64,
    g3: i64,
    g4: i64,
    g5: i64,
    g6: i64,

    pub(crate) salt_block_len: usize,
    mix_stride_handshake: i64,
    mix_rounds_handshake: u32,

    pub(crate) record_prefix_max: usize,
    pub(crate) pad_max_headroom: usize,
}

fn profile_secret(psk: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(PROFILE_SEED);
    hasher.update(psk);
    hasher.finalize().into()
}

impl Profile {
    /// `snellv6.NewProfile`.
    pub fn new(psk: &[u8]) -> Profile {
        let secret = profile_secret(psk);
        let ns = Namespaces::new(&secret);

        let pad_min = pick(ns.prf_static(LABEL_PAD_MIN, 0), 0x18, 0xa0);
        let pad_max = (pad_min + pick(ns.prf_static(LABEL_PAD_MAX, 0), 0xa0, 0x3c0)).min(MAX_EXTRA_PADDING);

        let mut prefix_min_hs = pick(ns.prf_static(LABEL_PREFIX_MIN, HANDSHAKE_DOMAIN), 0x10, 0x60);
        let prefix_max_hs =
            (prefix_min_hs + pick(ns.prf_static(LABEL_PREFIX_MAX, HANDSHAKE_DOMAIN), 0x10, 0xa0)).min(0x80);
        prefix_min_hs = prefix_min_hs.min(prefix_max_hs);
        let salt_prefix_len = pick(ns.prf_static(LABEL_RECORD_PREFIX, HANDSHAKE_DOMAIN), prefix_min_hs, prefix_max_hs);
        let salt_block_len = SALT_LEN as i64 + salt_prefix_len;

        let mix_rounds_hs = pick_u32(ns.prf_static(LABEL_MIX_ROUNDS, MIX_HANDSHAKE_DOMAIN), 1, 4);
        let mix_stride_hs = pick(ns.prf_static(LABEL_MIX_STRIDE, MIX_HANDSHAKE_DOMAIN), 0x11, 0xfb);

        let mut prefix_min_record = pick(ns.prf_static(LABEL_PREFIX_MIN, 0), 0x08, 0x50);
        let prefix_max_record = (prefix_min_record + pick(ns.prf_static(LABEL_PREFIX_MAX, 0), 0x10, 0xa0)).min(0x80);
        prefix_min_record = prefix_min_record.min(prefix_max_record);

        let chunk_initial = pick(ns.prf_static(LABEL_CHUNK_INITIAL, 0), 0x200, 0x05b4).clamp(0x60, 0x05b4);
        let first_record_cap = pick(ns.prf_static(LABEL_CHUNK_FIRST_CAP, CHUNK_INITIAL_DOMAIN), 0x100, 0x300)
            .min(chunk_initial.min(0x300))
            .max(0x100);
        let chunk_max = pick(ns.prf_static(LABEL_CHUNK_MAX, 0), 0x2000, 0x3fff).max(chunk_initial);

        let mut profile = Profile {
            namespaces: ns,
            generator: ns.prf_static(LABEL_GENERATOR, 0) & 3,
            pad_min,
            pad_max,
            pad_count: pick_u32(ns.prf_static(LABEL_PAD_COUNT, 0), 2, 8),
            pad_interval: pick_u32(ns.prf_static(LABEL_PAD_INTERVAL, 0), 2, 0x0b),
            small_limit: pick(ns.prf_static(LABEL_SMALL_LIMIT, 0), 0x60, 0x300),
            bit_min: pick_u32(ns.prf_static(LABEL_BIT_MIN, 0), 0x18, 0x29),
            bit_max: pick_u32(ns.prf_static(LABEL_BIT_MAX, 0), 0x3a, 0x4c),
            prefix_min_record,
            prefix_max_record,
            mix_mode: ns.prf_static(LABEL_MIX_MODE, 0) % 3,
            mix_rounds: pick_u32(ns.prf_static(LABEL_MIX_ROUNDS, 0), 1, 3),
            mix_stride: pick(ns.prf_static(LABEL_MIX_STRIDE, 0), 2, 13),
            mix_offset_base: pick(ns.prf_static(LABEL_MIX_OFFSET_BASE, 0), 0, 15),
            mix_block: pick(ns.prf_static(LABEL_MIX_BLOCK, 0), 8, 0x40),
            chunk_policy: ns.prf_static(LABEL_CHUNK_POLICY, 0) % 3,
            chunk_initial,
            first_record_cap,
            chunk_max,
            chunk_step: pick(ns.prf_static(LABEL_CHUNK_STEP, 0), 0x400, 0x1000).min(0x0b68),
            chunk_jitter: pick(ns.prf_static(LABEL_CHUNK_JITTER, 0), 0x10, 0xc0).min(0x0b6),
            idle_reset_sec: pick(ns.prf_static(LABEL_IDLE_RESET, 0), 0x0c, 0x5a),
            write_policy: ns.prf_static(LABEL_WRITE_POLICY, 0) % 3,
            write_first: pick_u32(ns.prf_static(LABEL_WRITE_FIRST, 0), 4, 8),
            chunk_buckets: [0; 8],
            write_buckets: [0; 8],
            write_seq: [0; 8],
            write_jitter: pick(ns.prf_static(LABEL_WRITE_JITTER, 0), 0x08, 0x60),
            write_jitter_pct: pick(ns.prf_static(LABEL_WRITE_POLICY, 0x504c), 8, 0x30),
            g1: pick(ns.prf_static(LABEL_GENERATOR, 1), 0x18, 0x80),
            g2: pick(ns.prf_static(LABEL_GENERATOR, 2), 0x10, 0x60),
            g3: pick(ns.prf_static(LABEL_GENERATOR, 3), 0x10, 0x60),
            g4: pick(ns.prf_static(LABEL_GENERATOR, 4), 0x00, 0x09),
            g5: pick(ns.prf_static(LABEL_GENERATOR, 5), 0x01, 0x08),
            g6: pick(ns.prf_static(LABEL_GENERATOR, 6), 0x07, 0x17),
            salt_block_len: salt_block_len as usize,
            mix_stride_handshake: mix_stride_hs,
            mix_rounds_handshake: mix_rounds_hs,
            record_prefix_max: prefix_max_record as usize,
            pad_max_headroom: (pad_max + MAX_EXTRA_PADDING) as usize,
        };

        for index in 0..8 {
            profile.chunk_buckets[index] = pick(ns.prf_static(LABEL_CHUNK_BUCKET, index as u32), 0x1000, chunk_max);
            profile.write_buckets[index] = pick(ns.prf_static(LABEL_WRITE_BUCKET, index as u32), 0x140, 0x05b4);
            profile.write_seq[index] = pick(ns.prf_static(LABEL_WRITE_SEQ, index as u32), 0x168, 0x05b4);
        }

        profile
    }

    pub(crate) fn record_prefix_len(&self, seq: u32) -> usize {
        pick(self.namespaces.prf32(LABEL_RECORD_PREFIX, seq, 0), self.prefix_min_record, self.prefix_max_record)
            as usize
    }

    pub(crate) fn chunk_payload_limit(&self, seq: u32, mut chunk_size: i64) -> i64 {
        if chunk_size == 0 {
            chunk_size = self.chunk_initial;
        }
        match self.chunk_policy {
            1 => {
                let raw = self.namespaces.prf32(LABEL_CHUNK_SIZE, seq, chunk_size as u32);
                chunk_size = self.chunk_buckets[(raw % self.chunk_buckets.len() as u32) as usize];
            }
            2 => {
                let raw_jitter = self.namespaces.prf32(LABEL_CHUNK_JITTER_V, seq, chunk_size as u32);
                chunk_size += (raw_jitter % (self.chunk_jitter * 2 + 1) as u32) as i64 - self.chunk_jitter;
            }
            _ => {}
        }
        chunk_size.min(self.chunk_max).max(0x40)
    }

    pub(crate) fn next_chunk_size(&self, chunk_size: i64) -> i64 {
        if chunk_size == 0 {
            return self.chunk_initial;
        }
        (chunk_size + self.chunk_step).min(self.chunk_max)
    }

    pub(crate) fn padding_len(
        &self,
        seq: u32,
        payload_len: usize,
        prefix_len: usize,
        salt_prefix_len: usize,
        total_len: usize,
    ) -> usize {
        let payload_len = payload_len as i64;
        let mut padding_len: i64 = 0;
        if seq < self.pad_count
            || (payload_len > 0 && payload_len <= self.small_limit)
            || (self.pad_interval > 0 && seq.is_multiple_of(self.pad_interval))
        {
            padding_len =
                pick(self.namespaces.prf32(LABEL_PAYLOAD_PAD, seq, payload_len as u32), self.pad_min, self.pad_max);
        }
        let payload_tag_len = if payload_len > 0 { AEAD_TAG_LEN as i64 } else { 0 };
        let frame_len = total_len as i64
            + prefix_len as i64
            + HEADER_CIPHER_LEN as i64
            + padding_len
            + payload_len
            + payload_tag_len;
        let target_len = self.write_target(seq, frame_len);
        if target_len > frame_len {
            padding_len += (target_len - frame_len).min(MAX_EXTRA_PADDING);
        }
        if total_len > 0 {
            padding_len =
                self.first_record_padding_len(padding_len, prefix_len as i64, salt_prefix_len as i64, payload_len);
        }
        padding_len.min(0xffff) as usize
    }

    fn write_target(&self, seq: u32, frame_len: i64) -> i64 {
        if frame_len > 0x05b3 {
            if frame_len <= 0xffff {
                return frame_len;
            }
            return 0xffff;
        }
        let ns = &self.namespaces;
        let mut target_len = if seq < self.write_first {
            self.write_seq[seq as usize]
        } else {
            self.write_buckets
                [(ns.prf32(LABEL_WRITE_TARGET, seq, frame_len as u32) % self.write_buckets.len() as u32) as usize]
        };
        if self.write_policy == 2 {
            let raw_jitter = ns.prf32(LABEL_WRITE_JITTER_V, seq, 0);
            let jitter = (raw_jitter % (self.write_jitter * 2 + 1) as u32) as i64 - self.write_jitter;
            target_len = (target_len + jitter).max(1);
        }
        let spread = MAX_EXTRA_PADDING.min(((frame_len as u64) * (self.write_jitter_pct as u64) / 100) as i64);
        if ns.prf32(LABEL_WRITE_TARGET, seq, spread as u32) & 1 == 0 {
            if target_len + spread <= 0xffff {
                target_len += spread;
            } else {
                target_len = 0xffff;
            }
        } else {
            let half_spread = spread >> 1;
            if target_len > half_spread {
                target_len -= half_spread;
            }
        }
        while target_len >= 0 && frame_len > target_len {
            let mut next_len = self.write_buckets
                [(ns.prf32(LABEL_WRITE_NEXT, seq, target_len as u32) % self.write_buckets.len() as u32) as usize];
            if next_len <= target_len {
                next_len = target_len + self.pad_max;
                if next_len > 0xffff {
                    return 0xffff;
                }
            }
            target_len = next_len;
        }
        target_len
    }

    fn first_record_padding_len(
        &self,
        padding_len: i64,
        prefix_len: i64,
        salt_prefix_len: i64,
        payload_len: i64,
    ) -> i64 {
        let overhead_len = salt_prefix_len + prefix_len + padding_len;
        let threshold_input = if payload_len == 0 { payload_len + 0x27 } else { payload_len + 0x37 };
        let threshold = ((threshold_input * 25 + 0x4a) / 75).max(0xc0);
        if overhead_len >= threshold {
            return padding_len;
        }
        let mut target_padding_len = threshold - salt_prefix_len - prefix_len;
        let max_padding_len = self.pad_max + MAX_EXTRA_PADDING;
        if max_padding_len <= target_padding_len {
            target_padding_len = max_padding_len;
        }
        if target_padding_len > 0xfffe {
            return padding_len;
        }
        target_padding_len
    }

    pub(crate) fn fill_padding(&self, seq: u32, output: &mut [u8]) {
        if output.is_empty() {
            return;
        }
        self.namespaces.prf_bytes(LABEL_PADDING, seq, output);
        match self.generator {
            0 => {
                let bit_count = pick_u32(self.namespaces.prf32(LABEL_BIT_PERCENT, seq, 0), self.bit_min, self.bit_max);
                let mut rotate = 1usize;
                let scaled = bit_count as usize * 8;
                if scaled > 0x31 {
                    rotate = 7;
                    if scaled <= 0x02ed {
                        rotate = (scaled + 0x32) / 100;
                    }
                }
                for (index, byte) in output.iter_mut().enumerate() {
                    let value = *byte;
                    let raw = value.wrapping_add(index as u8);
                    let table_row = rotate.max(1);
                    let table_value = BIT_ROTATE_TABLE[table_row * 16 + ((raw ^ value) & 0x0f) as usize];
                    *byte = table_value.rotate_left(((raw ^ (value >> 4)) & 7) as u32);
                }
            }
            1 => {
                let modulus = self.g1 + self.g2 + self.g3;
                for (index, byte) in output.iter_mut().enumerate() {
                    let value = *byte;
                    let bucket = value as i64 % modulus;
                    *byte = if bucket < self.g1 {
                        // Surge 6.7.0 (11520): FUN_100014f98: truncates the byte/index mix before
                        // reducing it into the printable range.
                        pick(value.wrapping_add(index as u8) as u32, 0x20, 0x7e) as u8
                    } else if bucket < self.g1 + self.g2 {
                        pick((value ^ index as u8) as u32, 0x80, 0xbf) as u8
                    } else {
                        pick(value.wrapping_add((index as u8).wrapping_mul(7)) as u32, 0xc0, 0xff) as u8
                    };
                }
            }
            2 => {
                for (index, byte) in output.iter_mut().enumerate() {
                    let value = *byte as i64;
                    let index = index as i64;
                    let low = ((value & 0x0f) + self.g4 + (index & 1)) % 10;
                    let high = (value + ((index & 3) << 4) + 0x30) & 0xf0;
                    *byte = (high | low) as u8;
                }
            }
            3 => {
                let mut motif = [0u8; 32];
                self.namespaces.prf_bytes(LABEL_MOTIF, seq, &mut motif);
                let motif_len = if self.g5 * 4 == 0 { 4 } else { (self.g5 * 4) as usize };
                let period = self.g6.max(5) as usize;
                let mut block_offset = 0usize;
                let mut motif_offset = 0usize;
                for (index, byte) in output.iter_mut().enumerate() {
                    let value = *byte;
                    if block_offset < period - 3 {
                        *byte =
                            (((self.g5 + 3) as usize).wrapping_mul(index) as u8) ^ motif[motif_offset % motif.len()];
                    } else if block_offset < period - 1 {
                        *byte = 0x30 | (value % 10);
                    }
                    block_offset += 1;
                    if block_offset == period {
                        block_offset = 0;
                    }
                    motif_offset += 1;
                    if motif_offset == motif_len {
                        motif_offset = 0;
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    pub(crate) fn mix_padding_payload(&self, seq: u32, padding: &mut [u8], payload_cipher: &mut [u8]) {
        let n = padding.len().min(payload_cipher.len());
        if n == 0 {
            return;
        }
        for round in 0..self.mix_rounds {
            match self.mix_mode {
                0 => self.mix_fixed_stride(round, padding, payload_cipher, n),
                1 => self.mix_alternating_block(round, padding, payload_cipher, n),
                2 => self.mix_prf_stride(seq, round, padding, payload_cipher, n),
                _ => unreachable!(),
            }
        }
    }

    fn mix_fixed_stride(&self, round: u32, padding: &mut [u8], payload_cipher: &mut [u8], n: usize) {
        let stride = (self.mix_stride + (round % 3) as i64).max(1) as usize;
        if stride == 1 {
            for i in 0..n {
                std::mem::swap(&mut padding[i], &mut payload_cipher[i]);
            }
            return;
        }
        let mut off = self.mix_offset_base as usize % stride;
        while off < n {
            std::mem::swap(&mut padding[off], &mut payload_cipher[off]);
            off += stride;
        }
    }

    fn mix_alternating_block(&self, round: u32, padding: &mut [u8], payload_cipher: &mut [u8], n: usize) {
        let block = self.mix_block as usize;
        let mut off = (round & 1) as usize * block;
        while off + block <= n {
            for i in off..off + block {
                std::mem::swap(&mut padding[i], &mut payload_cipher[i]);
            }
            off += block * 2;
        }
    }

    fn mix_prf_stride(&self, seq: u32, round: u32, padding: &mut [u8], payload_cipher: &mut [u8], n: usize) {
        let stride = (self.mix_stride + (round % 3) as i64).max(1) as usize;
        let mut off = ((self.namespaces.prf32(LABEL_MIX_OFFSET, seq, round) as u64 + self.mix_offset_base as u64)
            % stride as u64) as usize;
        if stride == 1 {
            for i in 0..n {
                std::mem::swap(&mut padding[i], &mut payload_cipher[i]);
            }
            return;
        }
        while off < n {
            std::mem::swap(&mut padding[off], &mut payload_cipher[off]);
            off += stride;
        }
    }

    pub(crate) fn extract_salt(&self, block: &[u8]) -> [u8; SALT_LEN] {
        let perm = shuffle_perm(self.namespaces.salt, self.mix_rounds_handshake as u8, block.len());
        let mut out = [0u8; SALT_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte =
                salt_mask(self.namespaces.salt, self.mix_stride_handshake as u8, i as u32) ^ block[perm[i] as usize];
        }
        out
    }

    pub(crate) fn write_salt_block(&self, salt: &[u8], block: &mut [u8]) {
        let perm = shuffle_perm(self.namespaces.salt, self.mix_rounds_handshake as u8, block.len());
        for i in 0..SALT_LEN {
            block[perm[i] as usize] =
                salt_mask(self.namespaces.salt, self.mix_stride_handshake as u8, i as u32) ^ salt[i];
        }
    }
}

fn salt_shuffle_prf(ns_salt: u64, domain: u32, index: u32) -> u32 {
    let rdx = (index as u64).wrapping_mul(COEF_B).wrapping_add(ADD_B);
    let rdi = ns_salt ^ SALT_NS_XOR;
    let rsi = (domain as u64).wrapping_mul(COEF_A).wrapping_add(ADD_A);
    let y = splitmix64((rdx ^ rdi) ^ rsi);
    (y ^ (y >> 32)) as u32
}

fn shuffle_perm(ns_salt: u64, rounds: u8, length: usize) -> Vec<u8> {
    let mut out: Vec<u8> = (0..length).map(|index| index as u8).collect();
    if length == 0 {
        return out;
    }
    let rounds = if rounds == 0 { 1 } else { rounds };
    for round in 0..rounds as u32 {
        let domain = MIX_HANDSHAKE_DOMAIN + round;
        for i in 0..length {
            let span = (length - i) as u64;
            let raw = salt_shuffle_prf(ns_salt, domain, i as u32) as u64;
            let j = i + (raw % span) as usize;
            out.swap(i, j);
        }
    }
    out
}

fn salt_mask(ns_salt: u64, mix_stride: u8, index: u32) -> u8 {
    let prf = prf32_fold(ns_salt, LABEL_MOTIF, MIX_HANDSHAKE_DOMAIN as u64, index as u64);
    (index as u8).wrapping_mul(mix_stride) ^ prf as u8
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::*;

    fn join<T: std::fmt::Display>(values: &[T]) -> String {
        let parts: Vec<String> = values.iter().map(ToString::to_string).collect();
        format!("[{}]", parts.join(", "))
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Renders the same vectors as the Go reference's `TestDumpVectors`
    /// (`tests/fixtures/v6_vectors.txt`).
    fn dump(psk: &str) -> String {
        let p = Profile::new(psk.as_bytes());
        let mut b = String::new();
        writeln!(b, "psk {psk}").unwrap();
        writeln!(b, "profile {}", describe(&p)).unwrap();
        let prefixes: Vec<usize> = (0..24).map(|seq| p.record_prefix_len(seq)).collect();
        writeln!(b, "prefix {}", join(&prefixes)).unwrap();
        let mut chunks = Vec::new();
        for seq in [0, 1, 2, 5, 17, 100] {
            for size in [0, 0x60, 0x200, 0x5b4, 0x1000, 0x3fff, 0x10000] {
                chunks.push(p.chunk_payload_limit(seq, size));
            }
        }
        writeln!(b, "chunk {}", join(&chunks)).unwrap();
        let mut paddings = Vec::new();
        for seq in [0, 1, 2, 3, 7, 8, 11, 12, 33, 1000] {
            for payload_len in [0, 1, 0x60, 0x2ff, 0x300, 0x500, 0x5b4, 0x2000, 0xffff] {
                let prefix_len = p.record_prefix_len(seq);
                paddings.push(p.padding_len(seq, payload_len, prefix_len, 0, 0));
                paddings.push(p.padding_len(
                    seq,
                    payload_len,
                    prefix_len,
                    p.salt_block_len - SALT_LEN,
                    p.salt_block_len,
                ));
            }
        }
        writeln!(b, "padding {}", join(&paddings)).unwrap();
        let mut targets = Vec::new();
        for seq in [0, 1, 4, 7, 8, 9, 50] {
            for frame_len in [0, 1, 0x40, 0x100, 0x200, 0x400, 0x5b3, 0x5b4, 0x2000, 0x10000] {
                targets.push(p.write_target(seq, frame_len));
            }
        }
        writeln!(b, "target {}", join(&targets)).unwrap();
        for seq in [0, 1, 2, 3, 9, 0xffffffff] {
            let mut fill = [0u8; 97];
            p.fill_padding(seq, &mut fill);
            writeln!(b, "fill {seq} {}", hex(&fill)).unwrap();
        }
        for seq in [0, 5] {
            for (padding_len, payload_len) in [(0, 10), (10, 0), (37, 200), (300, 100), (1024, 1040)] {
                let mut padding: Vec<u8> = (0..padding_len).map(|i| i as u8).collect();
                let mut payload: Vec<u8> = (0..payload_len).map(|i| (0x80 + i) as u8).collect();
                p.mix_padding_payload(seq, &mut padding, &mut payload);
                writeln!(b, "mix {seq} {padding_len} {payload_len} {} {}", hex(&padding), hex(&payload)).unwrap();
            }
        }
        let salt = b"0123456789abcdef";
        let mut block = vec![0u8; p.salt_block_len];
        p.fill_padding(0xffffffff, &mut block);
        p.write_salt_block(salt, &mut block);
        let extracted = p.extract_salt(&block);
        assert_eq!(salt, &extracted);
        writeln!(b, "salt {} {}", hex(&block), hex(&extracted)).unwrap();
        b
    }

    #[test]
    fn profile_matches_go_reference() {
        let fixture = include_str!("../../tests/fixtures/v6_vectors.txt");
        let mut psks = 0;
        for section in fixture.split("psk ").filter(|section| !section.is_empty()) {
            let psk = section.lines().next().unwrap();
            let expected = format!("psk {section}");
            let actual = dump(psk);
            for (line, (want, got)) in expected.lines().zip(actual.lines()).enumerate() {
                assert_eq!(want, got, "psk {psk:?} line {line}");
            }
            assert_eq!(expected.lines().count(), actual.lines().count(), "psk {psk:?}");
            psks += 1;
        }
        assert_eq!(45, psks);
    }

    /// A stable rendering of every derived field, used to compare against the Go implementation.
    fn describe(profile: &Profile) -> String {
        let p = profile;
        format!(
            "gen={} pad={}..{} padCount={} padInterval={} small={} bit={}..{} prefix={}..{} mix={}/{}/{}/{}/{} \
             chunk={}/{}/{}/{}/{}/{} idle={} write={}/{}/{}/{} buckets={:?}/{:?}/{:?} g={}/{}/{}/{}/{}/{} \
             salt={}/{}/{} headroom={}/{}",
            p.generator,
            p.pad_min,
            p.pad_max,
            p.pad_count,
            p.pad_interval,
            p.small_limit,
            p.bit_min,
            p.bit_max,
            p.prefix_min_record,
            p.prefix_max_record,
            p.mix_mode,
            p.mix_rounds,
            p.mix_stride,
            p.mix_offset_base,
            p.mix_block,
            p.chunk_policy,
            p.chunk_initial,
            p.first_record_cap,
            p.chunk_max,
            p.chunk_step,
            p.chunk_jitter,
            p.idle_reset_sec,
            p.write_policy,
            p.write_first,
            p.write_jitter,
            p.write_jitter_pct,
            p.chunk_buckets,
            p.write_buckets,
            p.write_seq,
            p.g1,
            p.g2,
            p.g3,
            p.g4,
            p.g5,
            p.g6,
            p.salt_block_len,
            p.mix_stride_handshake,
            p.mix_rounds_handshake,
            p.record_prefix_max,
            p.pad_max_headroom,
        )
    }
}
