//! Bit-balancing record padding shared by v4 and v5.

use rand::Rng;

/// The two ways the official implementations evaluate the target bit count.
/// They differ only in floating point evaluation order, which is kept.
#[derive(Clone, Copy)]
pub(crate) enum TargetFormula {
    /// Surge 6.7.0 (11520): `totalBits * (ratio / (ratio + 1))`.
    V4,
    /// snell-server v5.0.1: `totalBits * ratio / (ratio + 1)`.
    V5,
}

/// The process `rand()` 31-bit range.
pub(crate) fn random_int31() -> usize {
    (rand::rng().next_u32() & 0x7fffffff) as usize
}

fn fill_random(padding: &mut [u8]) {
    rand::rng().fill_bytes(padding);
}

pub(crate) fn fill_padding(padding: &mut [u8], payload_cipher: &[u8], formula: TargetFormula) {
    if padding.is_empty() {
        return;
    }
    // Surge 6.7.0 (11520): FUN_100012b24 / snell-server v5.0.1: FUN_00138af0 count ones only over
    // complete 32-bit chunks, but compute zeros against the full payload cipher length.
    let payload_count_len = payload_cipher.len() & !3;
    let payload_ones: i64 = payload_cipher[..payload_count_len].iter().map(|b| b.count_ones() as i64).sum();
    let payload_zeros = 8 * payload_cipher.len() as i64 - payload_ones;
    if payload_zeros <= 0 {
        fill_random(padding);
        return;
    }

    let ratio = payload_ones as f64 / payload_zeros as f64;
    if ratio <= 0.5 || ratio >= 1.6 {
        fill_random(padding);
        return;
    }

    let target_ratio_base = if payload_zeros < payload_ones { 0.4 } else { 1.6 };
    // Surge 6.7.0 (11520): FUN_100012944 / snell-server v5.0.1: FUN_00138af0 derive the target padding
    // ratio as base + rand()/2147483647.0/10, using the process rand() 31-bit range.
    let target_ratio = target_ratio_base + random_int31() as f64 / 2147483647.0 / 10.0;
    let total_bits = (8 * (padding.len() + payload_cipher.len())) as f64;
    let target = match formula {
        TargetFormula::V4 => total_bits * (target_ratio / (target_ratio + 1.0)) - payload_ones as f64,
        TargetFormula::V5 => total_bits * target_ratio / (target_ratio + 1.0) - payload_ones as f64,
    };
    let target_ones = target as i64;
    if target_ones < 0 || target_ones > 8 * padding.len() as i64 {
        fill_random(padding);
        return;
    }
    fill_padding_with_bit_count(padding, target_ones as usize);
}

pub(crate) fn fill_padding_with_bit_count(padding: &mut [u8], one_bits: usize) {
    let total_bits = 8 * padding.len();
    assert!(one_bits <= total_bits, "snell: invalid padding bit count");
    let mut bitset = vec![0u8; total_bits];
    bitset[..one_bits].fill(1);
    // Surge 6.7.0 (11520): FUN_100012eb8 / snell-server v5.0.1: FUN_00138af0 shuffle from the front and
    // map rand() with division by RAND_MAX/remaining+1, preserving its modulo bias.
    let mut position = 0;
    let mut remaining = total_bits;
    while remaining != 1 {
        let random_value = random_int31();
        let divisor = 0x7fffffff_usize.checked_div(remaining).unwrap_or(0);
        let swap_index = position + random_value / (divisor + 1);
        bitset.swap(swap_index, position);
        position += 1;
        remaining -= 1;
    }
    padding.fill(0);
    for (index, bit) in bitset.iter().enumerate() {
        if *bit == 1 {
            padding[index / 8] |= 1 << (index % 8);
        }
    }
}

/// Swaps every other byte between the padding and the payload cipher.
pub(crate) fn swap_even(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    let mut index = 0;
    while index < limit {
        std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
        index += 2;
    }
}
