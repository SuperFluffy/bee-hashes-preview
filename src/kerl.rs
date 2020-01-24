use crate::{Sponge, Trits, TritsMut};
use tiny_keccak::{Hasher, Keccak};

pub const RADIX: i32 = 3;
pub const BYTE_LENGTH: usize = 48;
pub const TRIT_LENGTH: usize = 243;
pub const INT_LENGTH: usize = BYTE_LENGTH / 4;
/// `3**242/2`
pub const HALF_3: [u32; 12] = [
    0xa5ce8964,
    0x9f007669,
    0x1484504f,
    0x3ade00d9,
    0x0c24486e,
    0x50979d57,
    0x79a4c702,
    0x48bbae36,
    0xa9f6808b,
    0xaa06a805,
    0xa87fabdf,
    0x5e69ebef,
];

#[derive(Clone)]
pub struct Kerl(Keccak);

impl Default for Kerl {
    fn default() -> Kerl {
        Kerl(Keccak::v384())
    }
}

impl Sponge for Kerl {
    const HASH_LEN: usize = TRIT_LENGTH;
    
    fn absorb(&mut self, input: &Trits) {
        assert_eq!(input.len() % TRIT_LENGTH, 0);
        let mut bytes: [u8; BYTE_LENGTH] = [0; BYTE_LENGTH];

        for chunk in input.0.chunks(TRIT_LENGTH) {
            trits_to_bytes(chunk, &mut bytes);
            self.0.update(&bytes);
        }
    }

    fn squeeze_into(&mut self, buf: &mut TritsMut) {
        assert_eq!(buf.len() % TRIT_LENGTH, 0);
        let mut bytes: [u8; BYTE_LENGTH] = [0; BYTE_LENGTH];

        for chunk in buf.0.chunks_mut(TRIT_LENGTH) {
            self.0.clone().finalize(&mut bytes);
            self.reset();
            bytes_to_trits(&mut bytes.to_vec(), chunk);
            for b in bytes.iter_mut() {
                *b = *b ^ 0xFF;
            }
            self.0.update(&bytes);
        }
    }

    fn reset(&mut self) {
        self.0 = Keccak::v384();
    }
}

/// For more information about byte encoding and how BigInt is used, please see
/// the following link: https://github.com/iotaledger/kerl/blob/master/IOTA-Kerl-spec.md#trits---bytes-encoding
fn trits_to_bytes(trits: &[i8], bytes: &mut [u8]) {
    assert_eq!(trits.len(), TRIT_LENGTH);
    assert_eq!(bytes.len(), BYTE_LENGTH);

    let mut base = [0; INT_LENGTH];

    base.clone_from_slice(&[0; 12]);

    let mut size = 1;
    let mut all_minus_1 = true;

    for t in trits[0..TRIT_LENGTH - 1].iter() {
        if *t != -1 {
            all_minus_1 = false;
            break;
        }
    }

    if all_minus_1 {
        base.clone_from_slice(&HALF_3);
        bigint_not(&mut base);
        bigint_add_small(&mut base, 1_u32);
    } else {
        for t in trits[0..TRIT_LENGTH - 1].iter().rev() {
            // multiply by radix
            {
                let sz = size;
                let mut carry: u32 = 0;

                for j in 0..sz {
                    let v = (base[j] as u64) * (RADIX as u64) + (carry as u64);
                    let (newcarry, newbase) = ((v >> 32) as u32, v as u32);
                    carry = newcarry;
                    base[j] = newbase;
                }

                if carry > 0 {
                    base[sz] = carry;
                    size += 1;
                }
            }

            let trit = (t + 1) as u32;
            // addition
            {
                let sz = bigint_add_small(&mut base, trit);
                if sz > size {
                    size = sz;
                }
            }
        }

        if !is_null(&base) {
            if bigint_cmp(&HALF_3, &base) <= 0 {
                // base >= HALF_3
                // just do base - HALF_3
                bigint_sub(&mut base, &HALF_3);
            } else {
                // we don't have a wrapping sub.
                // so let's use some bit magic to achieve it
                let mut tmp = HALF_3.clone();
                bigint_sub(&mut tmp, &base);
                bigint_not(&mut tmp);
                bigint_add_small(&mut tmp, 1_u32);
                base.clone_from_slice(&tmp);
            }
        }
    }

    let mut out = [0; BYTE_LENGTH];
    for i in 0..INT_LENGTH {
        let offset = i * 4;
        let tmp_base = base[INT_LENGTH - 1 - i];
        out[offset] = ((tmp_base & 0xFF00_0000) >> 24) as u8;
        out[offset + 1] = ((tmp_base & 0x00FF_0000) >> 16) as u8;
        out[offset + 2] = ((tmp_base & 0x0000_FF00) >> 8) as u8;
        out[offset + 3] = (tmp_base & 0x0000_00FF) as u8;
    }
    bytes.copy_from_slice(&out);
}

/// This will consume the input bytes slice and write to trits.
fn bytes_to_trits(bytes: &mut [u8], trits: &mut [i8]) {
    assert_eq!(bytes.len(), BYTE_LENGTH);
    assert_eq!(trits.len(), TRIT_LENGTH);

    trits[TRIT_LENGTH - 1] = 0;

    let mut base = [0; INT_LENGTH];
    for i in 0..INT_LENGTH {
        base[INT_LENGTH - 1 - i] = u32::from(bytes[i * 4]) << 24;
        base[INT_LENGTH - 1 - i] |= u32::from(bytes[i * 4 + 1]) << 16;
        base[INT_LENGTH - 1 - i] |= u32::from(bytes[i * 4 + 2]) << 8;
        base[INT_LENGTH - 1 - i] |= u32::from(bytes[i * 4 + 3]);
    }

    if is_null(&base) {
        trits.clone_from_slice(&[0; TRIT_LENGTH]);
        return;
    }

    let mut flip_trits = false;

    if base[INT_LENGTH - 1] >> 31 == 0 {
        // positive number
        // we need to add HALF_3 to move it into positvie unsigned space
        bigint_add(&mut base, &HALF_3);
    } else {
        // negative number
        bigint_not(&mut base);
        if bigint_cmp(&base, &HALF_3) > 0 {
            bigint_sub(&mut base, &HALF_3);
            flip_trits = true;
        } else {
            bigint_add_small(&mut base, 1 as u32);
            let mut tmp = HALF_3.clone();
            bigint_sub(&mut tmp, &mut base);
            base.clone_from_slice(&tmp);
        }
    }

    let mut rem;
    for i in 0..TRIT_LENGTH - 1 {
        rem = 0;
        for j in (0..INT_LENGTH).rev() {
            let lhs = ((rem as u64) << 32) | (base[j] as u64);
            let rhs = RADIX as u64;
            let q = (lhs / rhs) as u32;
            let r = (lhs % rhs) as u32;

            base[j] = q;
            rem = r;
        }
        trits[i] = rem as i8 - 1;
    }

    if flip_trits {
        for v in trits.iter_mut() {
            *v = -*v;
        }
    }
}

fn bigint_not(base: &mut [u32]) {
    for i in base.iter_mut() {
        *i = !*i;
    }
}

fn bigint_add_small(base: &mut [u32], other: u32) -> usize {
    let (mut carry, v) = full_add(base[0], other, false);
    base[0] = v;

    let mut i = 1;
    while carry {
        let (c, v) = full_add(base[i], 0, carry);
        base[i] = v;
        carry = c;
        i += 1;
    }

    i
}

fn bigint_add(base: &mut [u32], rh: &[u32]) {
    let mut carry = false;

    for (a, b) in base.iter_mut().zip(rh.iter()) {
        let (c, v) = full_add(*a, *b, carry);
        *a = v;
        carry = c;
    }
}

fn bigint_cmp(lh: &[u32], rh: &[u32]) -> i8 {
    for (a, b) in lh.iter().rev().zip(rh.iter().rev()) {
        if a < b {
            return -1;
        } else if a > b {
            return 1;
        }
    }
    return 0;
}

fn bigint_sub(base: &mut [u32], rh: &[u32]) {
    let mut noborrow = true;
    for (a, b) in base.iter_mut().zip(rh) {
        let (c, v) = full_add(*a, !*b, noborrow);
        *a = v;
        noborrow = c;
    }
    assert!(noborrow);
}

fn is_null(base: &[u32]) -> bool {
    for b in base.iter() {
        if *b != 0 {
            return false;
        }
    }
    return true;
}

fn full_add(lh: u32, rh: u32, carry: bool) -> (bool, u32) {
    let a = u64::from(lh);
    let b = u64::from(rh);

    let mut v = a + b;
    let mut l = v >> 32;
    let mut r = v & 0xFFFF_FFFF;

    let carry1 = l != 0;

    if carry {
        v = r + 1;
    }
    l = (v >> 32) & 0xFFFF_FFFF;
    r = v & 0xFFFF_FFFF;
    let carry2 = l != 0;
    (carry1 || carry2, r as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::trytes_to_trits_buf;

    const EXPECTED_KERL_HASH_TRYTES: &str = "\
LUCKQVACOGBFYSPPVSSOXJEKNSQQRQKPZC9NXFSMQNRQCGGUL9OHVVKBDSKEQEBKXRNUJSRX\
YVHJTXBPD";

    const INPUT_TRYTES: &str = "\
G9JYBOMPUXHYHKSNRNMMSSZCSHOFYOYNZRSZMAAYWDYEIMVVOGKPJBVBM9TD\
PULSFUNMTVXRKFIDOHUXXVYDLFSZYZTWQYTE9SPYYWYTXJYQ9IFGYOLZXWZB\
KWZN9QOOTBQMWMUBLEWUEEASRHRTNIQWJQNDWRYLCA";


    #[test]
    fn verify_kerl_hash_trytes() {
        let mut kerl = Kerl::default();
        let input_trits = trytes_to_trits_buf(INPUT_TRYTES);
        let expected_hash = trytes_to_trits_buf(EXPECTED_KERL_HASH_TRYTES);
        let calculated_hash = kerl.digest(&input_trits.as_trits());
        assert_eq!(expected_hash, calculated_hash);
    }
}