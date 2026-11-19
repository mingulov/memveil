// SPDX-License-Identifier: GPL-3.0-or-later
//! SHA-256 over bytes (narrow identity bindings).
//!
//! Pure code, no project dependencies: the standard FIPS 180-4
//! compression function with wrapping `u32` arithmetic.
//! Used to hash kernel config bytes, BTF, hook format
//! text, the BPF object, and the boot image for narrow
//! identity binding checks and committed capture event bytes.

/// Render bytes as lowercase hex with no separator.
pub fn bytes_to_hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0xF) as usize] as char);
    }
    out
}

fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

/// Compress the 64 bytes at `base` into the running state.
fn sha256_block(h: &mut [u32; 8], data: &[u8], base: usize) {
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ];
    let mut w = [0u32; 64];
    for (i, slot) in w.iter_mut().enumerate().take(16) {
        let o = base + 4 * i;
        *slot = (u32::from(data[o]) << 24)
            | (u32::from(data[o + 1]) << 16)
            | (u32::from(data[o + 2]) << 8)
            | u32::from(data[o + 3]);
    }
    for i in 16..64 {
        let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
    let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);
    for i in 0..64 {
        let big_s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let big_s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// SHA-256 digest of `data` as 64 lowercase hex chars.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut state = Sha256::new();
    state.update(data);
    state.copy_finish()
}

/// Incremental SHA-256; snapshots never consume the running state.
#[derive(Debug, Clone)]
pub struct Sha256 {
    h: [u32; 8],
    tail: Vec<u8>,
    bytes: u64,
}

impl Sha256 {
    /// A fresh digest state.
    pub fn new() -> Self {
        Self {
            h: [
                0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
                0x5BE0CD19,
            ],
            tail: Vec::new(),
            bytes: 0,
        }
    }

    /// Feed more bytes into the running state.
    pub fn update(&mut self, data: &[u8]) {
        self.bytes += data.len() as u64;
        let mut offset = 0;
        if !self.tail.is_empty() {
            while offset < data.len() && self.tail.len() < 64 {
                self.tail.push(data[offset]);
                offset += 1;
            }
            if self.tail.len() == 64 {
                let tail = std::mem::take(&mut self.tail);
                sha256_block(&mut self.h, &tail, 0);
            }
        }
        while offset + 64 <= data.len() {
            sha256_block(&mut self.h, data, offset);
            offset += 64;
        }
        while offset < data.len() {
            self.tail.push(data[offset]);
            offset += 1;
        }
    }

    /// The hex digest of everything fed so far, state untouched.
    pub fn copy_finish(&self) -> String {
        let mut h = self.h;
        let mut tail = self.tail.clone();
        tail.push(0x80);
        while tail.len() % 64 != 56 {
            tail.push(0);
        }
        let bits = self.bytes.wrapping_mul(8);
        for i in 0..8 {
            tail.push((bits >> (8 * (7 - i))) as u8);
        }
        for offset in (0..tail.len()).step_by(64) {
            sha256_block(&mut h, &tail, offset);
        }
        let mut digest = Vec::with_capacity(32);
        for word in h {
            for shift in [24, 16, 8, 0] {
                digest.push((word >> shift) as u8);
            }
        }
        bytes_to_hex(&digest)
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{Sha256, bytes_to_hex, sha256_hex};

    #[test]
    fn empty_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb924\
             27ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223\
             b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fifty_six_byte_vector() {
        // 448-bit boundary: padding spills into a second block.
        let data = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(data.len(), 56);
        assert_eq!(
            sha256_hex(data),
            "248d6a61d20638b8e5c026930c3e603\
             9a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sixty_four_byte_vector() {
        let data = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
        assert_eq!(data.len(), 64);
        assert_eq!(
            sha256_hex(data),
            "2ff100b36c386c65a1afc462ad53e254\
             79bec9498ed00aa5a04de584bc25301b"
        );
    }

    #[test]
    fn million_a_vector() {
        let data = vec![0x61u8; 1_000_000];
        assert_eq!(
            sha256_hex(&data),
            "cdc76e5c9914fb9281a1c7e284d73e6\
             7f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn incremental_snapshots() {
        let mut state = Sha256::new();
        assert_eq!(state.copy_finish(), sha256_hex(b""));
        let mut all_bytes: Vec<u8> = Vec::new();
        let expected = [
            "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488",
            "85c3bb135868f1433c5ec5f878d8b697acd27f3ed0c9f79af206ea416bca0d38",
            "9ee5f9064bf5ad41d0c1daea1b5218cff51e99e29b6052e36089ac4b9fee10ad",
            "a5ca14441f7f93913610bec51b63dc7f3c215ce8c7b23f8eb8761047ebfa6f4f",
            "9114e2764fd7046bf8673bbdb07260abf1e6682dbdbeb19905edb0dd1148fbee",
        ];
        for (step, size) in [63usize, 64, 65, 1, 127].into_iter().enumerate() {
            let mut chunk: Vec<u8> = Vec::new();
            for i in 0..size {
                chunk.push((i % 251) as u8);
                all_bytes.push((i % 251) as u8);
            }
            state.update(&chunk);
            assert_eq!(state.copy_finish(), expected[step]);
            assert_eq!(state.copy_finish(), sha256_hex(&all_bytes));
            assert_eq!(state.copy_finish(), sha256_hex(&all_bytes));
        }
    }

    #[test]
    fn hex_renders_lowercase_without_separator() {
        assert_eq!(bytes_to_hex(&[]), "");
        assert_eq!(bytes_to_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
