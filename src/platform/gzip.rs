// SPDX-License-Identifier: GPL-3.0-or-later
//! Single-member gzip inflation via the system zlib.
//!
//! `/proc/config.gz` is gzip-framed deflate; the config
//! binding hashes the INFLATED bytes. Decompression runs
//! through raw `inflate` (-15 window) from `libz.so.1`,
//! opened with `dlopen` at call time: no link-time
//! dependency, and a missing zlib reports uncheckable
//! instead of failing the run. Framing is strict-parsed
//! (magic, method, flags, name/comment terminators, header
//! CRC when present, stream CRC32, ISIZE); only trailing
//! bytes after the first member are ignored.

const MAX_GUNZIP_BYTES: u32 = 16_777_216;
const Z_FINISH: libc::c_int = 4;
const Z_STREAM_END: libc::c_int = 1;

/// Raw `z_stream` layout (LP64, 112 bytes).
///
/// Only the transfer fields are touched: `next_in`@0, `avail_in`@8,
/// `next_out`@24, `avail_out`@32, `total_out`@40; the rest stays zero
/// for default allocation. The behavioral ABI probe below re-verifies
/// this layout against the loaded zlib on every call.
#[repr(C)]
struct ZStream {
    next_in: *const u8,
    avail_in: u32,
    _pad0: u32,
    total_in: u64,
    next_out: *mut u8,
    avail_out: u32,
    _pad1: u32,
    total_out: u64,
    msg: *mut u8,
    state: *mut u8,
    zalloc: *mut u8,
    zfree: *mut u8,
    opaque: *mut u8,
    data_type: libc::c_int,
    _pad2: u32,
    adler: u64,
    reserved: u64,
}

const _: () = assert!(size_of::<ZStream>() == 112);
const _: () = assert!(std::mem::offset_of!(ZStream, next_in) == 0);
const _: () = assert!(std::mem::offset_of!(ZStream, avail_in) == 8);
const _: () = assert!(std::mem::offset_of!(ZStream, next_out) == 24);
const _: () = assert!(std::mem::offset_of!(ZStream, avail_out) == 32);
const _: () = assert!(std::mem::offset_of!(ZStream, total_out) == 40);

impl ZStream {
    fn zeroed() -> Self {
        // SAFETY: all-zero is valid: null pointers, zero counts.
        unsafe { std::mem::zeroed() }
    }
}

type Crc32Fn = unsafe extern "C" fn(u64, *const u8, u32) -> u64;
type InflateInit2Fn = unsafe extern "C" fn(
    *mut ZStream,
    libc::c_int,
    *const libc::c_char,
    libc::c_int,
) -> libc::c_int;
type InflateFn = unsafe extern "C" fn(*mut ZStream, libc::c_int) -> libc::c_int;
type InflateEndFn = unsafe extern "C" fn(*mut ZStream) -> libc::c_int;

/// One `dlopen`ed zlib with its four resolved symbols.
///
/// Never leaves the opening thread: the handle opens, probes,
/// inflates, and closes inside one `gunzip_member` call.
struct Zlib {
    _handle: *mut libc::c_void,
    crc32: Crc32Fn,
    inflate_init: InflateInit2Fn,
    inflate: InflateFn,
    inflate_end: InflateEndFn,
}

impl Zlib {
    /// Open `lib_name` without resolving symbols yet.
    fn open_handle(lib_name: &str) -> Option<*mut libc::c_void> {
        use std::ffi::CString;
        let soname = CString::new(lib_name).ok()?;
        // SAFETY: NUL-terminated soname; NULL return means unavailable.
        let handle = unsafe { libc::dlopen(soname.as_ptr(), libc::RTLD_NOW) };
        if handle.is_null() {
            return None;
        }
        Some(handle)
    }

    /// Resolve the inflate entry points of an open handle.
    ///
    /// A miss closes the handle and reports `None`: like the
    /// ABI probe, a present library without zlib symbols is an
    /// ABI mismatch, never an unavailable library.
    fn resolve(handle: *mut libc::c_void) -> Option<Self> {
        use std::mem::transmute_copy;
        // SAFETY: dlsym on a live handle with NUL-terminated names;
        // a NULL result means the symbol is absent.
        unsafe fn lookup<T>(handle: *mut libc::c_void, name: &[u8]) -> Option<T> {
            // SAFETY: caller holds a live dlopen handle.
            let sym = unsafe { libc::dlsym(handle, name.as_ptr().cast::<libc::c_char>()) };
            if sym.is_null() {
                return None;
            }
            // SAFETY: a non-NULL dlsym result converts to the
            // caller's function-pointer type by construction.
            Some(unsafe { transmute_copy::<*mut libc::c_void, T>(&sym) })
        }
        // SAFETY: as above; on any miss the handle closes here.
        unsafe {
            match (
                lookup::<Crc32Fn>(handle, b"crc32\0"),
                lookup::<InflateInit2Fn>(handle, b"inflateInit2_\0"),
                lookup::<InflateFn>(handle, b"inflate\0"),
                lookup::<InflateEndFn>(handle, b"inflateEnd\0"),
            ) {
                (Some(crc32), Some(init), Some(inflate), Some(end)) => Some(Self {
                    _handle: handle,
                    crc32,
                    inflate_init: init,
                    inflate,
                    inflate_end: end,
                }),
                _ => {
                    libc::dlclose(handle);
                    None
                }
            }
        }
    }

    /// Probe the hand-built `z_stream` layout against this zlib.
    ///
    /// Inflates a fixed raw-deflate vector through freshly
    /// hand-poked fields and checks the bytes, `total_out`, and
    /// the crc32 check value. Any deviation (field layout,
    /// endianness, signature) fails closed before real input
    /// runs.
    fn abi_ok(&self) -> bool {
        // SAFETY: all calls below use resolved zlib symbols with live
        // buffers; lengths fit u32 and the stream is freshly zeroed.
        unsafe {
            let check = (self.crc32)(0, b"123456789".as_ptr(), 9);
            if check != 0xCBF43926 {
                return false;
            }
            let probe_in: [u8; 27] = [
                203, 77, 205, 45, 75, 205, 204, 209, 173, 202, 201, 76, 210, 77, 76, 202, 212, 45,
                40, 202, 79, 74, 213, 45, 51, 4, 0,
            ];
            let want = b"memveil-zlib-abi-probe-v1";
            let mut probe_out = [0u8; 64];
            let mut zs = ZStream::zeroed();
            zs.next_in = probe_in.as_ptr();
            zs.avail_in = probe_in.len() as u32;
            zs.next_out = probe_out.as_mut_ptr();
            zs.avail_out = probe_out.len() as u32;
            let versa = b"1.2.0\0";
            let init_rc = (self.inflate_init)(
                &mut zs,
                -15,
                versa.as_ptr().cast::<libc::c_char>(),
                size_of::<ZStream>() as libc::c_int,
            );
            if init_rc != 0 {
                return false;
            }
            let frc = (self.inflate)(&mut zs, Z_FINISH);
            let _ = (self.inflate_end)(&mut zs);
            if frc != Z_STREAM_END {
                return false;
            }
            if zs.total_out != want.len() as u64 {
                return false;
            }
            if probe_out[..want.len()] != want[..] {
                return false;
            }
            // All input consumed, none mutated: inflate reads its
            // input exactly once. These reads also keep the input
            // buffer alive across the FFI calls above.
            if zs.avail_in != 0 {
                return false;
            }
            if probe_in
                != [
                    203, 77, 205, 45, 75, 205, 204, 209, 173, 202, 201, 76, 210, 77, 76, 202, 212,
                    45, 40, 202, 79, 74, 213, 45, 51, 4, 0,
                ]
            {
                return false;
            }
            true
        }
    }
}

impl Drop for Zlib {
    fn drop(&mut self) {
        // SAFETY: handle from a successful dlopen, closed once.
        unsafe {
            libc::dlclose(self._handle);
        }
    }
}

/// One inflation outcome (`data` valid only when `ok`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GunzipOut {
    /// True when the member inflated and verified.
    pub ok: bool,
    /// The inflated bytes; empty unless `ok`.
    pub data: Vec<u8>,
    /// Failure detail; empty on success.
    pub message: String,
}

fn u16le(data: &[u8], at: usize) -> usize {
    usize::from(data[at]) | (usize::from(data[at + 1]) << 8)
}

fn u32le(data: &[u8], at: usize) -> u32 {
    u32::from(data[at])
        | (u32::from(data[at + 1]) << 8)
        | (u32::from(data[at + 2]) << 16)
        | (u32::from(data[at + 3]) << 24)
}

fn fail(message: &str) -> GunzipOut {
    GunzipOut {
        ok: false,
        data: Vec::new(),
        message: message.to_string(),
    }
}

/// Inflate the first gzip member of `data`.
///
/// `lib_name` is the zlib soname (normally `libz.so.1`);
/// callers pass a bogus name only to prove the
/// missing-library path stays uncheckable, never fatal.
pub fn gunzip_member(data: &[u8], lib_name: &str) -> GunzipOut {
    let total = data.len();
    if total < 18 {
        return fail("gzip too short");
    }
    if total > u32::MAX as usize {
        return fail("gzip input too big");
    }
    if data[0] != 0x1F || data[1] != 0x8B {
        return fail("gzip bad magic");
    }
    if data[2] != 8 {
        return fail("gzip not deflate");
    }
    let flg = data[3];
    if flg & 0xE0 != 0 {
        return fail("gzip reserved flags");
    }
    let mut pos = 10;
    if flg & 0x04 != 0 {
        if pos + 2 > total {
            return fail("gzip truncated extra");
        }
        pos += 2 + u16le(data, pos);
        if pos > total {
            return fail("gzip truncated extra");
        }
    }
    if flg & 0x08 != 0 {
        loop {
            if pos >= total {
                return fail("gzip unterminated name");
            }
            if data[pos] == 0 {
                break;
            }
            pos += 1;
        }
        pos += 1;
    }
    if flg & 0x10 != 0 {
        loop {
            if pos >= total {
                return fail("gzip unterminated comment");
            }
            if data[pos] == 0 {
                break;
            }
            pos += 1;
        }
        pos += 1;
    }
    let header_end = pos;
    if flg & 0x02 != 0 {
        if pos + 2 > total {
            return fail("gzip truncated header crc");
        }
        pos += 2;
    }
    if pos + 8 > total {
        return fail("gzip truncated stream");
    }
    let want_crc = u32le(data, total - 8);
    let isize = u32le(data, total - 4);
    if isize > MAX_GUNZIP_BYTES {
        return fail("gzip output too big");
    }
    if isize == 0 {
        if want_crc != 0 {
            return fail("gzip crc mismatch");
        }
        return GunzipOut {
            ok: true,
            data: Vec::new(),
            message: String::new(),
        };
    }
    let handle = match Zlib::open_handle(lib_name) {
        Some(handle) => handle,
        None => return fail("zlib unavailable"),
    };
    let lib = match Zlib::resolve(handle) {
        Some(lib) => lib,
        None => return fail("zlib ABI mismatch"),
    };
    if !lib.abi_ok() {
        return fail("zlib ABI mismatch");
    }
    // SAFETY: resolved zlib symbols with live buffers; the ABI probe
    // above already verified layout, endianness, and signatures.
    unsafe {
        if flg & 0x02 != 0 {
            let header_crc = (lib.crc32)(0, data.as_ptr(), header_end as u32);
            if (header_crc & 0xFFFF) as usize != u16le(data, header_end) {
                return fail("gzip header crc mismatch");
            }
        }
        // Raw inflate through a hand-built z_stream (LP64
        // layout, 112 bytes; inflateInit2_ checks only
        // version[0] ('1') and the struct size, so the
        // abi_ok probe above guards the field layout,
        // endianness, and signatures behaviorally on every
        // call before real input runs.
        let mut out = vec![0u8; isize as usize];
        let mut zs = ZStream::zeroed();
        zs.next_in = data.as_ptr().add(pos);
        zs.avail_in = (total - 8 - pos) as u32;
        zs.next_out = out.as_mut_ptr();
        zs.avail_out = isize;
        let versa = b"1.2.0\0";
        let init_rc = (lib.inflate_init)(
            &mut zs,
            -15,
            versa.as_ptr().cast::<libc::c_char>(),
            size_of::<ZStream>() as libc::c_int,
        );
        if init_rc != 0 {
            return fail(&format!("zlib init error {init_rc}"));
        }
        let frc = (lib.inflate)(&mut zs, Z_FINISH);
        let _ = (lib.inflate_end)(&mut zs);
        if frc != Z_STREAM_END {
            return fail(&format!("zlib inflate error {frc}"));
        }
        if zs.total_out != u64::from(isize) {
            return fail("gzip length mismatch");
        }
        let got_crc = (lib.crc32)(0, out.as_ptr(), isize);
        if (got_crc & 0xFFFF_FFFF) as u32 != want_crc {
            return fail("gzip crc mismatch");
        }
        GunzipOut {
            ok: true,
            data: out,
            message: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::gunzip_member;
    use crate::platform::hash::sha256_hex;

    const ZLIB: &str = "libz.so.1";

    /// CPython-gzip blob inflating to 51 bytes (sha c7fae0d6...).
    fn basic_blob() -> Vec<u8> {
        vec![
            31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 115, 246, 247, 115, 243, 116, 143, 15, 14, 119, 12,
            176, 205, 227, 114, 134, 240, 60, 189, 161, 140, 128, 32, 127, 103, 219, 74, 46, 101,
            133, 146, 212, 226, 18, 133, 228, 252, 188, 180, 204, 116, 46, 0, 45, 1, 240, 222, 51,
            0, 0, 0,
        ]
    }

    #[test]
    fn basic_roundtrip() {
        let blob = basic_blob();
        let out = gunzip_member(&blob, ZLIB);
        assert!(out.ok, "unexpected failure: {}", out.message);
        assert_eq!(out.data.len(), 51);
        assert_eq!(
            sha256_hex(&out.data),
            "c7fae0d6bf4358c883803ebea802a2e6\
             b5b7eea48b795daa9ce4e24d4b294748"
        );
    }

    #[test]
    fn empty_member() {
        let blob = vec![
            31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let out = gunzip_member(&blob, ZLIB);
        assert!(out.ok, "unexpected failure: {}", out.message);
        assert_eq!(out.data.len(), 0);
    }

    #[test]
    fn fname_member() {
        let blob = vec![
            31, 139, 8, 8, 116, 250, 196, 106, 2, 255, 99, 111, 110, 102, 105, 103, 0, 115, 246,
            247, 115, 243, 116, 143, 15, 14, 119, 12, 176, 205, 227, 114, 134, 240, 60, 189, 161,
            140, 128, 32, 127, 103, 219, 74, 46, 101, 133, 146, 212, 226, 18, 133, 228, 252, 188,
            180, 204, 116, 46, 0, 45, 1, 240, 222, 51, 0, 0, 0,
        ];
        let out = gunzip_member(&blob, ZLIB);
        assert!(out.ok, "unexpected failure: {}", out.message);
        assert_eq!(out.data.len(), 51);
        assert_eq!(
            sha256_hex(&out.data),
            "c7fae0d6bf4358c883803ebea802a2e6\
             b5b7eea48b795daa9ce4e24d4b294748"
        );
    }

    #[test]
    fn bad_magic() {
        let blob = vec![0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0];
        let out = gunzip_member(&blob, ZLIB);
        assert!(!out.ok);
    }

    #[test]
    fn truncated() {
        let blob = basic_blob();
        let cut = &blob[..blob.len() - 8];
        let out = gunzip_member(cut, ZLIB);
        assert!(!out.ok);
    }

    #[test]
    fn corrupt() {
        let mut blob = basic_blob();
        blob[12] ^= 0xFF;
        let out = gunzip_member(&blob, ZLIB);
        assert!(!out.ok);
    }

    #[test]
    fn huge_isize_refused() {
        let mut blob = basic_blob();
        let n = blob.len();
        blob[n - 4] = 0;
        blob[n - 3] = 0;
        blob[n - 2] = 16;
        blob[n - 1] = 1;
        let out = gunzip_member(&blob, ZLIB);
        assert!(!out.ok);
        assert_eq!(out.message, "gzip output too big");
    }

    #[test]
    fn missing_library_uncheckable() {
        let blob = basic_blob();
        let out = gunzip_member(&blob, "libmemveil-no-such-soname.so.6");
        assert!(!out.ok);
        assert_eq!(out.message, "zlib unavailable");
    }

    #[test]
    fn abi_guard_refuses_fake_zlib() {
        // libc has no zlib symbols, so the ABI probe must refuse it
        // exactly like the Mojo suite's fake-zlib library.
        let blob = basic_blob();
        let out = gunzip_member(&blob, "libc.so.6");
        assert!(!out.ok);
        assert_eq!(out.message, "zlib ABI mismatch");
    }
}
