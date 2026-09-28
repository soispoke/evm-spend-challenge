//! Guest runtime: a bump allocator, a single-hart critical section, the
//! 1,680-byte challenge input from advice memory, and a digest output checked
//! against the public input.
#![no_std]

use core::alloc::{GlobalAlloc, Layout};
pub use leanvm_guest::{input, output};

pub const INPUT_BYTES: usize = 1680;

unsafe extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
}

struct Bump;
static mut NEXT: usize = 0;

// The guest executes once, on one hart, without interrupts. Allocations live
// until exit; bounds leave a separate 256 KiB stack region.
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let start = NEXT.max((&raw const __heap_start) as usize);
            let Some(aligned) = start.checked_add(layout.align() - 1) else {
                return core::ptr::null_mut();
            };
            let aligned = aligned & !(layout.align() - 1);
            let Some(end) = aligned.checked_add(layout.size()) else {
                return core::ptr::null_mut();
            };
            if end > (&raw const __heap_end) as usize {
                return core::ptr::null_mut();
            }
            NEXT = end;
            aligned as *mut u8
        }
    }
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

#[global_allocator]
static ALLOCATOR: Bump = Bump;

struct SingleHart;
critical_section::set_impl!(SingleHart);
// No concurrency or interrupts exist in this VM, so these sections need no
// synchronization or privileged interrupt-control instructions.
unsafe impl critical_section::Impl for SingleHart {
    unsafe fn acquire() -> critical_section::RawRestoreState {}
    unsafe fn release(_: critical_section::RawRestoreState) {}
}

/// The challenge input, read from the initialized advice memory.
pub fn challenge_input() -> &'static [u8] {
    let words = leanvm_guest::advice();
    assert!(INPUT_BYTES <= words.len() * 8);
    // RV64 is little endian; the host preserves the byte order.
    unsafe { core::slice::from_raw_parts(words.as_ptr().cast(), INPUT_BYTES) }
}

/// Publish the digest; the program only halts successfully when it equals
/// the public input.
pub fn finish(digest: [u8; 32]) {
    let words = core::array::from_fn(|i| u64::from_le_bytes(digest[8 * i..8 * i + 8].try_into().unwrap()));
    assert_eq!(input(), words);
    output(words);
}
