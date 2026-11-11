//! The library's global allocator: the system allocator, but every block is wiped before it
//! is freed (BLOX.md §10.2).
//!
//! Secrets cross the FFI in buffers UniFFI allocates and frees here (the phrase going in, a
//! new phrase coming out), and library code makes heap copies of its own. `Zeroizing` only
//! reaches the values we hold; this reaches every heap copy once it's dropped. Stack copies
//! are handled where they are made (`blox_evm::sign`).

use std::alloc::{GlobalAlloc, Layout, System};

use zeroize::Zeroize;

pub struct WipingAlloc;

// SAFETY: forwards to `System`; `dealloc` only writes inside the block it is handed, which the
// caller still owns until `System.dealloc`.
unsafe impl GlobalAlloc for WipingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            std::slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
            System.dealloc(ptr, layout);
        }
    }

    // `realloc` is not forwarded to `System.realloc`, which may move the block and free the old
    // one unwiped. The default allocates, copies and calls `dealloc` above.
}

#[global_allocator]
static ALLOC: WipingAlloc = WipingAlloc;
