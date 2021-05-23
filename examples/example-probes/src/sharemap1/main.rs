#![no_std]
#![no_main]

use redbpf_probes::kprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map("sharedmap")]
static mut SHARED_COUNT: Array<i64> = Array::with_max_entries(1);

#[kprobe]
fn vfs_read(_: Registers) {
    unsafe {
        let mut cnt = SHARED_COUNT.get_mut(0).unwrap();
        *cnt += 1;
    }
}
