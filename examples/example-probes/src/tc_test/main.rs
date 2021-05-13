// This program can be executed by
// # cargo run --example tcp-lifetime [interface]
#![no_std]
#![no_main]
use core::marker::PhantomData;
use core::mem;
use redbpf_macros::map;
use redbpf_probes::tc::prelude::*;
use redbpf_probes::tc::{TcAction, TcActionResult};

program!(0xFFFFFFFE, "GPL");

const PIN_GLOBAL_NS: u32 = 2;

#[repr(C)]
struct bpf_elf_map {
    type_: u32,
    size_key: u32,
    size_value: u32,
    max_elem: u32,
    flags: u32,
    id: u32,
    pinning: u32,
}

pub struct TcHashMap<K, V> {
    def: bpf_elf_map,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<K, V> TcHashMap<K, V> {
    /// Creates a map with the specified maximum number of elements.
    pub const fn with_max_entries(max_entries: u32) -> Self {
        Self {
            def: bpf_elf_map {
                type_: 1, // BPF_MAP_TYPE_HASH
                size_key: mem::size_of::<K>() as u32,
                size_value: mem::size_of::<V>() as u32,
                max_elem: max_entries,
                flags: 0,
                id: 0,
                pinning: PIN_GLOBAL_NS,
            },
            _k: PhantomData,
            _v: PhantomData,
        }
    }
    /// Returns a reference to the value corresponding to the key.
    #[inline]
    pub fn get(&mut self, key: &K) -> Option<&V> {
        unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
            );
            if value.is_null() {
                None
            } else {
                Some(&*(value as *const V))
            }
        }
    }

    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        unsafe {
            let value = bpf_map_lookup_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
            );
            if value.is_null() {
                None
            } else {
                Some(&mut *(value as *mut V))
            }
        }
    }

    /// Set the `value` in the map for `key`
    #[inline]
    pub fn set(&mut self, key: &K, value: &V) {
        unsafe {
            bpf_map_update_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
                value as *const _ as *const _,
                BPF_ANY.into(),
            );
        }
    }

    /// Delete the entry indexed by `key`
    #[inline]
    pub fn delete(&mut self, key: &K) {
        unsafe {
            bpf_map_delete_elem(
                &mut self.def as *mut _ as *mut _,
                key as *const _ as *const _,
            );
        }
    }
}

#[map(link_section = "maps")]
static mut blocked_packets: TcHashMap<u64, u64> = TcHashMap::<u64, u64>::with_max_entries(1024);

#[tc_action]
fn test_tc(skb: SkBuff) -> TcActionResult {
    unsafe {
        let key = 0;
        if let Some(mut cnt) = blocked_packets.get_mut(&key) {
            *cnt += 1;
        } else {
            let val = 0;
            blocked_packets.set(&key, &val);
        }
    }
    Ok(TcAction::Ok)
}
