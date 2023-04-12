//! Cantrip OS global timer support

#![cfg_attr(not(test), no_std)]

use core::ptr;
use cantrip_os_common::camkes::Camkes;
use cantrip_timerli_interface::*;


pub struct Timermanager {
    timer: usize,
}

extern "C" {
     static reg:*mut u64;
}

impl Timermanager {
    pub const fn new() -> Timermanager{
        Timermanager{timer: 0,}
    }
}

impl Timerinterface for Timermanager {
    fn readtime(&mut self) -> u32 {
      //  let addr:*const u64 = 0x3F003000 as *const u64;
        let addr:*mut u64 = unsafe{(reg as u64 + 0x4) as *mut u64};
        unsafe { ptr::read_volatile(addr) as u32}
    }
}


