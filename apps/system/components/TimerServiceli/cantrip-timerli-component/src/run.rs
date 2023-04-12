// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Cantrip OS MemoryManager component support.

// Code here binds the camkes component to the rust code.
#![no_std]
#![allow(clippy::missing_safety_doc)]

use cantrip_timerli_interface::Timerinterface;
use cantrip_timerli_interface::*;
use cantrip_os_common::camkes::Camkes;
use cantrip_timerli_manager::Timermanager;
use cantrip_timerli_manager::*;
use core::slice;
use log::info;
use core::ptr;


static mut CAMKES: Camkes = Camkes::new("TimerServiceli");
static mut CANTRIP_TIMERLI: Timermanager = Timermanager::new();

#[no_mangle]
pub unsafe extern "C" fn pre_init() {
    // NB: set to max; the LoggerInterface will filter
    static mut HEAP_MEMORY: [u8; 4 * 1024] = [0; 4 * 1024];
    CAMKES.pre_init(log::LevelFilter::Debug, &mut HEAP_MEMORY);
}

#[no_mangle]
pub unsafe extern "C" fn timerli_readtime() -> u32 {
    CANTRIP_TIMERLI.readtime()
}

