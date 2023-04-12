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

//! Cantrip OS timer support

#![cfg_attr(not(test), no_std)]
#![allow(dead_code)]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use cantrip_os_common::camkes::Camkes;
use cantrip_os_common::sel4_sys;
use core::fmt;
use log::trace;
use serde::{Deserialize, Serialize};



// ObjDescBundle holds a collection of ObjDesc's and their associated
// Objects are potentially batched with caps to allocated objects returned
// in the container slots specified by the |bundle] objects.
pub trait Timerinterface {
    fn readtime(&mut self) -> u32;
}

// Client wrappers.

// Allocates the objects specified in |request|. The capabilities are stored
// in |request|.cnode which is assumed to be a CNode with sufficient capacity
#[inline]
pub fn cantrip_timer_readtime() -> u32 {
    extern "C" {
        fn timerli_readtime() -> u32;
    }
   unsafe{ timerli_readtime() }
 
 
}

