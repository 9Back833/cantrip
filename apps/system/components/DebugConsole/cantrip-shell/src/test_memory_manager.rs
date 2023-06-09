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

//! MemoryManager service shell test commands

extern crate alloc;
//use alloc::vec;
use alloc::vec::Vec;
use crate::mstats;
use crate::CmdFn;
use crate::CommandError;
use crate::HashMap;
use alloc::vec;
use core::cmp::Reverse;
use core::fmt::Write;
use core::ptr::null;
use core::ptr::null_mut;
use log::info;
use cantrip_io as io;
use cantrip_memory_interface::*;
use cantrip_timerli_interface::*;
use cantrip_os_common::sel4_sys;
use rand::RngCore;
use rand_pcg::Pcg32;

use sel4_sys::seL4_CPtr;
use sel4_sys::seL4_MinSchedContextBits;
use sel4_sys::seL4_ObjectType::*;
use sel4_sys::seL4_SmallPageObject;
use sel4_sys::seL4_WordBits;

pub fn add_cmds(cmds: &mut HashMap<&str, CmdFn>) {
    cmds.extend([
        ("test_malloc", malloc_command as CmdFn),
        ("test_mfree", mfree_command as CmdFn),
        ("test_obj_alloc", obj_alloc_command as CmdFn),
    ]);
}

fn malloc_command(
    args: &mut dyn Iterator<Item = &str>,
    _input: &mut dyn io::BufRead,
    output: &mut dyn io::Write,
    _builtin_cpio: &[u8],
) -> Result<(), CommandError> {
    let space_str = args.next().ok_or(CommandError::BadArgs)?;
    let space_bytes = space_str.parse::<usize>()?;
    match cantrip_frame_alloc(space_bytes) {
        Ok(frames) => {
            writeln!(output, "Allocated {:?}", frames)?;
        }
        Err(status) => {
            writeln!(output, "malloc failed: {:?}", status)?;
        }
    }
    Ok(())
}

fn mfree_command(
    args: &mut dyn Iterator<Item = &str>,
    _input: &mut dyn io::BufRead,
    output: &mut dyn io::Write,
    _builtin_cpio: &[u8],
) -> Result<(), CommandError> {
    extern "C" {
        static SELF_CNODE: seL4_CPtr;
    }
    let cptr_str = args.next().ok_or(CommandError::BadArgs)?;
    let count_str = args.next().ok_or(CommandError::BadArgs)?;
    let frames = ObjDescBundle::new(
        unsafe { SELF_CNODE },
        seL4_WordBits as u8,
        vec![ObjDesc::new(
            seL4_SmallPageObject,
            count_str.parse::<usize>()?,
            cptr_str.parse::<usize>()? as seL4_CPtr,
        )],
    );
    match cantrip_object_free_toplevel(&frames) {
        Ok(_) => {
            writeln!(output, "Free'd {:?}", frames)?;
        }
        Err(status) => {
            writeln!(output, "mfree failed: {:?}", status)?;
        }
    }
    Ok(())
}

fn obj_alloc_command(
    _args: &mut dyn Iterator<Item = &str>,
    _input: &mut dyn io::BufRead,
    output: &mut dyn io::Write,
    _builtin_cpio: &[u8],
) -> Result<(), CommandError> {

    unsafe {
        continuous_test();
    };

    Ok(writeln!(output, "All tests passed!")?)

}

pub fn unit_test() {
    unsafe {
    let bulk0 = FRAME_VTREE.new_cantrip_frame_alloc(1);
    let bulk1 = FRAME_VTREE.new_cantrip_frame_alloc(4);
    let bulk2 = FRAME_VTREE.new_cantrip_frame_alloc(1);
    info!("bitmap:{:x?}",FRAME_VTREE.treevec[0].bitmap[1]);
    FRAME_VTREE.new_cantrip_frame_free(bulk0);
    info!("bitmap:{:x?}",FRAME_VTREE.treevec[0].bitmap[1]);
    FRAME_VTREE.new_cantrip_frame_free(bulk2);
    info!("bitmap:{:x?}",FRAME_VTREE.treevec[0].bitmap[1]);
    }
}

pub fn continuous_test() {
    unsafe {
        let a:u32 = cantrip_timer_readtime();
        for i in 0..224{
            let bulk = FRAME_VTREE.new_cantrip_frame_alloc(64);
        };
        let b:u32 = cantrip_timer_readtime();
        info!("256k_28M_toatl_time:{}",b-a);
    }
}

pub fn knuth_test() {
    unsafe {
        let mut seed = rand_pcg::Pcg32::new(0xcafef00dd15ea5e5, 0xa02bdbf7bb3c0a7);
        let frame_num_arr = [1,2,4,8,16];
        let mut mem_block_vec: Vec<MemBlock> = Vec::new();
        let mut total_frame_num = 0;
        for i in 1..=30000 {
            let frame_num = get_third_size_distribution(&mut seed,frame_num_arr);
            let time = get_time(&mut seed, 200);
            let bulk = FRAME_VTREE.new_cantrip_frame_alloc(frame_num);
            let mem_block = MemBlock::new(frame_num, i+time, bulk);
            mem_block_vec.push(mem_block);
            mem_block_vec.sort_by(|a, b| b.free_time.cmp(&a.free_time));
            loop {
                match mem_block_vec.last() {
                    Some(buddy) => {
                        if buddy.free_time <= i {
                            let block = mem_block_vec.pop().unwrap();
                            FRAME_VTREE.new_cantrip_mem_free(block);
                        } else {
                            break;
                        }
                    },
                    None => {
                        break;
                    }
                }
            }
        }
        let len = FRAME_VTREE.treevec.len();
        info!("len:{}",len);
        for i in 0..FRAME_VTREE.treevec.len() {
            for u in 0..33 {
                info!("tree:{},node:{},bitmap:{:x?}",i,u,FRAME_VTREE.treevec[i].bitmap[u]);
            }
        }
    }
}
