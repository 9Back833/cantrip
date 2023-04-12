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

    //let before_stats = cantrip_memory_stats().expect("before stats");
    //mstats(output, &before_stats)?;
    unsafe {
        const ARRAY_SIZE: usize = 10;
        const TEST_TIMES: usize = 2000;
        //let a:u32 = cantrip_timer_readtime();
        let mut seed = rand_pcg::Pcg32::new(0xcafef00dd15ea5e5, 0xa02bdbf7bb3c0a7);

        // let frame_num_arr = [10, 12, 14, 16, 18, 20, 30, 40, 50, 60, 70, 80, 90,
        //                  100, 150, 200, 250, 500, 1000];
        let mut mem_block_vec: Vec<MemBlock> = Vec::new();
        // let mut total_frame_num = 0;
        for i in 1..=12000 {
            let frame_num = 1;
            //total_frame_num += frame_num;
            //info!("total:{}",total_frame_num)
            let time = get_time(&mut seed, 100);
            let bulk = FRAME_VTREE.new_cantrip_frame_alloc(frame_num);
            let mem_block = MemBlock::new(frame_num, i+time, bulk);
            // let bulk1 = mem_block.get_bulk();
            // info!("alloc_block:{:?}",mem_block);
            mem_block_vec.push(mem_block);
            mem_block_vec.sort_by(|a, b| b.free_time.cmp(&a.free_time));
            loop {
                match mem_block_vec.last() {
                    Some(fxxk) => {
                        if fxxk.free_time <= i {
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
    };
        /*
        //let a:u32 = cantrip_timer_readtime();
        for _ in 0..1 {
            let frame_bulk0 = FRAME_VTREE.new_cantrip_frame_alloc(1);
            info!("frame_bundle:{:?}",frame_bulk0.frame_bundle);
            let frame_bulk1 = FRAME_VTREE.new_cantrip_frame_alloc(2);
            info!("frame_bundle:{:?}",frame_bulk1.frame_bundle);
            FRAME_VTREE.new_cantrip_frame_free(frame_bulk0);
            let frame_bulk2 = FRAME_VTREE.new_cantrip_frame_alloc(1);
            info!("frame_bundle:{:?}",frame_bulk2.frame_bundle);
            //let b:u32 = cantrip_timer_readtime();
        }
        //let b:u32 = cantrip_timer_readtime();
        //info!("toatl_time:{}",b-a);
    }
        */
    Ok(writeln!(output, "All tests passed!")?)
}
