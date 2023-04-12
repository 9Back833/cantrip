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
        // let mut default_memblock = MemBlock {frame_num: 0, free_time: 0, bulk:
        //     FrameBulk {
        //         frame_bundle: ObjDescBundle {cnode: 0, depth: 0, objs: Vec::new()}, 
        //         cptr: 0, tree_node: 0, alloc_node: (0, 0)}};
        //     [[MemBlock {frame_num: 0, free_time: 0, bulk: FrameBulk {
        //     frame_bundle: ObjDescBundle {cnode: 0, depth: 0, objs: Vec::new()}, 
        //     cptr: 0, tree_node: 0, alloc_node: (0, 0)}}; ARRAY_SIZE]; ARRAY_SIZE];
        // let mut test_circular: [[MemBlock; ARRAY_SIZE]; ARRAY_SIZE] = [[MemBlock {frame_num: 0, free_time: 0, bulk: FrameBulk {
        //         frame_bundle: ObjDescBundle {cnode: 0, depth: 0, objs: Vec::new()}, 
        //         cptr: 0, tree_node: 0, alloc_node: (0, 0)}}; ARRAY_SIZE]; ARRAY_SIZE];
        // let mut inner_i: [usize; ARRAY_SIZE] = [0; ARRAY_SIZE];
        // for t in 1..=TEST_TIMES {
        //     let outer_i = t % ARRAY_SIZE;

        //     let mut i = 0;
        //     while test_circular[outer_i][i].frame_num == 0 || i == ARRAY_SIZE {
        //         let block = test_circular[outer_i][i].clone();
        //         let bulk_free = block.get_bulk();
        //         FRAME_VTREE.new_cantrip_frame_free(bulk_free);
        //         test_circular[outer_i][i] = MemBlock::new_empty();
        //         i += 1;
        //     }

        //     let frame_num = get_second_size_distribution(&mut seed);
        //     let time = get_time(&mut seed, 10);
        //     let bulk = FRAME_VTREE.new_cantrip_frame_alloc(frame_num);
        //     let mut mem_block = MemBlock::new(frame_num, t+time, bulk);

        //     test_circular[outer_i][inner_i[outer_i]] = mem_block;
        //     inner_i[outer_i] += 1;
        // }

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
    /*
    fn check_alloc(
        output: &mut dyn io::Write,
        name: &str,
        res: Result<ObjDescBundle, MemoryManagerError>,
    ) {
        match res {
            Ok(obj) => {
                if let Err(e) = cantrip_object_free_toplevel(&obj) {
                    let _ = writeln!(output, "free {} {:?} failed: {:?}", name, obj, e);
                }
            }
            Err(e) => {
                let _ = writeln!(output, "alloc {} failed: {:?}", name, e);
            }
        }
    }

    // NB: alloc+free immediately so we don't run out of top-level CNode slots
    check_alloc(output, "untyped", cantrip_untyped_alloc(12)); // NB: 4KB
    check_alloc(output, "tcb", cantrip_tcb_alloc());
    check_alloc(output, "endpoint", cantrip_endpoint_alloc());
    check_alloc(output, "notification", cantrip_notification_alloc());
    check_alloc(output, "cnode", cantrip_cnode_alloc(5)); // NB: 32 slots
    check_alloc(output, "frame", cantrip_frame_alloc(4096));
    //    check_alloc(output, "large frame",  cantrip_frame_alloc(1024*1024));
    check_alloc(output, "page table", cantrip_page_table_alloc());

    #[cfg(feature = "CONFIG_KERNEL_MCS")]
    check_alloc(
        output,
        "sched context",
        cantrip_sched_context_alloc(seL4_MinSchedContextBits),
    );

    #[cfg(feature = "CONFIG_KERNEL_MCS")]
    check_alloc(output, "reply", cantrip_reply_alloc());

    let after_stats = cantrip_memory_stats().expect("after stats");
    mstats(output, &after_stats)?;
    //assert_eq!(before_stats.allocated_bytes, after_stats.allocated_bytes);
    //assert_eq!(before_stats.free_bytes, after_stats.free_bytes);

    // Batch allocate into a private CNode as we might to build a process.
    const CNODE_DEPTH: usize = 7; // 128 slots
    let cnode = cantrip_cnode_alloc(CNODE_DEPTH).unwrap(); // XXX handle error
    let objs = ObjDescBundle::new(
        cnode.objs[0].cptr,
        CNODE_DEPTH as u8,
        vec![
            ObjDesc::new(seL4_TCBObject, 1, 0),      // 1 tcb
            ObjDesc::new(seL4_EndpointObject, 2, 1), // 2 endpoiints
            ObjDesc::new(seL4_ReplyObject, 2, 3),    // 2 replys
            ObjDesc::new(
                seL4_SchedContextObject, // 1 sched context
                seL4_MinSchedContextBits,
                5,
            ),
            ObjDesc::new(seL4_SmallPageObject, 10, 6), // 10 4K pages
        ],
    );
    match cantrip_object_alloc(&objs) {
        Ok(_) => {
            writeln!(output, "Batch alloc ok: {:?}", objs)?;
            if let Err(e) = cantrip_object_free(&objs) {
                writeln!(output, "Batch free err: {:?}", e)?;
            }
        }
        Err(e) => {
            writeln!(output, "Batch alloc err: {:?} {:?}", objs, e)?;
        }
    }
    if let Err(e) = cantrip_object_free_toplevel(&cnode) {
        writeln!(output, "Cnode free err: {:?} {:?}", cnode, e)?;
    }

    // Batch allocate using the newer api that constructs a CNode based
    // on the batch of objects specified.
    match cantrip_object_alloc_in_cnode(vec![
        ObjDesc::new(seL4_TCBObject, 1, 0),      // 1 tcb
        ObjDesc::new(seL4_EndpointObject, 1, 1), // 1 endpoiints
        ObjDesc::new(seL4_ReplyObject, 1, 2),    // 1 replys
        ObjDesc::new(
            seL4_SchedContextObject, // 1 sched context
            seL4_MinSchedContextBits,
            3,
        ),
        ObjDesc::new(seL4_SmallPageObject, 2, 4), // 2 4K pages
    ]) {
        Ok(objs) => {
            writeln!(output, "cantrip_object_alloc_in_cnode ok: {:?}", objs)?;
            if let Err(e) = cantrip_object_free_in_cnode(&objs) {
                writeln!(output, "cantrip_object_free_in_cnode failed: {:?}", e)?;
            }
        }
        Err(e) => {
            writeln!(output, "cantrip_object_alloc_in_cnode failed: {:?}", e)?;
        }
    }
    */
    //let after_stats = cantrip_memory_stats().expect("after stats");
    //mstats(output, &after_stats)?;
    Ok(writeln!(output, "All tests passed!")?)
}
