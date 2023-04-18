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

//! Cantrip OS memory management support

#![cfg_attr(not(test), no_std)]
#![allow(dead_code)]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use cantrip_os_common::camkes::Camkes;
use cantrip_os_common::sel4_sys;
use cantrip_os_common::slot_allocator;
use core::fmt;
use log::trace;
use serde::{Deserialize, Serialize};
use log::info;
use rand::RngCore;
use rand_pcg::Pcg32;

use sel4_sys::seL4_CNode_Move;
use sel4_sys::seL4_CPtr;
use sel4_sys::seL4_Error;
use sel4_sys::seL4_ObjectType;
use sel4_sys::seL4_ObjectType::*;
use sel4_sys::seL4_PageBits;
use sel4_sys::seL4_PageTableObject;
use sel4_sys::seL4_Result;
use sel4_sys::seL4_SmallPageObject;
use sel4_sys::seL4_WordBits;

use slot_allocator::CANTRIP_CSPACE_SLOTS;

use core::num::Wrapping;
use core::mem::size_of;

// new code
const MIN_MEMORY_SIZE: usize = 4 * 1024;
const MAX_MEMORY_SIZE: usize = 4 * 1024 * 1024;
const MIDDLE_MEMORY_SIZE: usize = 128 * 1024;
const MAX_VTREE_LEVEL: usize = 10;
const MID_VTREE_LEVEL: usize = 5;


// NB: @14b per desc this supports ~150 descriptors (depending
//   on serde overhead), the rpc buffer is actually 4K so we could
//   raise this
pub const RAW_OBJ_DESC_DATA_SIZE: usize = 2048;
pub type RawObjDescData = [u8; RAW_OBJ_DESC_DATA_SIZE];

extern "C" {
    // Each CAmkES-generated CNode has a writable self-reference to itself in
    // the slot SELF_CNODE to enable dynamic management of capabilities.
    static SELF_CNODE: seL4_CPtr;

    // Each CAmkES-component has a CNode setup at a well-known slot. In lieu
    // of any supplied CNode we can use that container to pass capabilities.
    static MEMORY_RECV_CNODE: seL4_CPtr;
    static MEMORY_RECV_CNODE_DEPTH: u8;

}

// The MemoryManager takes collections of Object Descriptors.
//
// For an alloc request an object descriptor provides everything needed
// to allocate & retype untyped memory. Capabilities for the realized
// objects are attached to the IPC buffer holding the reply in a CNode
// container. For free requests the same object descriptors should be
// provided. Otherwise clients are responsible for filling in
// allocated objects; e.g. map page frames into a VSpace, bind endpoints
// to irq's, configure TCB slots, etc.
//
// TODO(sleffler): support setting fixed physical address for drivers
// TODO(sleffler): maybe allocate associated resources like endpoint #'s?
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct ObjDesc {
    // Requested object type or type of object being released.
    pub type_: seL4_ObjectType,

    // Count of consecutive objects with the same type or, for CNode
    // objects the log2 number of slots to use in sizing the object,
    // or for untyped objects the log2 size in bytes, or for scheduler
    // context objects the size in bits. See seL4_ObjectType::size_bits().
    count: usize, // XXX oversized (except for untyped use)

    // CSpace address for realized objects requested. If |count| is >1
    // this descriptor describes objects with |cptr|'s [0..|count|).
    // Since each block of objects has it's own |cptr| one can describe
    // a collection with random layout in CSpace (useful for construction).
    //
    // Object capabilities returned by the MemoryManager have the maximal
    // rights. We depend on trusted agents (e.g. ProcessManager) to reduce
    // rights when assigning them to an application. This also applies to
    // the vm attributes of page frames (e.g. mark not executable as
    // appropriate).
    pub cptr: seL4_CPtr,
}
impl ObjDesc {
    pub fn new(type_: seL4_ObjectType, count: usize, cptr: seL4_CPtr) -> Self {
        ObjDesc { type_, count, cptr }
    }

    // Returns a new ObjDesc with count of 1 and the cptr offset by |index|.
    pub fn new_at(&self, index: usize) -> ObjDesc {
        assert!(index < self.retype_count());
        ObjDesc::new(self.type_, 1, self.cptr + index)
    }

    // Parameters for seL4_Untyped_Retype call.
    pub fn retype_size_bits(&self) -> Option<usize> {
        match self.type_ {
            seL4_UntypedObject  // Log2 memory size
            | seL4_CapTableObject // Log2 number of slots
            | seL4_SchedContextObject => Some(self.count), // Log2 context size
            _ => self.type_.size_bits(),
        }
    }
    pub fn retype_count(&self) -> usize {
        match self.type_ {
            // NB: we don't support creating multiple instances of the same
            //   size; the caller must supply multiple object descriptors.
            seL4_UntypedObject | seL4_CapTableObject | seL4_SchedContextObject => 1,
            _ => self.count,
        }
    }

    // Memory occupied by objects. Used mainly for bookkeeping and statistics.
    pub fn size_bytes(&self) -> Option<usize> {
        match self.type_ {
            seL4_UntypedObject | seL4_SchedContextObject => Some(1 << self.count),
            seL4_CapTableObject => self.type_.size_bits().map(|x| (1 << (x + self.count))),
            _ => self.type_.size_bits().map(|x| self.count * (1 << x)),
        }
    }

    // Checks if two descriptors can be combined. This is used to optimize
    // dynamically constructed ObjDescBundle's (e.g. rz::Upload)
    pub fn can_combine(&self, other: &ObjDesc) -> bool {
        self.type_ == other.type_ && self.cptr + self.count == other.cptr
    }
}

// ObjDescBundle holds a collection of ObjDesc's and their associated
// container (i.e. CNode). This enables full "path addressing" of the
// objects. Helper methods do move/copy operations between a component's
// top-level CNode and dynamically allocated CNodes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjDescBundle {
    pub cnode: seL4_CPtr,
    pub depth: u8,
    pub objs: Vec<ObjDesc>,
}
impl ObjDescBundle {
    pub fn new(cnode: seL4_CPtr, depth: u8, objs: Vec<ObjDesc>) -> Self {
        // TODO(sleffler): assert the largest cptr fits in the container
        ObjDescBundle { cnode, depth, objs }
    }

    // Returns whether there are any object descriptors.
    pub fn is_empty(&self) -> bool { self.objs.len() == 0 }

    // Returns the number of object descriptors.
    pub fn len(&self) -> usize { self.objs.len() }

    // Returns the count of objects specified by the object descriptors.
    pub fn count(&self) -> usize {
        self.objs
            .as_slice()
            .iter()
            .map(|od| od.retype_count())
            .sum()
    }

    // Returns the total bytes specified by the object descriptors.
    pub fn size_bytes(&self) -> usize {
        self.objs
            .as_slice()
            .iter()
            .map(|od| od.size_bytes().unwrap())
            .sum()
    }

    // Returns the log2 size that holds all the objects. This is typically
    // used to size CNode's based on their intended contents. NB: we return
    // values > 0 since the kernel rejects a CapTable object with size_bits=0.
    pub fn count_log2(&self) -> usize {
        // NB: BITS & leading_zeros return u32
        (1 + usize::BITS - usize::leading_zeros(self.count())) as usize
    }

    pub fn maybe_combine_last(&mut self) -> bool {
        let len = self.len();
        if len > 1 && self.objs[len - 2].can_combine(&self.objs[len - 1]) {
            self.objs[len - 2].count += self.objs[len - 1].count;
            self.objs.pop();
            true
        } else {
            false
        }
    }

    // Returns an iterator that enumerates each object's seL4_CPtr.
    pub fn cptr_iter(&self) -> impl Iterator<Item = seL4_CPtr> + '_ {
        self.objs
            .iter()
            .flat_map(|od| od.cptr..(od.cptr + od.retype_count()))
    }

    // Move objects to dynamically-allocated slots in the top-level
    // CNode and mutate the Object Descriptor with the new cptr's.
    // NB: there is no attempt to preserve the order of cptr's (and
    // in practice they are linearized).
    // TODO(sleffler) make generic (requires supplying slot allocator)?
    pub fn move_objects_to_toplevel(&mut self) -> seL4_Result {
        let dest_cnode = unsafe { SELF_CNODE };
        let dest_depth = seL4_WordBits as u8;
        for od in &mut self.objs {
            let dest_slot = unsafe { CANTRIP_CSPACE_SLOTS.alloc(od.retype_count()) }
                .ok_or(seL4_Error::seL4_NotEnoughMemory)?; // XXX seL4_Result not a good fit
            for offset in 0..od.retype_count() {
                unsafe {
                    // TODO(sleffler): cleanup on error?
                    seL4_CNode_Move(
                        /*desT_root=*/ dest_cnode,
                        /*dest_index=*/ dest_slot + offset,
                        /*dest_depth=*/ dest_depth,
                        /*src_root=*/ self.cnode,
                        /*src_index=*/ od.cptr + offset,
                        /*src_depth=*/ self.depth,
                    )?;
                }
            }
            od.cptr = dest_slot;
        }
        self.cnode = dest_cnode;
        self.depth = dest_depth;
        Ok(())
    }

    // Move objects from the top-level CSpace to |dest_cnode| and
    // release the top-level slots. The Object Descriptor are mutated
    // with adjusted cptr's.
    // TODO(sleffler): this does not preserve the order of the cptr's;
    //   doing so is easy but not very useful when move_object_to_toplevvel
    //   does not
    pub fn move_objects_from_toplevel(
        &mut self,
        dest_cnode: seL4_CPtr,
        dest_depth: u8,
    ) -> seL4_Result {
        let mut dest_slot = 0; // NB: assume empty container
        for od in &mut self.objs {
            let count = od.retype_count();
            for offset in 0..count {
                // XXX cleanup on error?
                unsafe {
                    seL4_CNode_Move(
                        /*dest_root=*/ dest_cnode,
                        /*dest_index=*/ dest_slot + offset,
                        /*dest_depth=*/ dest_depth,
                        /*src_root=*/ self.cnode,
                        /*src_index=*/ od.cptr + offset,
                        /*src_depth=*/ self.depth,
                    )
                }?;
            }
            unsafe { CANTRIP_CSPACE_SLOTS.free(od.cptr, count) };
            od.cptr = dest_slot;
            dest_slot += count;
        }
        self.cnode = dest_cnode;
        self.depth = dest_depth;
        Ok(())
    }

    //new code
    pub fn move_frame_to_framecnode(
        &mut self,
        dest_cnode: seL4_CPtr,
        dest_depth: u8,
        dest_slot:usize,
    ) -> seL4_Result {
        let mut dest_slot = dest_slot; // NB: assume empty container
        for od in &mut self.objs {
            let count = od.retype_count();
            for offset in 0..count {
                unsafe {
                    seL4_CNode_Move(
                        /*dest_root=*/ dest_cnode,
                        /*dest_index=*/ dest_slot + offset,
                        /*dest_depth=*/ dest_depth,
                        /*src_root=*/ self.cnode,
                        /*src_index=*/ od.cptr + offset,
                        /*src_depth=*/ self.depth,
                    )
                }?;
            }
            unsafe { CANTRIP_CSPACE_SLOTS.free(od.cptr, count) };
            od.cptr = dest_slot;
            dest_slot += count;
        }
        self.cnode = dest_cnode;
        self.depth = dest_depth;
        Ok(())
    }
}
impl fmt::Display for ObjDescBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.cnode == unsafe { SELF_CNODE } {
            assert_eq!(self.depth as usize, seL4_WordBits);
            write!(f, "{{ SELF,  {:?} }}", &self.objs)
        } else if self.cnode == unsafe { MEMORY_RECV_CNODE } {
            assert_eq!(self.depth, unsafe { MEMORY_RECV_CNODE_DEPTH });
            write!(f, "{{ MEMORY_RECV, {:?} }}", &self.objs)
        } else {
            write!(
                f,
                "{{ cnode: {}, depth: {}, {:?} }}",
                self.cnode, self.depth, &self.objs
            )
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum MemoryError {
    ObjCountInvalid = 0, // Too many objects requested
    ObjTypeInvalid,      // Request with invalid object type
    ObjCapInvalid,       // Request with invalid cptr XXX
    CapAllocFailed,
    UnknownMemoryError,
    // Generic errors.
    AllocFailed,
    FreeFailed,
}

pub const RAW_MEMORY_STATS_DATA_SIZE: usize = 100;
pub type RawMemoryStatsData = [u8; RAW_MEMORY_STATS_DATA_SIZE];

#[repr(C)]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MemoryManagerStats {
    // Current space committed to allocations.
    pub allocated_bytes: usize,

    // Current space available.
    pub free_bytes: usize,

    // Total space for user requests (independent of any alignment).
    pub total_requested_bytes: usize,

    // Space required for operation of the MemoryManager service.
    pub overhead_bytes: usize,

    // Current number of seL4 objects allocated.
    pub allocated_objs: usize,

    // Total number of seL4 objects allocated.
    pub total_requested_objs: usize,

    // Retype requests failed due to insufficient available memory.
    pub untyped_slab_too_small: usize,

    // Alloc requests failed due to lack of untyped memory.
    pub out_of_memory: usize,

    pub current_memory_size: usize,

    pub frame_base_slot: usize,

    pub recv_frame_base_slot: usize,
}

// Objects are potentially batched with caps to allocated objects returned
// in the container slots specified by the |bundle] objects.
pub trait MemoryManagerInterface {
    fn alloc(&mut self, bundle: &ObjDescBundle) -> Result<(), MemoryError>;
    fn free(&mut self, bundle: &ObjDescBundle) -> Result<(), MemoryError>;
    fn stats(&self) -> Result<MemoryManagerStats, MemoryError>;
    fn debug(&self) -> Result<(), MemoryError>;
}

// Public version of MemoryError presented over rpc interface.
// This is needed because the enum is exported to C users and needs to
// be unique from other enum's.
// TODO(sleffler): switch to single generic error space ala absl::StatusCode
#[repr(C)]
#[derive(Debug, Eq, PartialEq)]
pub enum MemoryManagerError {
    MmeSuccess = 0,
    MmeObjCountInvalid,
    MmeObjTypeInvalid,
    MmeObjCapInvalid,
    MmeCapAllocFailed,
    MmeSerializeFailed,
    MmeDeserializeFailed,
    MmeUnknownError,
    // Generic errors.
    MmeAllocFailed,
    MmeFreeFailed,
}
impl From<MemoryError> for MemoryManagerError {
    fn from(err: MemoryError) -> MemoryManagerError {
        match err {
            MemoryError::ObjCountInvalid => MemoryManagerError::MmeObjCountInvalid,
            MemoryError::ObjTypeInvalid => MemoryManagerError::MmeObjTypeInvalid,
            MemoryError::ObjCapInvalid => MemoryManagerError::MmeObjCapInvalid,
            MemoryError::CapAllocFailed => MemoryManagerError::MmeCapAllocFailed,
            MemoryError::AllocFailed => MemoryManagerError::MmeAllocFailed,
            MemoryError::FreeFailed => MemoryManagerError::MmeFreeFailed,
            _ => MemoryManagerError::MmeUnknownError,
        }
    }
}
impl From<Result<(), MemoryError>> for MemoryManagerError {
    fn from(result: Result<(), MemoryError>) -> MemoryManagerError {
        result.map_or_else(MemoryManagerError::from, |_v| MemoryManagerError::MmeSuccess)
    }
}
impl From<MemoryManagerError> for Result<(), MemoryManagerError> {
    fn from(err: MemoryManagerError) -> Result<(), MemoryManagerError> {
        if err == MemoryManagerError::MmeSuccess {
            Ok(())
        } else {
            Err(err)
        }
    }
}

// Client wrappers.

// Allocates the objects specified in |request|. The capabilities are stored
// in |request|.cnode which is assumed to be a CNode with sufficient capacity
#[inline]
pub fn cantrip_object_alloc(request: &ObjDescBundle) -> Result<(), MemoryManagerError> {
    extern "C" {
        // NB: this assumes the MemoryManager component is named "memory".
        fn memory_alloc(c_request_len: u32, c_request_data: *const u8) -> MemoryManagerError;
    }
    trace!("cantrip_object_alloc {}", request);
    let raw_data = &mut [0u8; RAW_OBJ_DESC_DATA_SIZE];
    postcard::to_slice(&request, &mut raw_data[..])
        .map_err(|_| MemoryManagerError::MmeSerializeFailed)?;
    unsafe {
        // Attach our CNode for returning objects; the CAmkES template
        // forces extraCaps=1 when constructing the MessageInfo struct
        // used by the seL4_Call inside memory_alloc.
        // NB: scrubbing the IPC buffer is done on drop of |cleanup|
        sel4_sys::debug_assert_slot_cnode!(request.cnode);
        let _cleanup = Camkes::set_request_cap(request.cnode);

        memory_alloc(raw_data.len() as u32, raw_data.as_ptr()).into()
    }
}

// Allocates the objects specified in |objs|. The capabilities are moved
// to SELF_CNODE which must have sufficient space.
#[inline]
pub fn cantrip_object_alloc_in_toplevel(
    objs: Vec<ObjDesc>,
) -> Result<ObjDescBundle, MemoryManagerError> {
    // Request the objects using the dedicated MemoryManager container.
    let mut request =
        ObjDescBundle::new(unsafe { MEMORY_RECV_CNODE }, unsafe { MEMORY_RECV_CNODE_DEPTH }, objs);
    cantrip_object_alloc(&request)?;
    match request.move_objects_to_toplevel() {
        Err(_) => {
            cantrip_object_free(&request).expect("cantrip_object_alloc_in_toplevel");
            Err(MemoryManagerError::MmeObjCapInvalid) // TODO(sleffler): e.into
        }
        Ok(_) => Ok(request),
    }
}

// Allocates the objects specified in |objs|. The capabilities are stored
// in a new CNode allocated with sufficient capacity.
// Note the objects' cptr's are assumed to be consecutive and start at zero.
// Note the returned |ObjDescBundle| has the new CNode marked as the container.
#[inline]
pub fn cantrip_object_alloc_in_cnode(
    objs: Vec<ObjDesc>,
) -> Result<ObjDescBundle, MemoryManagerError> {
    fn next_log2(value: usize) -> usize {
        // NB: BITS & leading_zeros return u32
        (1 + usize::BITS - usize::leading_zeros(value)) as usize
    }
    // NB: CNode size depends on how many objects are requested.
    let cnode_depth = next_log2(objs.iter().map(|od| od.count).sum());

    // Request a top-level CNode.
    let cnode = cantrip_cnode_alloc(cnode_depth)?;

    // Now construct the request for |objs| with |cnode| as the container.
    let request = ObjDescBundle::new(cnode.objs[0].cptr, cnode_depth as u8, objs);
    match cantrip_object_alloc(&request) {
        Err(e) => {
            cantrip_object_free_toplevel(&cnode).expect("cnode free");
            Err(e)
        }
        Ok(_) => Ok(request),
    }
}

// TODO(sleffler): remove unused convience wrappers?

#[inline]
pub fn cantrip_untyped_alloc(space_bytes: usize) -> Result<ObjDescBundle, MemoryManagerError> {
    let mut objs = ObjDescBundle::new(
        unsafe { MEMORY_RECV_CNODE },
        unsafe { MEMORY_RECV_CNODE_DEPTH },
        vec![ObjDesc::new(
            seL4_UntypedObject,
            space_bytes,
            /*cptr=*/ 0,
        )],
    );
    cantrip_object_alloc(&objs)?;
    objs.move_objects_to_toplevel()
        .map_err(|_| MemoryManagerError::MmeObjCapInvalid)?;
    Ok(objs)
}

#[inline]
pub fn cantrip_tcb_alloc() -> Result<ObjDescBundle, MemoryManagerError> {
    let mut objs = ObjDescBundle::new(
        unsafe { MEMORY_RECV_CNODE },
        unsafe { MEMORY_RECV_CNODE_DEPTH },
        vec![ObjDesc::new(seL4_TCBObject, 1, /*cptr=*/ 0)],
    );
    cantrip_object_alloc(&objs)?;
    objs.move_objects_to_toplevel()
        .map_err(|_| MemoryManagerError::MmeObjCapInvalid)?;
    Ok(objs)
}

#[inline]
pub fn cantrip_endpoint_alloc() -> Result<ObjDescBundle, MemoryManagerError> {
    let mut objs = ObjDescBundle::new(
        unsafe { MEMORY_RECV_CNODE },
        unsafe { MEMORY_RECV_CNODE_DEPTH },
        vec![ObjDesc::new(seL4_EndpointObject, 1, /*cptr=*/ 0)],
    );
    cantrip_object_alloc(&objs)?;
    objs.move_objects_to_toplevel()
        .map_err(|_| MemoryManagerError::MmeObjCapInvalid)?;
    Ok(objs)
}

#[inline]
pub fn cantrip_notification_alloc() -> Result<ObjDescBundle, MemoryManagerError> {
    let mut objs = ObjDescBundle::new(
        unsafe { MEMORY_RECV_CNODE },
        unsafe { MEMORY_RECV_CNODE_DEPTH },
        vec![ObjDesc::new(seL4_NotificationObject, 1, /*cptr=*/ 0)],
    );
    cantrip_object_alloc(&objs)?;
    objs.move_objects_to_toplevel()
        .map_err(|_| MemoryManagerError::MmeObjCapInvalid)?;
    Ok(objs)
}

#[inline]
// |size_bits| is the log2 of the #slots to allocate.
pub fn cantrip_cnode_alloc(size_bits: usize) -> Result<ObjDescBundle, MemoryManagerError> {
    let mut objs = ObjDescBundle::new(
        unsafe { MEMORY_RECV_CNODE },
        unsafe { MEMORY_RECV_CNODE_DEPTH },
        vec![ObjDesc::new(
            seL4_CapTableObject,
            size_bits,
            /*cptr=*/ 0,
        )],
    );
    cantrip_object_alloc(&objs)?;
    objs.move_objects_to_toplevel()
        .map_err(|_| MemoryManagerError::MmeObjCapInvalid)?;
    Ok(objs)
}

#[cfg(feature = "CONFIG_KERNEL_MCS")]
#[inline]
pub fn cantrip_sched_context_alloc(size_bits: usize) -> Result<ObjDescBundle, MemoryManagerError> {
    let mut objs = ObjDescBundle::new(
        unsafe { MEMORY_RECV_CNODE },
        unsafe { MEMORY_RECV_CNODE_DEPTH },
        vec![ObjDesc::new(
            seL4_SchedContextObject,
            size_bits,
            /*cptr=*/ 0,
        )],
    );
    cantrip_object_alloc(&objs)?;
    objs.move_objects_to_toplevel()
        .map_err(|_| MemoryManagerError::MmeObjCapInvalid)?;
    Ok(objs)
}

#[cfg(feature = "CONFIG_KERNEL_MCS")]
#[inline]
pub fn cantrip_reply_alloc() -> Result<ObjDescBundle, MemoryManagerError> {
    let mut objs = ObjDescBundle::new(
        unsafe { MEMORY_RECV_CNODE },
        unsafe { MEMORY_RECV_CNODE_DEPTH },
        vec![ObjDesc::new(seL4_ReplyObject, 1, /*cptr=*/ 0)],
    );
    cantrip_object_alloc(&objs)?;
    objs.move_objects_to_toplevel()
        .map_err(|_| MemoryManagerError::MmeObjCapInvalid)?;
    Ok(objs)
}

// Wrapper for allocating small pages.
#[inline]
pub fn cantrip_frame_alloc(space_bytes: usize) -> Result<ObjDescBundle, MemoryManagerError> {
    fn howmany(value: usize, unit: usize) -> usize { (value + (unit - 1)) / unit }
    // NB: always allocate small pages
    let mut objs = ObjDescBundle::new(
        unsafe { MEMORY_RECV_CNODE },
        unsafe { MEMORY_RECV_CNODE_DEPTH },
        // NB: always allocate 4K pages
        vec![ObjDesc::new(
            seL4_SmallPageObject,
            howmany(space_bytes, 1 << seL4_PageBits),
            /*cptr=*/ 0,
        )],
    );
    cantrip_object_alloc(&objs)?;
    objs.move_objects_to_toplevel()
        .map_err(|_| MemoryManagerError::MmeObjCapInvalid)?;
    Ok(objs)
}

// Like cantrip_frame_alloc but also create a CNode to hold the frames.
#[inline]
pub fn cantrip_frame_alloc_in_cnode(
    space_bytes: usize,
) -> Result<ObjDescBundle, MemoryManagerError> {
    fn howmany(value: usize, unit: usize) -> usize { (value + (unit - 1)) / unit }
    // NB: always allocate small pages
    let npages = howmany(space_bytes, 1 << seL4_PageBits);
    // XXX horrible band-aid to workaround Retype "fanout" limit of 256
    // objects: split our request accordingly. This shold be handled in
    // MemoryManager using the kernel config or bump the kernel limit.
    assert!(npages <= 512); // XXX 2MB
    if npages > 256 {
        cantrip_object_alloc_in_cnode(vec![
            ObjDesc::new(seL4_SmallPageObject, 256, /*cptr=*/ 0),
            ObjDesc::new(seL4_SmallPageObject, npages - 256, /*cptr=*/ 256),
        ])
    } else {
        cantrip_object_alloc_in_cnode(vec![ObjDesc::new(
            seL4_SmallPageObject,
            npages,
            /*cptr=*/ 0,
        )])
    }
}

#[inline]
pub fn cantrip_page_table_alloc() -> Result<ObjDescBundle, MemoryManagerError> {
    let mut objs = ObjDescBundle::new(
        unsafe { MEMORY_RECV_CNODE },
        unsafe { MEMORY_RECV_CNODE_DEPTH },
        vec![ObjDesc::new(seL4_PageTableObject, 1, /*cptr=*/ 0)],
    );
    cantrip_object_alloc(&objs)?;
    objs.move_objects_to_toplevel()
        .map_err(|_| MemoryManagerError::MmeObjCapInvalid)?;
    Ok(objs)
}

#[inline]
pub fn cantrip_object_free(request: &ObjDescBundle) -> Result<(), MemoryManagerError> {
    extern "C" {
        // NB: this assumes the MemoryManager component is named "memory".
        fn memory_free(c_data_len: u32, c_data: *const u8) -> MemoryManagerError;
    }
    trace!("cantrip_object_free {}", request);
    let raw_data = &mut [0u8; RAW_OBJ_DESC_DATA_SIZE];
    postcard::to_slice(request, &mut raw_data[..])
        .map_err(|_| MemoryManagerError::MmeSerializeFailed)?;
    unsafe {
        // Attach our CNode for returning objects; the CAmkES template
        // forces extraCaps=1 when constructing the MessageInfo struct
        // used in the seL4_Call.
        // NB: scrubbing the IPC buffer is done on drop of |cleanup|
        sel4_sys::debug_assert_slot_cnode!(request.cnode);
        let _cleanup = Camkes::set_request_cap(request.cnode);

        memory_free(raw_data.len() as u32, raw_data.as_ptr()).into()
    }
}

// Free |request| and then the container that holds them. The container
// is expected to be in the top-level CNode (as returned by
// cantrip_object_alloc_in_cnode).
#[inline]
pub fn cantrip_object_free_in_cnode(request: &ObjDescBundle) -> Result<(), MemoryManagerError> {
    let cnode_obj = ObjDescBundle::new(
        unsafe { SELF_CNODE },
        seL4_WordBits as u8,
        vec![ObjDesc::new(
            /*type=*/ seL4_CapTableObject,
            /*count=*/ request.depth as usize,
            /*cptr=*/ request.cnode,
        )],
    );
    cantrip_object_free(request)?;
    // No way to recover if this fails..
    cantrip_object_free_toplevel(&cnode_obj)
}

#[inline]
pub fn cantrip_object_free_toplevel(objs: &ObjDescBundle) -> Result<(), MemoryManagerError> {
    let mut objs_mut = objs.clone();
    // Move ojbects to the pre-allocated container. Note this returns
    // the toplevel slots to the slot allocator.
    objs_mut
        .move_objects_from_toplevel(unsafe { MEMORY_RECV_CNODE }, unsafe {
            MEMORY_RECV_CNODE_DEPTH
        })
        .map_err(|_| MemoryManagerError::MmeObjCapInvalid)?;
    cantrip_object_free(&objs_mut)
}

#[inline]
pub fn cantrip_memory_stats() -> Result<MemoryManagerStats, MemoryManagerError> {
    extern "C" {
        // NB: this assumes the MemoryManager component is named "memory".
        fn memory_stats(c_data: *mut RawMemoryStatsData) -> MemoryManagerError;
    }
    let raw_data = &mut [0u8; RAW_MEMORY_STATS_DATA_SIZE];
    match unsafe { memory_stats(raw_data as *mut _) } {
        MemoryManagerError::MmeSuccess => {
            let stats = postcard::from_bytes::<MemoryManagerStats>(raw_data)
                .map_err(|_| MemoryManagerError::MmeDeserializeFailed)?;
            Ok(stats)
        }
        status => Err(status),
    }
}

#[inline]
pub fn cantrip_memory_debug() -> Result<(), MemoryManagerError> {
    extern "C" {
        // NB: this assumes the MemoryManager component is named "memory".
        fn memory_debug();
    }
    unsafe { memory_debug() };
    Ok(())
}

#[inline]
pub fn cantrip_memory_capscan() -> Result<(), MemoryManagerError> {
    extern "C" {
        // NB: this assumes the MemoryManager component is named "memory".
        fn memory_capscan();
    }
    unsafe { memory_capscan() };
    Ok(())
}

// new code
#[derive(Debug)]
pub enum Error {
    OutOfMemory,
    NotFound,
}

#[derive(Debug)]
pub struct Vtree {
    pub bitmap: [usize;33],
    pub total_mem_size: usize,
    pub first_frame_cptr: usize,
}

impl Vtree {
    pub fn init(total_mem_size:usize, first_frame_cptr:usize) -> Self {
        let mut bitmap = [0usize;33];    //1 free ; 0 used
        if total_mem_size < MIDDLE_MEMORY_SIZE {
            let level = MAX_VTREE_LEVEL - CalculateOf2::log2_2(MAX_MEMORY_SIZE / total_mem_size);
            let left_index = find_node_index_region(total_mem_size).0;
            let num = level +1;
            let top_mask = 1 << 31;
            bitmap[0] |= top_mask;
            let mut sub_mask = 0;
            for i in 0..num {
                let temp = 1 << i;
                for i in 0..temp {
                    sub_mask |= 1 << (63 - (left_index * temp + i));
                }
            }
            bitmap[1] |= sub_mask;
            Self {
                bitmap,
                total_mem_size,
                first_frame_cptr,
            }
        } else {
            let level = MAX_VTREE_LEVEL - CalculateOf2::log2_2(MAX_MEMORY_SIZE / total_mem_size);
            if total_mem_size == MIDDLE_MEMORY_SIZE {
                bitmap[0] = 1 << 31;
                bitmap[1] = (1 << 63) - 1;
            } else {
                let left_index = find_node_index_region(total_mem_size).0;
                let top_num = level - 4;
                let sub_num = total_mem_size / MIDDLE_MEMORY_SIZE;
                let mut top_mask = 0;
                for i in 0..top_num {
                    let temp = 1 <<(i);
                    for u in 0..temp {
                        top_mask |= 1 << (63 - (left_index * temp + u));
                    }
                }
                bitmap[0] |= top_mask;
                for i in 1..= sub_num {
                    bitmap[i] |= (1<<63)-1;
                }
            }
            Self {
                bitmap,
                total_mem_size,
                first_frame_cptr,
            }
        }
    }

    pub fn find_alloc_node(&self, mem_size:usize) -> Result<(usize, usize), Error> {
        if mem_size > MIDDLE_MEMORY_SIZE {  // >128k
            let region = find_node_index_region(mem_size);
            let left_index = region.0;
            let right_index = region.1;
            let mask = (1 << (64 - left_index)) -1;
            let temp = self.bitmap[0] & mask;
            let top_index = temp.leading_zeros() as usize;
            if top_index > right_index {
                return Err(Error::NotFound);
            } else {
                return Ok((top_index, 0));
            }
        } else {
            let top_left_index = 32;
            let top_mask = (1 << (64 - top_left_index)) -1;
            let top_temp = self.bitmap[0] & top_mask;
            let top_temp_index = top_temp.leading_zeros() as usize;
            let sub_tree_num = 32 - (63 - top_temp_index);
            let sub_region = find_node_index_region(mem_size);
            let sub_left_index = sub_region.0;
            let sub_right_index = sub_region.1;
            let sub_mask = (1 << (64 - sub_left_index)) -1;
            for i in sub_tree_num..33 {
                let sub_temp = self.bitmap[i] & sub_mask;
                let sub_index = sub_temp.leading_zeros() as usize;
                if sub_index > sub_right_index {
                    continue;
                } else {
                    return Ok((31+i,sub_index));
                }
            }
        }
        return Err(Error::NotFound);
    }
    pub fn chang_flag_one(&mut self,mem_size: usize) {
        let node_index = self.find_alloc_node(mem_size).unwrap();
        let top = node_index.0;
        let sub = node_index.1;
        if (0<top) && (top<32) && (sub == 0) {
            let level = MAX_VTREE_LEVEL - CalculateOf2::log2_2(MAX_MEMORY_SIZE / mem_size);
            let top_child_num = level - 4;
            let mut top_child_mask = 0;
            let mut top_parents_mask = 0;
            for i in 0..top_child_num {
                let temp = 1 << i;
                for i in 0..temp {
                    let sub_num = 63 - (top * temp + i);
                    if sub_num <= 31 {
                        let sub_index = 32 - sub_num;
                        self.bitmap[sub_index] = 0;
                    }
                    top_child_mask |= 1 << sub_num;
                }
            }
            self.bitmap[0] ^= top_child_mask;
            let top_parents_num = MAX_VTREE_LEVEL - level;
            for i in 0..top_parents_num {
                let parents = top >> (i+1);
                let temp = 1 << (63 - parents);
                if (self.bitmap[0] & temp) > 0 {
                    top_parents_mask |= 1 << (63 - parents);
                }
            }
            self.bitmap[0] ^= top_parents_mask;
        }
        if (top>31) && (top<64) && (sub>1) && (sub<64) {
            let level = MAX_VTREE_LEVEL - CalculateOf2::log2_2(MAX_MEMORY_SIZE / mem_size);
            let sub_tree_index = 32 - (63 - top);
            let sub_child_num = level + 1;
            let mut sub_child_mask = 0;
            let mut sub_parents_mask = 0;
            for i in 0..sub_child_num {
                let temp = 1 << i;
                for u in 0..temp {
                    sub_child_mask |= 1 << (63 - (sub * temp + u))
                }
            }
            self.bitmap[sub_tree_index] ^= sub_child_mask;
            let sub_parents_num = MID_VTREE_LEVEL - level;
            for i in 0..sub_parents_num {
                let parents = sub >> (i+1);
                let temp = 1 << (63 - parents);
                if (self.bitmap[sub_tree_index] & temp) > 0 {
                    sub_parents_mask |= 1 << (63 - parents);
                }
            }
            self.bitmap[sub_tree_index] ^= sub_parents_mask;
            let mut top_parents_mask = 0;
            let top_parents_num = 5;
            if self.bitmap[sub_tree_index] == 0 {
                let temp_mask = 1 << (63 - top);
                self.bitmap[0] ^= temp_mask;
            }
            for i in 0..top_parents_num {
                let parents = top >> (i+1);
                let temp = 1 << (63 - parents);
                if (self.bitmap[0] & temp) > 0 {
                    top_parents_mask |= 1 << (63 - parents);
                }
            }
            self.bitmap[0] ^= top_parents_mask;
        }
        if (top>31) && (top<64) && (sub == 1) {
            let sub_tree_index = 32 - (63 - top);
            self.bitmap[sub_tree_index] = 0;
            let mut top_parents_mask = 0;
            let top_parents_num = 6;
            for i in 0..top_parents_num {
                let parents = top >> i;
                let temp = 1 << (63 - parents);
                if (self.bitmap[0] & temp) > 0 {
                    top_parents_mask |= 1 <<(63 - parents);
                }
            }
            self.bitmap[0] ^= top_parents_mask;
        }
        self.current_vtree_max_memory_block();
    }

    pub fn chang_flag_zero(&mut self,inode:(usize,usize)) {
        let top = inode.0;
        let sub = inode.1;
        if (0<top) && (top<32) && (sub == 0) {
            let result = CalculateOf2::multiple_of_2(top);
            let mut level = 0;
            if result {
                level += MAX_VTREE_LEVEL - CalculateOf2::log2_2(top);
            } else {
                let next_power_of_top = CalculateOf2::next_power_of_2(top);
                let level_temp = CalculateOf2::log2_2(next_power_of_top);
                level += MAX_VTREE_LEVEL - level_temp + 1;
            }
            let top_child_num = level - 4;
            let mut top_child_mask = 0;
            for i in 0..top_child_num {
                let child_temp = 1 << i;
                for u in 0..child_temp {
                    let sub_num = 63 - (top * child_temp + u);
                    if sub_num <= 31 {
                        let sub_index = 32 - sub_num;
                        self.bitmap[sub_index] = (1 << 63) -1;
                    }
                    top_child_mask |= 1 << sub_num;
                }
            }
            self.bitmap[0] |= top_child_mask;
            let top_parents_num = MAX_VTREE_LEVEL - level;
            let mut top_parents_mask = 0;
            for i in 0..top_parents_num {
                let parents = top >> (i+1);
                let top_buddy = find_buddy(top >> i);
                let buddy_temp = 1 << (63 - top_buddy);
                if ((self.bitmap[0] & buddy_temp) > 0) && (self.bitmap[0] & (1 << (63 - (top >> i))) > 0) {
                    top_parents_mask |= 1 << (63 - parents);
                }
            }
            self.bitmap[0] |= top_parents_mask;
        }
        if (top>31) && (top<64) && (sub>1) && (sub<64) {
            let result = CalculateOf2::multiple_of_2(sub);
            let sub_tree_index = 32 - (63 - top);
            let mut level = 0;
            let sub_buddy = find_buddy(sub);
            if result {
                level += MID_VTREE_LEVEL - CalculateOf2::log2_2(sub);
            } else {
                let next_power_of_sub = CalculateOf2::next_power_of_2(sub);
                let level_temp = CalculateOf2::log2_2(next_power_of_sub);
                level += MID_VTREE_LEVEL + 1 - level_temp;
            }
            let sub_child_num = level + 1 ;
            let mut sub_child_mask = 0;
            for i in 0..sub_child_num {
                let temp = 1 << i;
                for u in 0..temp {
                sub_child_mask |= 1 << (63 - (sub * temp + u));
                }
            }
            self.bitmap[sub_tree_index] |= sub_child_mask;
            let sub_parents_num = MID_VTREE_LEVEL - level;
            let mut sub_parents_mask = 0;
            for i in 0..sub_parents_num {
                let parents = sub >> (i + 1);
                let left_child = parents << 1;
                let right_child = (parents << 1) + 1;
                if ((self.bitmap[sub_tree_index] & (1<<(63-left_child))) != 0) && ((self.bitmap[sub_tree_index] & (1<<(63-right_child))) != 0) {
                    sub_parents_mask |= 1 << (63 - parents);
                    self.bitmap[sub_tree_index] |= sub_parents_mask;
                }
            }
            if self.bitmap[sub_tree_index] != 0 {
                self.bitmap[0] |= (1<<(63-top));
            }
            let mut top_parents_mask = 0;
            let top_parents_num = 5;
            for i in 0..top_parents_num {
                let parents = top >> (i+1);
                if (parents >= 16) && (parents <= 31){
                    continue;
                }
                let top_buddy = find_buddy(top >> i);
                let buddy_temp = 1 << (63 - top_buddy);
                if ((self.bitmap[0] & buddy_temp) != 0) && (self.bitmap[0] & (1 << (63 - (top >> i))) != 0) {
                    top_parents_mask |= 1 << (63 - parents);
                }
            }
            self.bitmap[0] |= top_parents_mask;
        }
        if (top>31) && (top<64) && (sub == 1) {
            let sub_tree_index = 32 - (63 - top);
            self.bitmap[sub_tree_index] = (1 << 63) - 1;
            let mut top_parents_mask = 0;
            self.bitmap[0] |= 1 << (top - 1);
            let top_parents_num = 5;
            for i in 0..top_parents_num {
                let parents = top >> (i+1);
                let top_buddy = find_buddy(top >> i);
                let buddy_temp = 1 << (63 - top_buddy);
                if ((self.bitmap[0] & buddy_temp) > 0) && (self.bitmap[0] & (1 << (63 - (top >> i))) > 0) {
                    top_parents_mask |= 1 << (63 - parents);
                }
            }
            self.bitmap[0] |= top_parents_mask;
        }
         self.current_vtree_max_memory_block();
    }

    pub fn current_vtree_max_memory_block(&mut self) {
        let first_top_node = self.bitmap[0].leading_zeros() as usize;
        let mut current_max_mem = 0;
        let mut level = 0;
        if first_top_node < 32 {
            let result = CalculateOf2::multiple_of_2(first_top_node);
            if result {
                level += MAX_VTREE_LEVEL - CalculateOf2::log2_2(first_top_node);
            } else {
                let next_power_of_top = CalculateOf2::next_power_of_2(first_top_node);
                let level_temp = CalculateOf2::log2_2(next_power_of_top);
                level += MAX_VTREE_LEVEL - level_temp + 1;
            }
            current_max_mem += 1 << (level + 12);
            self.total_mem_size = current_max_mem;
        }
        if (first_top_node >= 32) && (first_top_node <= 63) {
            let sub_tree_index = 32 - (63 - first_top_node);
            let mut min_sub_node = 64;
            for i in sub_tree_index..33 {
                let first_sub_node = self.bitmap[i].leading_zeros() as usize;
                if first_sub_node < min_sub_node {
                    min_sub_node = first_sub_node;
                }
            }
            let result = CalculateOf2::multiple_of_2(min_sub_node);
             if result {
                level += MID_VTREE_LEVEL - CalculateOf2::log2_2(min_sub_node);
            } else {
                let next_power_of_sub = CalculateOf2::next_power_of_2(min_sub_node);
                let level_temp = CalculateOf2::log2_2(next_power_of_sub);
                level += (MID_VTREE_LEVEL + 1 - level_temp);
            }
            current_max_mem += 1 << (level + 12);
        }
        if first_top_node == 64 {
            current_max_mem = 0;
        }
        self.total_mem_size = current_max_mem;
    }
}

pub fn find_node_index_region(mem_size: usize) -> (usize, usize) {
    if mem_size > MIDDLE_MEMORY_SIZE {
        let level = MAX_VTREE_LEVEL - CalculateOf2::log2_2(MAX_MEMORY_SIZE / mem_size);
        let left_index = 1 << (MAX_VTREE_LEVEL - level);
        let right_index = (1 << (MAX_VTREE_LEVEL - level + 1)) - 1;
        (left_index,right_index)
    } else {
        let level = MAX_VTREE_LEVEL - CalculateOf2::log2_2(MAX_MEMORY_SIZE / mem_size);
        let left_index = 1 << (MID_VTREE_LEVEL - level);
        let right_index = (1 << (MID_VTREE_LEVEL - level + 1)) - 1;
        (left_index,right_index)
    }
}

pub fn find_buddy(num: usize) -> usize{
    let buddy = num;
    if num % 2 == 0 {
        buddy + 1
    } else {
        buddy -1
    }
}

pub fn find_sub_tree_level(sub:usize) -> usize {
    let mut level = 0;
    if CalculateOf2::multiple_of_2(sub) {
        level += CalculateOf2::log2_2(64/sub) - 1;
    } else {
        level += CalculateOf2::log2_2(64/CalculateOf2::next_power_of_2(sub));
    }
    level
}

pub static mut FRAME_VTREE: TreeVec = TreeVec::init();

#[derive(Debug)]
pub struct TreeVec {
    pub treevec: Vec<Vtree>,
}

impl TreeVec {
    pub const fn init() -> Self {
        let treevec = Vec::<Vtree>::new();
        TreeVec {
            treevec,
        }
    }

    pub fn insert_vtree(&mut self) {
        let recv_frame_base_slot = cantrip_memory_stats().unwrap().recv_frame_base_slot;
        let mut objs = ObjDescBundle::new(
            unsafe { MEMORY_RECV_CNODE },
            unsafe { MEMORY_RECV_CNODE_DEPTH },
            vec![ObjDesc::new(
                seL4_SmallPageObject,
                1024,
                /*cptr=*/ recv_frame_base_slot,
            )],
        );
        cantrip_object_alloc(&objs);
        let cur_untyped_size = cantrip_memory_stats().unwrap().current_memory_size;
        let mut new_tree_num = 1;
        if cur_untyped_size > MAX_MEMORY_SIZE {
            for i in 0..new_tree_num {
                let new_vtree = Vtree::init(MAX_MEMORY_SIZE,recv_frame_base_slot);
                self.treevec.push(new_vtree);
            }
        } else {
            let new_vtree = Vtree::init(cur_untyped_size, recv_frame_base_slot);
            self.treevec.push(new_vtree);
        }
    }

    pub fn find_request_vtree(&self, mem_size: usize) -> Option<usize> {
        self.treevec.iter().position(|x| x.total_mem_size >= mem_size)
    }

    pub fn new_cantrip_frame_alloc(&mut self, num:usize) -> FrameBulk{
        let request_mem = num * MIN_MEMORY_SIZE;
        let mut tree_node_option = self.find_request_vtree(request_mem);
        while tree_node_option.is_none() {
            self.insert_vtree();
            tree_node_option = self.find_request_vtree(request_mem);
        }
        let tree_node = tree_node_option.unwrap();
        let alloc_node = self.treevec[tree_node].find_alloc_node(request_mem).unwrap();
        let top = alloc_node.0;
        let sub = alloc_node.1;
        let mut frame_start_cptr = 0;
        if (0<top) && (top<32) && (sub == 0) {
            let level = find_sub_tree_level(top);
            let sub_tree_node = (top << level) - 32;
            frame_start_cptr += self.treevec[tree_node].first_frame_cptr + sub_tree_node * 32;
        }
        if (top>31) && (top<64) && (sub>0) && (sub<64) {
            let sub_tree_node = 32 - (63 - top) - 1;
            let level = find_sub_tree_level(sub);
            let start_index = (sub << level) - 32;
            frame_start_cptr += self.treevec[tree_node].first_frame_cptr + sub_tree_node * 32 + start_index;
        }
        self.treevec[tree_node].chang_flag_one(request_mem);
        let frame_obj = vec![ObjDesc::new(seL4_SmallPageObject, num, frame_start_cptr)];
        unsafe {
            let mut frame_bundle:ObjDescBundle = ObjDescBundle::new(MEMORY_RECV_CNODE, MEMORY_RECV_CNODE_DEPTH, frame_obj);
            frame_bundle.move_objects_to_toplevel();
            let mut frame_bulk = FrameBulk::new(frame_bundle,frame_start_cptr,tree_node,alloc_node);
            frame_bulk
        }
    }

    pub fn new_cantrip_frame_free(&mut self, frame: FrameBulk) {
        self.treevec[frame.tree_node].chang_flag_zero(frame.alloc_node);
        unsafe {
            let mut frame_bundle = frame.frame_bundle;
            let cptr = frame.cptr;
            &frame_bundle.move_frame_to_framecnode(MEMORY_RECV_CNODE, MEMORY_RECV_CNODE_DEPTH,cptr);
        }
    }

    pub fn new_cantrip_mem_free(&mut self, mem: MemBlock) {
        unsafe {
            let frame_bundle = mem.bulk;
            self.new_cantrip_frame_free(frame_bundle);
        }
    }

}

#[derive(Debug)]
pub struct FrameBulk {
    pub frame_bundle: ObjDescBundle,
    pub cptr: usize,
    pub tree_node: usize,
    pub alloc_node: (usize,usize),
}

impl FrameBulk {
    pub fn new(frame_bundle: ObjDescBundle, cptr: usize, tree_node:usize, alloc_node: (usize,usize)) -> Self {
        FrameBulk {
            frame_bundle,
            cptr,
            tree_node,
            alloc_node
        }
    }
}


#[derive(Debug)]
pub struct MemBlock {
    pub frame_num: usize,
    pub free_time: usize,
    pub bulk: FrameBulk,
}

impl MemBlock {
    pub fn new(num: usize, time: usize, bulk: FrameBulk) -> Self {
        Self {
            frame_num: num,
            free_time: time,
            bulk: bulk,
        }
    }

}

const MAX_FRAME_NUM:usize = 1024;
const NUM_OF_SIZE:usize = 5;

pub fn get_time(seed: &mut Pcg32, max_time:usize) -> usize {
    let mut time = ((seed.next_u32() as usize) % (max_time)) + 1;
    while time > max_time {
        time = ((seed.next_u32() as usize) % (max_time)) + 1;
    }
    time
}

pub fn get_first_size_distribution(seed: &mut Pcg32) -> usize {
    let frame_num = ((seed.next_u32() as usize) % (1 << CalculateOf2::log2_2(2))) + 1;
    frame_num

}

pub fn get_second_size_distribution(seed: &mut Pcg32) -> usize {
    let temp = ((seed.next_u32() as usize) % (1 << CalculateOf2::log2_2(MAX_FRAME_NUM))) + 1;
    let mut frame_num = 0;
    match temp {
        1..=512 => {
            frame_num += 1;
        },
        513..=768 => {
            frame_num += 2;
        },
        769..=896 => {
            frame_num += 4;
        },
        897..=960 => {
            frame_num += 8;
        },
        961..=992 => {
            frame_num += 16;
        },
        993..=1008 => {
            frame_num += 32;
        },
        1009..=1016 => {
            frame_num += 64;
        },
        1017..=1020 => {
            frame_num += 128;
        },
        1021..=1022 => {
            frame_num += 256;
        },
        1023 => {
            frame_num += 512;
        },
        1024 => {
            frame_num += 1024;
        },
        _ => {
            panic!("error frame num");
    }
}
    frame_num
}

pub fn get_third_size_distribution(seed: &mut Pcg32, arr: [usize; NUM_OF_SIZE]) -> usize {
    let mut index = (seed.next_u32() as usize) % (1 << CalculateOf2::log2_2(CalculateOf2::next_power_of_2(NUM_OF_SIZE)));
    while index > (NUM_OF_SIZE - 1) {
        index = (seed.next_u32() as usize) % (1 << CalculateOf2::log2_2(CalculateOf2::next_power_of_2(NUM_OF_SIZE)));
    }
    let frame_num = arr[index];
    frame_num
}

pub trait CalculateOf2 {
    fn multiple_of_2(self) -> bool;
    fn next_power_of_2(self) -> usize;
    fn log2_2(self) -> usize;
}

impl CalculateOf2 for usize {
    fn multiple_of_2(self) -> bool {
        self !=0 && (self & (self - 1)) == 0
    }
    //Find a power of 2 greater than the input
    fn next_power_of_2(self) -> usize {
        if self == 0 {
            return 1;
        }
        let mut v = Wrapping(self);
        v -= Wrapping(1);
        v = v | (v >> 1);
        v = v | (v >> 2);
        v = v | (v >> 4);
        v = v | (v >> 8);
        v = v | (v >> 16);
        if size_of::<usize>() > 4 {
            v = v | (v >> 32);
        }
        v += Wrapping(1);
        let result = match v { Wrapping(v) => v };
        assert!(result.multiple_of_2());
        assert!(result >= self && self > result >> 1);
        result
    }
    fn log2_2(self) -> usize {
        let mut temp = self;
        let mut result = 0;
        temp >>= 1;
        while temp != 0 {
            result += 1;
            temp >>= 1;
        }
        result
    }
}
