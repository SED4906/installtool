use core::{alloc::GlobalAlloc, ptr::null_mut};

use limine::{
    memory_map::EntryType,
    request::{HhdmRequest, MemoryMapRequest},
};
use spin::Mutex;
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

const PAGE_SIZE: usize = 4096;
static HHDM_OFFSET: Mutex<usize> = Mutex::new(0);

pub fn init() {
    {
        let mut hhdm_offset = HHDM_OFFSET.lock();
        *hhdm_offset = HHDM_REQUEST.get_response().unwrap().offset() as usize;
    }
    for entry in MEMORY_MAP_REQUEST.get_response().unwrap().entries() {
        if entry.entry_type != EntryType::USABLE {
            continue;
        }
        for page in (entry.base..entry.base + entry.length).step_by(PAGE_SIZE) {
            Freelist::free(page as *mut ());
        }
    }
}

pub fn hhdm(ptr: u64) -> u64 {
    let hhdm_offset = HHDM_OFFSET.lock();
    ptr + (*hhdm_offset as u64)
}

pub struct Freelist(*mut Freelist);
unsafe impl Send for Freelist {}
unsafe impl Sync for Freelist {}
static FREELIST: Mutex<Freelist> = Mutex::new(Freelist(null_mut()));

impl Freelist {
    pub fn free<T>(ptr: *mut T) {
        let mut freelist = FREELIST.lock();
        let hhdm_offset = HHDM_OFFSET.lock();
        unsafe {
            *(ptr as *mut Freelist).byte_add(*hhdm_offset) = Freelist(freelist.0);
        }
        freelist.0 = ptr as *mut Freelist;
    }
    pub fn alloc<T>() -> *mut T {
        let mut freelist = FREELIST.lock();
        let hhdm_offset = HHDM_OFFSET.lock();
        if freelist.0.is_null() {
            null_mut()
        } else {
            let result = freelist.0;
            unsafe {
                freelist.0 = (*result.byte_add(*hhdm_offset)).0;
            }
            result as *mut T
        }
    }
}

pub unsafe fn map_to<T>(page_map: MemoryPageMap, virtual_address: *mut T, physical_address: *mut T, options: MapToOptions) {
    let page_map_level_4 = MemoryMappingLevel::Level4(page_map as SubPageMap);
    let page_map_level_3 = map_to_step(page_map_level_4, virtual_address);
    let page_map_level_2 = map_to_step(page_map_level_3, virtual_address);
    let page_map_level_1 = map_to_step(page_map_level_2, virtual_address);
    match page_map_level_1 {
        MemoryMappingLevel::Level1(page_map) => (*page_map)[(virtual_address as usize >> 12) & 0x1FF] = (physical_address as usize) | options.to_flags(),
        _ => panic!("this page map is the wrong level somehow"),
    }
}

unsafe fn map_to_step<T>(page_map: MemoryMappingLevel, virtual_address: *mut T) -> MemoryMappingLevel {
    match page_map {
        MemoryMappingLevel::Level4(page_map) => {
            if (*page_map)[(virtual_address as usize >> 39) & 0x1FF] & 1 == 0 {
                (*page_map)[(virtual_address as usize >> 39) & 0x1FF] = (Freelist::alloc::<usize>() as usize) | 7;
            }
            MemoryMappingLevel::Level3((*page_map)[(virtual_address as usize >> 39) & 0x1FF] as SubPageMap)
        },
        MemoryMappingLevel::Level3(page_map) => {
            if (*page_map)[(virtual_address as usize >> 30) & 0x1FF] & 1 == 0 {
                (*page_map)[(virtual_address as usize >> 30) & 0x1FF] = (Freelist::alloc::<usize>() as usize) | 7;
            }
            MemoryMappingLevel::Level2((*page_map)[(virtual_address as usize >> 39) & 0x1FF] as SubPageMap)
        },
        MemoryMappingLevel::Level2(page_map) => {
            if (*page_map)[(virtual_address as usize >> 21) & 0x1FF] & 1 == 0 {
                (*page_map)[(virtual_address as usize >> 21) & 0x1FF] = (Freelist::alloc::<usize>() as usize) | 7;
            }
            MemoryMappingLevel::Level1((*page_map)[(virtual_address as usize >> 39) & 0x1FF] as SubPageMap)
        },
        MemoryMappingLevel::Level1(_) => panic!("map_to_step shouldn't be called on the lowest page map level"),
    }
}

pub type MemoryPageMap = usize;
pub type SubPageMap = *mut [MemoryPageMap;PAGE_SIZE/size_of::<usize>()];

pub enum MemoryMappingLevel {
    Level4(SubPageMap),
    Level3(SubPageMap),
    Level2(SubPageMap),
    Level1(SubPageMap),
}

pub struct MemoryMapping {
    physical_address: *mut (),
    options: MapToOptions
}

pub struct MapToOptions {
    pub privilege: MappingPrivilege,
    pub writeable: MappingWriteable,
    pub present: bool,
}

pub enum MappingPrivilege {
    Kernel,
    User,
}

pub enum MappingWriteable {
    ReadOnly,
    ReadWrite,
}

impl MapToOptions {
    pub fn to_flags(&self) -> usize {
        let mut result = 0;
        if self.present {
            result |= 1
        }
        match self.writeable {
            MappingWriteable::ReadOnly => {}
            MappingWriteable::ReadWrite => result |= 2,
        }
        match self.privilege {
            MappingPrivilege::Kernel => {}
            MappingPrivilege::User => result |= 4,
        }
        result
    }

    pub fn new_user_rw() -> MapToOptions {
        MapToOptions {
            privilege: MappingPrivilege::User,
            writeable: MappingWriteable::ReadWrite,
            present: true,
        }
    }

    pub fn new_kernel_rw() -> MapToOptions {
        MapToOptions {
            privilege: MappingPrivilege::Kernel,
            writeable: MappingWriteable::ReadWrite,
            present: true,
        }
    }
}

unsafe impl GlobalAlloc for Freelist {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        if layout.size() > 4096 {
            panic!("allocation too large");
        }
        if layout.align() > 4096 {
            panic!("allocation too aligned");
        }
        Freelist::alloc::<u8>()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        Freelist::free(ptr)
    }
}