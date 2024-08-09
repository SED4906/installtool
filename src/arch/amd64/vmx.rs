use core::ptr::addr_of;

use limine::memory_map::EntryType;
use x86::bits64::registers::rsp;
use x86::bits64::vmx::{vmclear, vmlaunch, vmptrld, vmread, vmresume, vmwrite, vmxon};

use x86::controlregs::{self, cr3};
use x86::cpuid::CpuId;
use x86::msr::{self, IA32_VMX_ENTRY_CTLS, IA32_VMX_EXIT_CTLS, IA32_VMX_PINBASED_CTLS, IA32_VMX_PROCBASED_CTLS, IA32_VMX_PROCBASED_CTLS2};
use x86::vmx::vmcs::control::{ExitControls, PrimaryControls, SecondaryControls};
use x86::vmx::vmcs;
use x86::{controlregs::{cr0, cr4}, msr::rdmsr};
use x86_64::instructions::tables::{sgdt, sidt};

use crate::arch::amd64::descriptors::TSS;
use crate::arch::cpu;
use crate::arch::cpu::mm::Freelist;
use crate::{print, println};

use super::mm::MEMORY_MAP_REQUEST;

pub fn has_intel_cpu() -> bool {
    let cpuid = CpuId::new();
    if let Some(vi) = cpuid.get_vendor_info() {
        if vi.as_str() == "GenuineIntel" {
            return true;
        }
    }
    false
}

pub fn has_vmx_support() -> bool {
    let cpuid = CpuId::new();
    if let Some(fi) = cpuid.get_feature_info() {
        if fi.has_vmx() {
            return true;
        }
    }
    false
}

pub fn enable_vmx_operation() -> bool {
    let mut cr4 = unsafe { controlregs::cr4() };
    cr4.set(controlregs::Cr4::CR4_ENABLE_VMX, true);
    unsafe { controlregs::cr4_write(cr4) };

    assert!(set_lock_bit());
    println!("[+] Lock bit set via IA32_FEATURE_CONTROL");

    true
}

fn set_lock_bit() -> bool {
    const VMX_LOCK_BIT: u64 = 1 << 0;
    const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

    let ia32_feature_control = unsafe { rdmsr(msr::IA32_FEATURE_CONTROL) };

    if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
        unsafe {
            msr::wrmsr(
                msr::IA32_FEATURE_CONTROL,
                VMXON_OUTSIDE_SMX | VMX_LOCK_BIT | ia32_feature_control,
            )
        };
    } else if (ia32_feature_control & VMXON_OUTSIDE_SMX) == 0 {
        return false
    }

    true
}

pub fn adjust_control_registers() {
    set_cr0_bits();
    println!("[+] Mandatory bits in CR0 set/cleared");

    set_cr4_bits();
    println!("[+] Mandatory bits in CR4 set/cleared");
}

/// Set the mandatory bits in CR0 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
fn set_cr0_bits() {
    let ia32_vmx_cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
    let ia32_vmx_cr0_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };

    let mut cr0 = unsafe { controlregs::cr0() };

    cr0 |= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed0 as usize);
    cr0 &= controlregs::Cr0::from_bits_truncate(ia32_vmx_cr0_fixed1 as usize);

    unsafe { controlregs::cr0_write(cr0) };
}

/// Set the mandatory bits in CR4 and clear bits that are mandatory zero (Intel Manual: 24.8 Restrictions on VMX Operation)
fn set_cr4_bits() {
    let ia32_vmx_cr4_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
    let ia32_vmx_cr4_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };

    let mut cr4 = unsafe { controlregs::cr4() };

    cr4 |= controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed0 as usize);
    cr4 &= controlregs::Cr4::from_bits_truncate(ia32_vmx_cr4_fixed1 as usize);

    unsafe { controlregs::cr4_write(cr4) };
}

#[repr(C, align(4096))]
pub struct VmxonRegion {
    pub revision_id: u32,
    pub data: [u8; PAGE_SIZE - 4],
}
const PAGE_SIZE: usize = 0x1000;

pub fn get_vmcs_revision_id() -> u32 {
    unsafe { (msr::rdmsr(msr::IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF }
}

pub unsafe fn has_unrestricted_guest() -> bool {
    msr::rdmsr(msr::IA32_VMX_PROCBASED_CTLS2) & (1<<39) != 0
}

pub unsafe fn map_ept_page_4kb(eptp: u64, page: u64, guest: u64) {
    let ept4 = eptp as *mut u64;
    let ept4i = ((guest >> 39) & 0x1FF) as usize;
    let ept4e = *ept4.add(ept4i);
    if ept4e == 0 {
        let page = Freelist::alloc::<[u8;4096]>();
        (*page).fill(0);
        *ept4.add(ept4i) = 7 | page as u64;
    }
    let ept3 = (*ept4.add(ept4i) & !0xFFF) as *mut u64;
    let ept3i = ((guest >> 30) & 0x1FF) as usize;
    let ept3e = *ept3.add(ept3i);
    if ept3e == 0 {
        let page = Freelist::alloc::<[u8;4096]>();
        (*page).fill(0);
        *ept3.add(ept3i) = 7 | page as u64;
    }
    let ept2 = (*ept3.add(ept3i) & !0xFFF) as *mut u64;
    let ept2i = ((guest >> 21) & 0x1FF) as usize;
    let ept2e = *ept2.add(ept2i);
    if ept2e == 0 {
        let page = Freelist::alloc::<[u8;4096]>();
        (*page).fill(0);
        *ept2.add(ept2i) = 7 | page as u64;
    }
    let ept1 = (*ept2.add(ept2i) & !0xFFF) as *mut u64;
    let ept1i = ((guest >> 12) & 0x1FF) as usize;
    *ept1.add(ept1i) = 7 | page;
}

pub unsafe fn map_ept_page_2mb(eptp: u64, page: u64, guest: u64) {
    let ept4 = eptp as *mut u64;
    let ept4i = ((guest >> 39) & 0x1FF) as usize;
    let ept4e = *ept4.add(ept4i);
    if ept4e == 0 {
        let page = Freelist::alloc::<[u8;4096]>();
        (*page).fill(0);
        *ept4.add(ept4i) = 7 | page as u64;
    }
    let ept3 = (*ept4.add(ept4i) & !0xFFF) as *mut u64;
    let ept3i = ((guest >> 30) & 0x1FF) as usize;
    let ept3e = *ept3.add(ept3i);
    if ept3e == 0 {
        let page = Freelist::alloc::<[u8;4096]>();
        (*page).fill(0);
        *ept3.add(ept3i) = 7 | page as u64;
    }
    let ept2 = (*ept3.add(ept3i) & !0xFFF) as *mut u64;
    let ept2i = ((guest >> 21) & 0x1FF) as usize;
    *ept2.add(ept2i) = 7 | (1<<7) | page;
}

pub unsafe fn map_ept_page_1gb(eptp: u64, page: u64, guest: u64) {
    let ept4 = eptp as *mut u64;
    let ept4i = ((guest >> 39) & 0x1FF) as usize;
    let ept4e = *ept4.add(ept4i);
    if ept4e == 0 {
        let page = Freelist::alloc::<[u8;4096]>();
        (*page).fill(0);
        *ept4.add(ept4i) = 7 | page as u64;
    }
    let ept3 = (*ept4.add(ept4i) & !0xFFF) as *mut u64;
    let ept3i = ((guest >> 30) & 0x1FF) as usize;
    *ept3.add(ept3i) = 7 | (1<<7) | page;
}


pub unsafe fn setup_ept(eptp: u64) {
    for entry in MEMORY_MAP_REQUEST.get_response().unwrap().entries() {
        if entry.entry_type == EntryType::USABLE || entry.entry_type == EntryType::BAD_MEMORY {
            continue;
        }
        
        let mut current_page = entry.base;
        while current_page < entry.base + entry.length {
            // if we are 1GB aligned and 1GB size
            if current_page & 0x3FFFFFFF == 0 && entry.length - (current_page - entry.base) >= 512*512*4096 {
                map_ept_page_1gb(eptp, current_page, current_page);
                current_page += 512*512*4096;
            }
            // if we are 2MB aligned and 2MB size
            else if current_page & 0x1FFFFF == 0 && entry.length - (current_page - entry.base) >= 512*4096 {
                map_ept_page_2mb(eptp, current_page, current_page);
                current_page += 512*4096;
            } else {
                map_ept_page_4kb(eptp, current_page, current_page);
                current_page += 4096;
            }
        }
    }
    map_ept_page_4kb(eptp, 0, 0);
    'exhaust: for entry in MEMORY_MAP_REQUEST.get_response().unwrap().entries() {
        if entry.entry_type != EntryType::USABLE {
            continue;
        }
        
        let mut current_page = entry.base;
        while current_page < entry.base + entry.length {
            let page = Freelist::alloc::<u8>() as u64;
            if page == 0 {break 'exhaust};
            map_ept_page_4kb(eptp, page, current_page);
            current_page += 4096;
        }
    }
    map_ept_page_4kb(eptp, 0xfffff000, 0xff000);
}

pub unsafe fn init() {
    assert!(has_intel_cpu(), "not an Intel CPU");
    assert!(has_vmx_support(), "VMX not supported");
    assert!(enable_vmx_operation(), "failed to enable VMX");
    assert!(has_unrestricted_guest(), "missing crucial CPU feature (unrestricted guest)");
    
    println!("starting vm...");

    adjust_control_registers();

    let vmcs_revision_id = get_vmcs_revision_id();

    let vmcs_root = Freelist::alloc::<VmxonRegion>();
    let vmcs_guest = Freelist::alloc::<VmxonRegion>();
    let guest_eptp = Freelist::alloc::<u64>() as u64;
    (*(guest_eptp as *mut [u8;4096])).fill(0);
    (*(vmcs_guest as *mut [u8;4096])).fill(0);

    setup_ept(guest_eptp);
    (*vmcs_root).revision_id = vmcs_revision_id;
    (*vmcs_guest).revision_id = vmcs_revision_id;

    println!("vmxon?");
    vmxon(vmcs_root as u64).expect("vmxon failed");
    println!("vmclear?");
    vmclear(vmcs_guest as u64).expect("vmclear failed");
    println!("vmptrld?");
    vmptrld(vmcs_guest as u64).expect("vmptrld failed");

    vmwrite(vmcs::host::CR3, cr3());
    vmwrite(vmcs::host::CR0, cr0().bits() as u64);
    vmwrite(vmcs::host::CR4, cr4().bits() as u64);
    vmwrite(vmcs::host::RIP, vmexit_handler as u64);
    vmwrite(vmcs::host::RSP, rsp() - 0x80);
    vmwrite(vmcs::host::GDTR_BASE, sgdt().base.as_u64());
    vmwrite(vmcs::host::IDTR_BASE, sidt().base.as_u64());
    vmwrite(vmcs::host::TR_BASE, addr_of!(TSS) as u64);
    vmwrite(vmcs::host::TR_SELECTOR, 0x18);
    vmwrite(vmcs::host::CS_SELECTOR, 0x08);
    vmwrite(vmcs::host::DS_SELECTOR, 0);
    vmwrite(vmcs::host::ES_SELECTOR, 0);
    vmwrite(vmcs::host::FS_SELECTOR, 0);
    vmwrite(vmcs::host::GS_SELECTOR, 0);
    vmwrite(vmcs::host::SS_SELECTOR, 0);

    vmwrite(vmcs::host::IA32_SYSENTER_CS, 0);
    vmwrite(vmcs::host::IA32_SYSENTER_EIP, 0);
    vmwrite(vmcs::host::IA32_SYSENTER_ESP, 0);
    vmwrite(vmcs::host::FS_BASE, 0);
    vmwrite(vmcs::host::GS_BASE, 0);
    vmwrite(vmcs::control::VMENTRY_CONTROLS, {
        let mut adjust = 0 as u64;
        let bits = msr::rdmsr(IA32_VMX_ENTRY_CTLS);
        adjust &= bits >> 32;
        adjust |= bits & 0xFFFFFFFF;
        adjust
    });
    vmwrite(vmcs::control::PINBASED_EXEC_CONTROLS,{
        let mut adjust = 0;
        let bits = msr::rdmsr(IA32_VMX_PINBASED_CTLS);
        adjust &= bits >> 32;
        adjust |= bits & 0xFFFFFFFF;
        adjust
    });
    vmwrite(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,{
        let mut adjust = (PrimaryControls::USE_MSR_BITMAPS | PrimaryControls::SECONDARY_CONTROLS).bits() as u64;
        let bits = msr::rdmsr(IA32_VMX_PROCBASED_CTLS);
        adjust &= bits >> 32;
        adjust |= bits & 0xFFFFFFFF;
        adjust
    });
    vmwrite(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS,{
        let mut adjust = (SecondaryControls::ENABLE_EPT | SecondaryControls::UNRESTRICTED_GUEST).bits() as u64;
        let bits = msr::rdmsr(IA32_VMX_PROCBASED_CTLS2);
        adjust &= bits >> 32;
        adjust |= bits & 0xFFFFFFFF;
        adjust
    });
    vmwrite(vmcs::control::VMEXIT_CONTROLS, {
        let mut adjust = ExitControls::HOST_ADDRESS_SPACE_SIZE.bits() as u64;
        let bits = msr::rdmsr(IA32_VMX_EXIT_CTLS);
        adjust &= bits >> 32;
        adjust |= bits & 0xFFFFFFFF;
        adjust
    });
    vmwrite(vmcs::guest::LINK_PTR_FULL, 0xFFFFFFFFFFFFFFFF);
    //vmwrite(vmcs::control::EXCEPTION_BITMAP, 0xFFFFFFFF);

    let ia32_vmx_cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
    let ia32_vmx_cr0_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };
    let ia32_vmx_cr4_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED0) };
    let guest_cr0 = (0x60000010 | ia32_vmx_cr0_fixed0) & ia32_vmx_cr0_fixed1;
    let guest_cr4 = ia32_vmx_cr4_fixed0;

    vmwrite(vmcs::guest::CR0, guest_cr0 & !(1<<0 | 1<<31));
    vmwrite(vmcs::guest::CR4, guest_cr4);
    vmwrite(vmcs::guest::CR3, 0);
    vmwrite(vmcs::guest::GDTR_BASE, 0);
    vmwrite(vmcs::guest::GDTR_LIMIT, 0);
    vmwrite(vmcs::guest::IDTR_BASE, 0);
    vmwrite(vmcs::guest::IDTR_LIMIT, 0);
    vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, 0xB | (1<<4) | (1<<7));
    vmwrite(vmcs::guest::CS_BASE, 0xFFFF0000);
    vmwrite(vmcs::guest::CS_LIMIT, 0xFFFF);
    vmwrite(vmcs::guest::CS_SELECTOR, 0xF000);
    vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, 3 | (1<<4) | (1<<7));
    vmwrite(vmcs::guest::DS_BASE, 0);
    vmwrite(vmcs::guest::DS_LIMIT, 0xFFFF);
    vmwrite(vmcs::guest::DS_SELECTOR, 0);
    vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, 3 | (1<<4) | (1<<7));
    vmwrite(vmcs::guest::ES_BASE, 0);
    vmwrite(vmcs::guest::ES_LIMIT, 0xFFFF);
    vmwrite(vmcs::guest::ES_SELECTOR, 0);
    vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, 3 | (1<<4) | (1<<7));
    vmwrite(vmcs::guest::FS_BASE, 0);
    vmwrite(vmcs::guest::FS_LIMIT, 0xFFFF);
    vmwrite(vmcs::guest::FS_SELECTOR, 0);
    vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, 3 | (1<<4) | (1<<7));
    vmwrite(vmcs::guest::GS_BASE, 0);
    vmwrite(vmcs::guest::GS_LIMIT, 0xFFFF);
    vmwrite(vmcs::guest::GS_SELECTOR, 0);
    vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, 3 | (1<<4) | (1<<7));
    vmwrite(vmcs::guest::SS_BASE, 0);
    vmwrite(vmcs::guest::SS_LIMIT, 0xFFFF);
    vmwrite(vmcs::guest::SS_SELECTOR, 0);
    vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, 2 | (1<<7));
    vmwrite(vmcs::guest::LDTR_BASE, 0);
    vmwrite(vmcs::guest::LDTR_LIMIT, 0);
    vmwrite(vmcs::guest::LDTR_SELECTOR, 0);
    vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, 3 | (1<<7));
    vmwrite(vmcs::guest::TR_BASE, 0);
    vmwrite(vmcs::guest::TR_LIMIT, 0);
    vmwrite(vmcs::guest::TR_SELECTOR, 0);
    vmwrite(vmcs::guest::DR7, 0);
    vmwrite(vmcs::guest::RSP, 0);
    vmwrite(vmcs::guest::RIP, 0xFFF0);
    vmwrite(vmcs::guest::RFLAGS, 2);
    vmwrite(vmcs::guest::IA32_SYSENTER_CS, 0);
    vmwrite(vmcs::guest::IA32_SYSENTER_EIP, 0);
    vmwrite(vmcs::guest::IA32_SYSENTER_ESP, 0);

    vmwrite(vmcs::control::EPTP_FULL, guest_eptp | (3<<3));

    match vmlaunch() {
        Ok(()) => {},
        Err(_) => {
            let error = vmread(vmcs::ro::VM_INSTRUCTION_ERROR).expect("failed to read error code");
            panic!("vmlaunch failed ({error})");
        },
    }
    
    cpu::wait_forever()
}

unsafe fn vmexit_handler() {
    let exit_reason = vmread(vmcs::ro::EXIT_REASON).expect("failed to get exit reason");
    print!("vmexit ({exit_reason:x}) ");
    if exit_reason == 48 {
        let ept_violation_addr = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL).expect("failed to get EPT violation guest address");
        panic!("unhandled EPT violation at {ept_violation_addr:x}");
    }
    println!();
    if exit_reason == 2 {
        panic!("guest system died of death");
    }
    match vmresume() {
        Ok(()) => {},
        Err(_) => {
            let error = vmread(vmcs::ro::VM_INSTRUCTION_ERROR).expect("failed to read error code");
            panic!("vmresume failed ({error})");
        },
    }
}
