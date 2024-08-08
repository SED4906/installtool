use core::ptr::addr_of;

use x86::bits64::registers::rsp;
use x86::bits64::vmx::{vmclear, vmlaunch, vmptrld, vmread, vmresume, vmwrite, vmxon};

use x86::controlregs::{cr0_write, cr3, Cr0};
use x86::msr::{IA32_PAT, IA32_VMX_BASIC, IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1, IA32_VMX_ENTRY_CTLS, IA32_VMX_EPT_VPID_CAP, IA32_VMX_EXIT_CTLS, IA32_VMX_PINBASED_CTLS, IA32_VMX_PROCBASED_CTLS, IA32_VMX_PROCBASED_CTLS2, IA32_VMX_VMFUNC};
use x86::segmentation::{cs, ds, es, fs, gs, ss};
use x86::task::tr;
use x86::vmx::{vmcs, VmFail};
use x86::{controlregs::{cr0, cr4, cr4_write, Cr4}, cpuid::cpuid, msr::rdmsr};
use x86_64::instructions::tables::{sgdt, sidt};
use x86_64::registers::control::Efer;

use crate::arch::amd64::descriptors::TSS;
use crate::arch::cpu;
use crate::arch::cpu::mm::Freelist;
use crate::println;

pub unsafe fn init() {
    assert!(cpuid!(1).ecx & (1<<5) != 0, "vmx not supported");
    unsafe { cr4_write(cr4() | Cr4::CR4_ENABLE_VMX) }
    let vmcs_revision_id = rdmsr(IA32_VMX_BASIC);
    
    println!("starting vm...");

    cr0_write(Cr0::from_bits_unchecked((cr0().bits() as u64 | rdmsr(IA32_VMX_CR0_FIXED0)) as usize));
    cr4_write(Cr4::from_bits_unchecked((cr4().bits() as u64 | rdmsr(IA32_VMX_CR4_FIXED0)) as usize));

    let vmcs_root = Freelist::alloc::<u32>() as u64;
    let vmcs_guest = Freelist::alloc::<u32>() as u64;
    let guest_pml4 = Freelist::alloc::<u64>() as u64;

    println!("{vmcs_root:x} {vmcs_guest:x} {vmcs_revision_id:x}");
    *(vmcs_root as *mut u32) = vmcs_revision_id as u32;
    *(vmcs_guest as *mut u32) = vmcs_revision_id as u32;
    println!("vmxon?");
    vmxon(vmcs_root).expect("vmxon failed");
    println!("vmclear?");
    vmclear(vmcs_guest).expect("vmclear failed");
    println!("vmptrld?");
    vmptrld(vmcs_guest).expect("vmptrld failed");

    vmwrite(vmcs::host::CR3, cr3());
    vmwrite(vmcs::host::CR0, cr0().bits() as u64);
    vmwrite(vmcs::host::CR4, cr4().bits() as u64);
    vmwrite(vmcs::host::RIP, vmexit_handler as u64);
    vmwrite(vmcs::host::RSP, rsp() - 0x80);
    vmwrite(vmcs::host::GDTR_BASE, sgdt().base.as_u64());
    vmwrite(vmcs::host::IDTR_BASE, sidt().base.as_u64());
    vmwrite(vmcs::host::TR_BASE, addr_of!(TSS) as u64);
    vmwrite(vmcs::host::TR_SELECTOR, (tr().bits() & 0xF8) as u64);
    vmwrite(vmcs::host::CS_SELECTOR, cs().bits() as u64);
    vmwrite(vmcs::host::DS_SELECTOR, ds().bits() as u64);
    vmwrite(vmcs::host::ES_SELECTOR, es().bits() as u64);
    vmwrite(vmcs::host::FS_SELECTOR, fs().bits() as u64);
    vmwrite(vmcs::host::GS_SELECTOR, gs().bits() as u64);
    vmwrite(vmcs::host::SS_SELECTOR, ss().bits() as u64);
    vmwrite(vmcs::host::IA32_EFER_FULL, Efer::read_raw());
    vmwrite(vmcs::host::IA32_PAT_FULL, rdmsr(IA32_PAT));

    vmwrite(vmcs::host::IA32_SYSENTER_CS, 0);
    vmwrite(vmcs::host::IA32_SYSENTER_EIP, 0);
    vmwrite(vmcs::host::IA32_SYSENTER_ESP, 0);
    vmwrite(vmcs::host::FS_BASE, 0);
    vmwrite(vmcs::host::GS_BASE, 0);
    vmwrite(vmcs::control::VMENTRY_CONTROLS, {
        let mut adjust = 1<<2;
        adjust &= rdmsr(IA32_VMX_ENTRY_CTLS) >> 32;
        adjust |= rdmsr(IA32_VMX_ENTRY_CTLS) & 0xFFFFFFFF;
        adjust
    });
    vmwrite(vmcs::control::PINBASED_EXEC_CONTROLS,{
        let mut adjust = 1;
        adjust &= rdmsr(IA32_VMX_PINBASED_CTLS) >> 32;
        adjust |= rdmsr(IA32_VMX_PINBASED_CTLS) & 0xFFFFFFFF;
        adjust
    });
    vmwrite(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,{
        let mut adjust = 3<<15 | 1<<31;
        adjust &= rdmsr(IA32_VMX_PROCBASED_CTLS) >> 32;
        adjust |= rdmsr(IA32_VMX_PROCBASED_CTLS) & 0xFFFFFFFF;
        adjust
    });
    vmwrite(vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS,{
        let mut adjust = 1<<1|1<<7;
        adjust &= rdmsr(IA32_VMX_PROCBASED_CTLS2) >> 32;
        adjust |= rdmsr(IA32_VMX_PROCBASED_CTLS2) & 0xFFFFFFFF;
        adjust
    });
    vmwrite(vmcs::control::VMEXIT_CONTROLS, {
        let mut adjust = 1<<2;
        adjust &= rdmsr(IA32_VMX_EXIT_CTLS) >> 32;
        adjust |= rdmsr(IA32_VMX_EXIT_CTLS) & 0xFFFFFFFF;
        adjust
    });
    vmwrite(vmcs::guest::LINK_PTR_FULL, 0xFFFFFFFFFFFFFFFF);
    //vmwrite(vmcs::control::EXCEPTION_BITMAP, 0xFFFFFFFF);

    vmwrite(vmcs::guest::CR0, 0x60000010);
    vmwrite(vmcs::guest::CR4, 0);
    vmwrite(vmcs::guest::CR3, 0);
    vmwrite(vmcs::guest::GDTR_BASE, 0);
    vmwrite(vmcs::guest::GDTR_LIMIT, 0);
    vmwrite(vmcs::guest::IDTR_BASE, 0);
    vmwrite(vmcs::guest::IDTR_LIMIT, 0);
    vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, 3 | (1<<4) | (1<<7));
    vmwrite(vmcs::guest::CS_BASE, 0);
    vmwrite(vmcs::guest::CS_LIMIT, 0xFFFF);
    vmwrite(vmcs::guest::CS_SELECTOR, 0);
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
    vmwrite(vmcs::guest::RFLAGS, 2);
    vmwrite(vmcs::guest::IA32_SYSENTER_CS, 0);
    vmwrite(vmcs::guest::IA32_SYSENTER_EIP, 0);
    vmwrite(vmcs::guest::IA32_SYSENTER_ESP, 0);
    vmwrite(vmcs::control::EPTP_FULL, guest_pml4);

    println!("MSR_IA32_VMX_PINBASED_CTLS {:x}",rdmsr(IA32_VMX_PINBASED_CTLS));
    println!("MSR_IA32_VMX_PROCBASED_CTLS {:x}",rdmsr(IA32_VMX_PROCBASED_CTLS));
    println!("MSR_IA32_VMX_PROCBASED_CTLS2 {:x}",rdmsr(IA32_VMX_PROCBASED_CTLS2));
    println!("MSR_IA32_VMX_EXIT_CTLS {:x}",rdmsr(IA32_VMX_EXIT_CTLS));
    println!("MSR_IA32_VMX_ENTRY_CTLS {:x}",rdmsr(IA32_VMX_ENTRY_CTLS));
    println!("MSR_IA32_VMX_EPT_VPID_CAP {:x}",rdmsr(IA32_VMX_EPT_VPID_CAP));
    println!("MSR_IA32_VMX_VMFUNC {:x}",rdmsr(IA32_VMX_VMFUNC));
    println!("MSR_IA32_CR0_FIXED0 {:x}",rdmsr(IA32_VMX_CR0_FIXED0));
    println!("MSR_IA32_CR0_FIXED1 {:x}",rdmsr(IA32_VMX_CR0_FIXED1));
    println!("MSR_IA32_CR4_FIXED0 {:x}",rdmsr(IA32_VMX_CR4_FIXED0));
    println!("MSR_IA32_CR4_FIXED1 {:x}",rdmsr(IA32_VMX_CR4_FIXED1));
    println!();
    println!("host cr0 {:x}",cr0());
    println!("host cr3 {:x}",cr3());
    println!("host cr4 {:x}",cr4());
    println!("host efer {:x}", Efer::read_raw());
    println!("host fs_base {:x}", 0);
    println!("host gdtr_base {:x}", sgdt().base.as_u64());
    println!("host gs_base {:x}", 0);
    println!("host idtr_base {:x}", sidt().base.as_u64());
    println!("host pat {:x}", rdmsr(IA32_PAT));
    println!("host rip {:x}", vmexit_handler as u64);
    println!("host rsp {:x}", rsp() - 0x80);
    println!("host cs {:x}", cs());
    println!("host ds {:x}", ds());
    println!("host es {:x}", es());
    println!("host fs {:x}", fs());
    println!("host gs {:x}", gs());
    println!("host ss {:x}", ss());
    println!("host cs_se {:x}", 0);
    println!("host eip_se {:x}", 0);
    println!("host esp_se {:x}", 0);
    println!("host tr_base {:x}", addr_of!(TSS) as u64);

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
    println!("vmexit");
    vmresume().expect("vmresume failed");
}
