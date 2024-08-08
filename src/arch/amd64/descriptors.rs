use spin::Mutex;
use x86_64::instructions::tables::load_tss;
use x86_64::registers::segmentation::{Segment, SegmentSelector, CS, DS, SS};
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use x86_64::structures::idt::InterruptDescriptorTable;
use x86_64::structures::tss::TaskStateSegment;
use x86_64::PrivilegeLevel::Ring0;

use super::cpu_interrupts;

pub static GDT: Mutex<GlobalDescriptorTable> = Mutex::new(GlobalDescriptorTable::new());
pub static TSS: TaskStateSegment = TaskStateSegment::new();
pub static IDT: Mutex<InterruptDescriptorTable> = Mutex::new(InterruptDescriptorTable::new());

pub fn init() {
    let mut gdt = GDT.lock();
    gdt.append(Descriptor::kernel_code_segment());
    gdt.append(Descriptor::kernel_data_segment());
    gdt.append(Descriptor::tss_segment(&TSS));
    unsafe {
        gdt.load_unsafe();
        CS::set_reg(SegmentSelector::new(1, Ring0));
        load_tss(SegmentSelector::new(3, Ring0));
    }
    let mut idt = IDT.lock();
    idt.divide_error
        .set_handler_fn(cpu_interrupts::exception_no_err);
    idt.debug.set_handler_fn(cpu_interrupts::exception_no_err);
    idt.non_maskable_interrupt
        .set_handler_fn(cpu_interrupts::exception_no_err);
    idt.breakpoint
        .set_handler_fn(cpu_interrupts::exception_no_err);
    idt.overflow
        .set_handler_fn(cpu_interrupts::exception_no_err);
    idt.bound_range_exceeded
        .set_handler_fn(cpu_interrupts::exception_no_err);
    idt.invalid_opcode
        .set_handler_fn(cpu_interrupts::exception_no_err);
    idt.device_not_available
        .set_handler_fn(cpu_interrupts::exception_no_err);
    idt.double_fault
        .set_handler_fn(cpu_interrupts::exception_err_fatal);
    idt.invalid_tss
        .set_handler_fn(cpu_interrupts::exception_err);
    idt.segment_not_present
        .set_handler_fn(cpu_interrupts::exception_err);
    idt.stack_segment_fault
        .set_handler_fn(cpu_interrupts::exception_err);
    idt.general_protection_fault
        .set_handler_fn(cpu_interrupts::exception_err);
    idt.page_fault
        .set_handler_fn(cpu_interrupts::exception_page_fault);
    idt.x87_floating_point
        .set_handler_fn(cpu_interrupts::exception_no_err);
    idt.alignment_check
        .set_handler_fn(cpu_interrupts::exception_err);
    idt.machine_check
        .set_handler_fn(cpu_interrupts::exception_no_err_fatal);
    idt.simd_floating_point
        .set_handler_fn(cpu_interrupts::exception_no_err);
    idt.virtualization
        .set_handler_fn(cpu_interrupts::exception_no_err);
    idt.cp_protection_exception
        .set_handler_fn(cpu_interrupts::exception_err);
    idt.hv_injection_exception
        .set_handler_fn(cpu_interrupts::exception_no_err);
    idt.vmm_communication_exception
        .set_handler_fn(cpu_interrupts::exception_err);
    idt.security_exception
        .set_handler_fn(cpu_interrupts::exception_err);
    unsafe {
        idt.load_unsafe();
    }
}
