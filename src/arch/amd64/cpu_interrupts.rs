use x86::controlregs::cr2;
use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

pub extern "x86-interrupt" fn exception_no_err(_stack: InterruptStackFrame) {
    panic!("Unhandled Exception")
} 

pub extern "x86-interrupt" fn exception_err(_stack: InterruptStackFrame, error_code: u64) {
    panic!("Unhandled Exception ({error_code:x})")
} 

pub extern "x86-interrupt" fn exception_err_fatal(_stack: InterruptStackFrame, error_code: u64) -> ! {
    panic!("Fatal exception ({error_code:x})")
} 

pub extern "x86-interrupt" fn exception_no_err_fatal(_stack: InterruptStackFrame) -> ! {
    panic!("Fatal exception")
} 

pub extern "x86-interrupt" fn exception_page_fault(_stack: InterruptStackFrame, error_code: PageFaultErrorCode) {
    panic!("Page fault exception ({}) @{:x}", error_code.bits(), unsafe { cr2() })
} 