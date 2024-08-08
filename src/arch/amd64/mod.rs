mod descriptors;
mod cpu_interrupts;
pub mod vmx;
pub mod mm;

use core::arch::asm;

pub fn halt_forever() -> ! {
    loop {
        unsafe{asm!("cli;hlt")};
    }
}

pub fn wait_forever() -> ! {
    loop {
        unsafe{asm!("hlt")};
    }
}

pub fn init() {
    descriptors::init();
    mm::init();
}
