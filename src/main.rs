#![feature(abi_x86_interrupt,slice_pattern,naked_functions)]
#![no_std]
#![no_main]

use arch::cpu;

mod gfx;
mod terminal;
mod arch;

#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    cpu::init();
    gfx::framebuffer_init();
    println!("Starting up...");
    if let Some(framebuffer) = gfx::FRAMEBUFFER.lock().as_ref() {
        framebuffer.rect(128, 128, 192, 192, 0xFFFF0000, 0x80FF0000);
        framebuffer.rect(136, 136, 200, 200, 0xFFFF8000, 0x80FF8000);
        framebuffer.rect(144, 144, 208, 208, 0xFF80FF00, 0x8080FF00);
        framebuffer.rect(152, 152, 216, 216, 0xFF00FF00, 0x8000FF00);
        framebuffer.rect(160, 160, 224, 224, 0xFF00FF80, 0x8000FF80);
        framebuffer.rect(168, 168, 232, 232, 0xFF0080FF, 0x800080FF);
        framebuffer.rect(176, 176, 240, 240, 0xFF0000FF, 0x800000FF);
        framebuffer.line(256, 256, 320, 384, 0xFF808080);
        framebuffer.line(256, 256, 384, 320, 0xFF808080);
    }
    cpu::vmx::init();

    cpu::wait_forever()
}

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    println!();
    println!("Computer over!");
    println!("{info}");
    if let Some(framebuffer) = crate::gfx::FRAMEBUFFER.lock().as_ref() {
        framebuffer.circle(framebuffer.width/2, framebuffer.height/2, 128, 0xFF808080);
        framebuffer.circle(framebuffer.width/2, framebuffer.height/2, 127, 0xFF808080);
        framebuffer.circle(framebuffer.width/2, framebuffer.height/2, 126, 0xFF808080);
        framebuffer.line(framebuffer.width/2-90, framebuffer.height/2-90,framebuffer.width/2+90, framebuffer.height/2+90, 0xFF808080);
        framebuffer.line(framebuffer.width/2-91, framebuffer.height/2-89,framebuffer.width/2+89, framebuffer.height/2+91, 0xFF808080);
        framebuffer.line(framebuffer.width/2-89, framebuffer.height/2-91,framebuffer.width/2+91, framebuffer.height/2+89, 0xFF808080);
    }
    cpu::halt_forever()
}