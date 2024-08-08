use core::fmt;
use spin::Mutex;

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut col = COL.lock();
        let mut row = ROW.lock();
        if let Some(framebuffer) = crate::gfx::FRAMEBUFFER.lock().as_ref() {
            (*col, *row) = framebuffer.string(
                0,
                0,
                s,
                Some(framebuffer.width / 16),
                Some(*col),
                Some(framebuffer.height / 16),
                Some(*row),
                0xFFFFFFFF,
            );
        }
        Ok(())
    }
}

pub struct Writer {}
static WRITER: Mutex<Writer> = Mutex::new(Writer {});
pub static COL: Mutex<usize> = Mutex::new(0);
pub static ROW: Mutex<usize> = Mutex::new(0);

pub fn _print(args: fmt::Arguments) {
    // NOTE: Locking needs to happen around `print_fmt`, not `print_str`, as the former
    // will call the latter potentially multiple times per invocation.
    let mut writer = WRITER.lock();
    fmt::Write::write_fmt(&mut *writer, args).ok();
}

#[macro_export]
macro_rules! print {
    ($($t:tt)*) => { $crate::terminal::_print(format_args!($($t)*)) };
}

#[macro_export]
macro_rules! println {
    ()          => { $crate::print!("\n"); };
    // On nightly, `format_args_nl!` could also be used.
    ($($t:tt)*) => { $crate::print!("{}\n", format_args!($($t)*)) };
}
