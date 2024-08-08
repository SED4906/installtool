pub static FONT: &[u8] = include_bytes!("FM-TOWNS.F08");
const FONT_HEIGHT: usize = 8;
//pub static FONT: &[u8] = include_bytes!("unifont.bin");
use core::usize;

use spin::Mutex;

static FRAMEBUFFER_REQUEST: limine::request::FramebufferRequest =
    limine::request::FramebufferRequest::new();
pub static FRAMEBUFFER: Mutex<Option<Framebuffer>> = Mutex::new(None);
pub fn framebuffer_init() {
    if let Some(framebuffer_response) = FRAMEBUFFER_REQUEST.get_response() {
        // Get the first framebuffer's information.
        let response = &framebuffer_response
            .framebuffers()
            .next()
            .unwrap_or_else(|| crate::cpu::halt_forever());
        let mut framebuffer = FRAMEBUFFER.lock();
        *framebuffer = Some(Framebuffer {
            address: response.addr() as *mut u32,
            pitch: response.pitch() as usize,
            width: response.width() as usize,
            height: response.height() as usize,
        });
    } else {
        crate::cpu::halt_forever()
    }
}

pub struct Framebuffer {
    pub address: *mut u32,
    pub pitch: usize,
    pub width: usize,
    pub height: usize,
}

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

impl Framebuffer {
    pub fn pixel(&self, x: usize, y: usize, color: u32) {
        let pixel_offset = y * self.pitch / 4 + x;
        unsafe {
            if color & 0xFF000000 == 0xFF000000 {
                *(self.address.add(pixel_offset)) = color;
            } else {
                let current = *(self.address.add(pixel_offset));
                let alpha = ((color & 0xFF000000) >> 24) as i32;
                let mut c0 = (color & 0xFF) as i32;
                let cc0 = (current & 0xFF) as i32;
                let mut c1 = ((color & 0xFF00) >> 8) as i32;
                let cc1 = ((current & 0xFF00) >> 8) as i32;
                let mut c2 = ((color & 0xFF0000) >> 16) as i32;
                let cc2 = ((current & 0xFF0000) >> 16) as i32;
                c0 = (cc0 * 255 + alpha * (c0 - cc0)) / 255;
                c1 = (cc1 * 255 + alpha * (c1 - cc1)) / 255;
                c2 = (cc2 * 255 + alpha * (c2 - cc2)) / 255;
                *(self.address.add(pixel_offset)) = (c0 & 0xFF) as u32
                    | (((c1 & 0xFF) as u32) << 8)
                    | (((c2 & 0xFF) as u32) << 16)
                    | 0xFF000000;
            }
        }
    }

    pub fn read_pixel(&self, x: usize, y: usize) -> u32 {
        let pixel_offset = y * self.pitch / 4 + x;
        return unsafe { *(self.address.add(pixel_offset)) };
    }

    pub fn rect(&self, x0: usize, y0: usize, x1: usize, y1: usize, border: u32, fill: u32) {
        for py in y0..=y1 {
            for px in x0..=x1 {
                if px == x0 || px == x1 || py == y0 || py == y1 {
                    self.pixel(px, py, border)
                } else {
                    self.pixel(px, py, fill)
                }
            }
        }
    }

    pub fn line(&self, x0: usize, y0: usize, x1: usize, y1: usize, color: u32) {
        let mut x0: isize = x0 as isize;
        let mut y0: isize = y0 as isize;
        let x1: isize = x1 as isize;
        let y1: isize = y1 as isize;
        let dx: isize = if x1 > x0 { x1 - x0 } else { x0 - x1 };
        let sx: isize = if x0 < x1 { 1 } else { -1 };
        let dy: isize = if y1 > y0 { y0 - y1 } else { y1 - y0 };
        let sy: isize = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;
        loop {
            self.pixel(x0.unsigned_abs(), y0.unsigned_abs(), color);
            if x0 == x1 && y0 == y1 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                if x0 == x1 {
                    break;
                }
                err += dy;
                x0 += sx;
            }
            if e2 <= dx {
                if y0 == y1 {
                    break;
                }
                err += dx;
                y0 += sy;
            }
        }
    }

    pub fn circle(&self, xc: usize, yc: usize, r: usize, color: u32) {
        let mut t1: isize = r as isize / 16;
        let mut x: isize = r as isize;
        let mut y: isize = 0;
        while x >= y {
            let xo = x as usize;
            let yo = y as usize;
            self.pixel(xc + xo, yc + yo, color);
            self.pixel(xc + xo, yc - yo, color);
            self.pixel(xc - xo, yc + yo, color);
            self.pixel(xc - xo, yc - yo, color);
            self.pixel(xc + yo, yc + xo, color);
            self.pixel(xc + yo, yc - xo, color);
            self.pixel(xc - yo, yc + xo, color);
            self.pixel(xc - yo, yc - xo, color);
            y += 1;
            t1 += y;
            let t2 = t1 - x;
            if t2 >= 0 {
                t1 = t2;
                x -= 1;
            }
        }
    }

    pub fn clear(&self, color: u32) {
        for y in 0..self.height {
            for x in 0..self.width {
                self.pixel(x, y, color)
            }
        }
    }

    pub fn character(&self, x: usize, y: usize, c: char, color: u32) {
        for py in y..y + FONT_HEIGHT {
            for px in x..x + 8 {
                if crate::gfx::FONT[(c as usize) * FONT_HEIGHT + py as usize - y as usize]
                    & (128 >> (px - x))
                    != 0
                {
                    self.pixel(px, py, color);
                } else {
                    self.pixel(px, py, color & 0xFF000000 | ((!color) & 0x00FFFFFF));
                }
            }
        }
    }

    pub fn string(
        &self,
        x: usize,
        y: usize,
        s: &str,
        wrap: Option<usize>,
        indent: Option<usize>,
        max_lines: Option<usize>,
        v_indent: Option<usize>, 
        color: u32,
    ) -> (usize, usize) {
        let mut line_length = indent.unwrap_or_default();
        let mut line = v_indent.unwrap_or_default();
        for c in s.chars() {
            match c as u32 {
                8 => line_length -= 1,
                9 => {
                    line_length += 8;
                    line_length &= !7;
                }
                13 => line_length = 0,
                10 => {
                    line_length = 0;
                    line += 1;
                }
                _ if (c as u32) < 256 => {
                    self.character(x + line_length * 8, y + line * 8, c, color);
                    line_length += 1;
                }
                _ => {
                    self.character(x + line_length * 8, y + line * 8, '?', color);
                    line_length += 1;
                }
            };
            if let Some(wrap) = wrap {
                if line_length >= wrap {
                    line_length = 0;
                    line += 1;
                }
            }
            if let Some(max_lines) = max_lines {
                if line > max_lines {
                    line = 0;
                    line_length = 0;
                }
            }
        }
        return (line_length, line);
    }
}
