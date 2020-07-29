use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Write;

enum Status {
    Continue,
    Stop,
}

#[derive(Debug)]
enum MvArg {
    A,
    B,
    C,
    D,
    E,
    F,
    PtrC,
}

#[derive(Debug)]
enum Mv32Arg {
    La,
    Lb,
    Lc,
    Ld,
    Ptr,
    Pc,
}

#[derive(Debug)]
enum Instr {
    Add,
    Aptr(u8),
    Cmp,
    Halt,
    Jez(u32),
    Jnz(u32),
    Mv(MvArg, MvArg),
    Mv32(Mv32Arg, Mv32Arg),
    Mvi(MvArg, u8),
    Mvi32(Mv32Arg, u32),
    Out,
    Sub,
    Xor,
}

struct TomtelVm<W>
where
    W: Write,
{
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
    la: u32,
    lb: u32,
    lc: u32,
    ld: u32,
    ptr: u32,
    pc: u32,
    output: W,
    memory: Vec<u8>,
}

impl<W> TomtelVm<W>
where
    W: Write,
{
    fn new(output: W, memory: &[u8]) -> Self {
        Self {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            e: 0,
            f: 0,
            la: 0,
            lb: 0,
            lc: 0,
            ld: 0,
            ptr: 0,
            pc: 0,
            output,
            memory: memory.to_vec(),
        }
    }

    fn output(self) -> W {
        self.output
    }

    fn run(&mut self) {
        loop {
            let (instr, size) = self.fetch_instr();
            self.pc += size as u32;
            match self.exec(instr) {
                Status::Stop => return,
                Status::Continue => continue,
            }
        }
    }

    fn fetch_instr(&self) -> (Instr, u8) {
        let b = self.memory[self.pc as usize];

        match b {
            0x01 => (Instr::Halt, 1),
            0x02 => (Instr::Out, 1),
            0x21 => (Instr::Jez(self.imm32()), 5),
            0x22 => (Instr::Jnz(self.imm32()), 5),
            0xC1 => (Instr::Cmp, 1),
            0xC2 => (Instr::Add, 1),
            0xC3 => (Instr::Sub, 1),
            0xC4 => (Instr::Xor, 1),
            0xE1 => (Instr::Aptr(self.imm8()), 2),
            b => self.parse_mv(b),
        }
    }

    fn parse_mv(&self, instr: u8) -> (Instr, u8) {
        let opcode = (instr & 0b11000000) >> 6;
        let dest = (instr & 0b00111000) >> 3;
        let src = instr & 0b00000111;

        match (opcode, src) {
            (0b01, 0) => (Instr::Mvi(Self::parse_mv_arg(dest), self.imm8()), 2),
            (0b01, src) => (
                Instr::Mv(Self::parse_mv_arg(dest), Self::parse_mv_arg(src)),
                1,
            ),
            (0b10, 0) => (Instr::Mvi32(Self::parse_mv32_arg(dest), self.imm32()), 5),
            (0b10, src) => (
                Instr::Mv32(Self::parse_mv32_arg(dest), Self::parse_mv32_arg(src)),
                1,
            ),
            _ => unreachable!(),
        }
    }

    fn parse_mv_arg(arg: u8) -> MvArg {
        match arg {
            1 => MvArg::A,
            2 => MvArg::B,
            3 => MvArg::C,
            4 => MvArg::D,
            5 => MvArg::E,
            6 => MvArg::F,
            7 => MvArg::PtrC,
            _ => unreachable!(),
        }
    }

    fn parse_mv32_arg(arg: u8) -> Mv32Arg {
        match arg {
            1 => Mv32Arg::La,
            2 => Mv32Arg::Lb,
            3 => Mv32Arg::Lc,
            4 => Mv32Arg::Ld,
            5 => Mv32Arg::Ptr,
            6 => Mv32Arg::Pc,
            _ => unreachable!(),
        }
    }

    fn imm8(&self) -> u8 {
        self.memory[self.pc as usize + 1]
    }

    fn imm32(&self) -> u32 {
        let mut rdr = &self.memory[self.pc as usize + 1..];
        rdr.read_u32::<LittleEndian>().unwrap_or(0)
    }

    fn exec(&mut self, instr: Instr) -> Status {
        match instr {
            Instr::Add => self.a = self.a.overflowing_add(self.b).0,
            Instr::Aptr(imm8) => self.ptr += imm8 as u32,
            Instr::Cmp => self.f = if self.a == self.b { 0 } else { 1 },
            Instr::Halt => return Status::Stop,
            Instr::Jez(imm32) => {
                if self.f == 0 {
                    self.pc = imm32
                }
            }
            Instr::Jnz(imm32) => {
                if self.f != 0 {
                    self.pc = imm32
                }
            }
            Instr::Mv(dest, src) => *self.get_reg8_mut_ref(dest) = self.get_reg8_value(src),
            Instr::Mv32(dest, src) => *self.get_reg32_mut_ref(dest) = self.get_reg32_value(src),
            Instr::Mvi(dest, imm8) => *self.get_reg8_mut_ref(dest) = imm8,
            Instr::Mvi32(dest, imm32) => *self.get_reg32_mut_ref(dest) = imm32,
            Instr::Out => {
                let _ = self.output.write(&[self.a]);
            }
            Instr::Sub => self.a = self.a.overflowing_sub(self.b).0,
            Instr::Xor => self.a ^= self.b,
        }

        Status::Continue
    }

    fn get_reg8_value(&self, arg: MvArg) -> u8 {
        match arg {
            MvArg::A => self.a,
            MvArg::B => self.b,
            MvArg::C => self.c,
            MvArg::D => self.d,
            MvArg::E => self.e,
            MvArg::F => self.f,
            MvArg::PtrC => {
                let idx = self.ptr + self.c as u32;
                self.memory[idx as usize]
            }
        }
    }

    fn get_reg8_mut_ref(&mut self, arg: MvArg) -> &mut u8 {
        match arg {
            MvArg::A => &mut self.a,
            MvArg::B => &mut self.b,
            MvArg::C => &mut self.c,
            MvArg::D => &mut self.d,
            MvArg::E => &mut self.e,
            MvArg::F => &mut self.f,
            MvArg::PtrC => {
                let idx = self.ptr + self.c as u32;
                self.memory
                    .get_mut(idx as usize)
                    .expect("invalid memory access")
            }
        }
    }

    fn get_reg32_value(&self, arg: Mv32Arg) -> u32 {
        match arg {
            Mv32Arg::La => self.la,
            Mv32Arg::Lb => self.lb,
            Mv32Arg::Lc => self.lc,
            Mv32Arg::Ld => self.ld,
            Mv32Arg::Ptr => self.ptr,
            Mv32Arg::Pc => self.pc,
        }
    }

    fn get_reg32_mut_ref(&mut self, arg: Mv32Arg) -> &mut u32 {
        match arg {
            Mv32Arg::La => &mut self.la,
            Mv32Arg::Lb => &mut self.lb,
            Mv32Arg::Lc => &mut self.lc,
            Mv32Arg::Ld => &mut self.ld,
            Mv32Arg::Ptr => &mut self.ptr,
            Mv32Arg::Pc => &mut self.pc,
        }
    }
}

pub fn run_payload_program(program: &[u8]) -> Vec<u8> {
    let out = vec![];
    let mut vm = TomtelVm::new(out, program);
    vm.run();
    vm.output()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_world() {
        let program = vec![
            0x50, 0x48, 0xC2, 0x02, 0xA8, 0x4D, 0x00, 0x00, 0x00, 0x4F, 0x02, 0x50, 0x09, 0xC4,
            0x02, 0x02, 0xE1, 0x01, 0x4F, 0x02, 0xC1, 0x22, 0x1D, 0x00, 0x00, 0x00, 0x48, 0x30,
            0x02, 0x58, 0x03, 0x4F, 0x02, 0xB0, 0x29, 0x00, 0x00, 0x00, 0x48, 0x31, 0x02, 0x50,
            0x0C, 0xC3, 0x02, 0xAA, 0x57, 0x48, 0x02, 0xC1, 0x21, 0x3A, 0x00, 0x00, 0x00, 0x48,
            0x32, 0x02, 0x48, 0x77, 0x02, 0x48, 0x6F, 0x02, 0x48, 0x72, 0x02, 0x48, 0x6C, 0x02,
            0x48, 0x64, 0x02, 0x48, 0x21, 0x02, 0x01, 0x65, 0x6F, 0x33, 0x34, 0x2C,
        ];
        let out = vec![];
        let mut vm = TomtelVm::new(out, &program);
        vm.run();
        let output = String::from_utf8(vm.output());

        assert_eq!(output.unwrap().as_str(), "Hello, world!");
    }
}
