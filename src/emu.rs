use std::{convert::TryInto, num::TryFromIntError};

use dynasmrt::{relocations::Relocation, Assembler};
use memmap2::Mmap;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::PcodeCacheOnlyTranslator;

use crate::{Address, OpCode, PcodeOp, Varnode};

/// single pcode translate
pub trait PcodeTranslator: std::fmt::Debug {
    type Reloc: Relocation;
    type Mem: Memory;

    fn int_add(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    // todo: other operations..
    fn copy(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn load(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn store(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn branch(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn cbranch(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn branchInd(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;


    fn intXor(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn intAnd(
    &mut self,
    ops: &mut Assembler<Self::Reloc>,
    mem: &Self::Mem,
    inputs: &[&dyn Varnode],
    out: &dyn Varnode,
    ) -> Result<()>;
    fn intOr(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn intLeft(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn intRight(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn intSright(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn intMult(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn intDiv(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn intRem(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn intSdiv(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn intSrem(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn boolNegate(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn boolXor(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn boolAnd(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn boolOr(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;
    fn floatEqual(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        inputs: &[&dyn Varnode],
        out: &dyn Varnode,
    ) -> Result<()>;

    fn translate_pcode(
        &mut self,
        ops: &mut Assembler<Self::Reloc>,
        mem: &Self::Mem,
        pcode: &dyn PcodeOp,
    ) -> Result<()> {
        use OpCode::*;

        match pcode.opcode() {
            IntAdd => {
                let inputs = pcode.inputs();
                let output = pcode.output();

                // without output, IntAdd takes no effect then
                if output.is_none() {
                    return Ok(());
                }

                let output = output.unwrap();
                self.int_add(ops, mem, &inputs, output)?;
            }
            Copy => {
                let inputs = pcode.inputs();
                let output = pcode.output();

                if output.is_none() {
                    return Ok(());
                }

                let output = output.unwrap();
                self.copy(ops, mem, &inputs, output)?;
            }
            Load => {
                let inputs = pcode.inputs();
                let output = pcode.output();

                if output.is_none() {
                    return Ok(());
                }

                let output = output.unwrap();
                self.load(ops, mem, &inputs, output)?;

            }
            Store => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return Ok(());
                }
                let output = output.unwrap();
                self.store(ops, mem, &inputs, output);
            }
            Branch => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    let output = output.unwrap();
                    self.branch(ops, mem, &inputs, output);
                }
                return Ok(());
            }
            Cbranch => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return Ok(());
                }
                let output = output.unwrap();
                self.cbranch(ops, mem, &inputs, output);
            }
            BranchInd => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    let output = output.unwrap();
                    self.branchInd(ops, mem, &inputs, output);
                }
                return Ok(());
            }
            IntXor => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return Ok(());
                }
                let output = output.unwrap();
                self.intXor(ops, mem, &inputs, output);
            }
            IntAdd => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.intAnd(ops, mem, &inputs, output);
            }
            IntOr => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.intOr(ops, mem, &inputs, output);
            }
            IntLeft => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.intLeft(ops, mem, &inputs, output);
            }
            IntRight => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.intRight(ops, mem, &inputs, output);
            }
            IntSRight => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.intSright(ops, mem, &inputs, output);
            }
            IntMult => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.intMult(ops, mem, &inputs, output);
            }
            IntDiv => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.intDiv(ops, mem, &inputs, output);
            }
            IntRem => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.intRem(ops, mem, &inputs, output);
            }
            IntSDiv => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.intSdiv(ops, mem, &inputs, output);
            }
            IntSRem => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.intSrem(ops, mem, &inputs, output);
            }
            BoolNegate => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.boolNegate(ops, mem, &inputs, output);
            }
            BoolXor => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.boolXor(ops, mem, &inputs, output);
            }
            BoolAnd => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.boolAnd(ops, mem, &inputs, output);
            }
            BoolOr => {
                let inputs = pcode.inputs();
                let output = pcode.output();
                if output.is_none() {
                    return  Ok(());
                }
                let output = output.unwrap();
                self.boolOr(ops, mem, &inputs, output);
            }







            _ => todo!("other opcodes"),
        }
        todo!()
    }
}

#[derive(Debug)]
pub enum EmuError {
    /// Cache-only translator requires every address is in the cache. If not, this error indicates
    /// that it is unable to continue execution.
    NotInCache(usize),
    /// This address cannot be translated into target memory addressing.
    /// Address is represented by (space, offset)
    UnknownAddr((String, usize)),
    /// Host addressing is not enough for target machine.
    NotEnoughAddressing(TryFromIntError),
}

// TODO: implement Error for EmuError

pub type Result<T> = std::result::Result<T, EmuError>;

pub trait Memory: std::fmt::Debug {
    /// This memory's actual addressing
    type MemAddr;

    /// Translate the pcode addr into this memory's addressing
    fn translate(&self, addr: &dyn Address) -> Result<Self::MemAddr>;
}

/// Emulator Memory
/// `BlockTranslator` is responsible for translating a single block into executable pcode
pub trait BlockTranslator<Mem: Memory>: std::fmt::Debug {
    fn translate(&mut self, mem: &mut Mem, addr: usize) -> Result<*const u8>;
}

#[derive(Debug)]
pub struct Emulator<Trans, Mem>
where
    Trans: BlockTranslator<Mem>,
    Mem: Memory,
{
    /// translator used to translate the blocks
    trans: Trans,
    /// internal memory implementation
    mem: Mem,
}

impl<Trans, Mem> Emulator<Trans, Mem>
where
    Trans: BlockTranslator<Mem>,
    Mem: Memory,
{
    pub fn new(trans: Trans, mem: Mem) -> Self {
        Self { trans, mem }
    }

    /// Run until the end of the program
    pub fn run(&mut self, entry: usize) -> Result<()> {
        // translate the fall back block then call it.
        // Note that only the first block should be reside in a call, as it can be returned.
        let entry_block = self.trans.translate(&mut self.mem, entry)?;
        let entry_func: extern "C" fn() = unsafe { std::mem::transmute(entry_block) };
        entry_func();
        Ok(())
    }
}

/// Plain memory that gets mapped into the system already.
#[derive(Debug)]
pub struct MemMappedMemory {
    /// vec of (begin, size). All these memories are actually mapped.
    regions: Vec<Mmap>,
    /// the base of the register
    reg_base: usize,
}

impl MemMappedMemory {
    pub fn new(reg_base: usize) -> Self {
        Self {
            reg_base,
            regions: vec![],
        }
    }
}

impl Memory for MemMappedMemory {
    type MemAddr = usize;

    fn translate(&self, addr: &dyn Address) -> Result<Self::MemAddr> {
        let offset: usize = addr
            .offset()
            .try_into()
            .map_err(|e| EmuError::NotEnoughAddressing(e))?;

        match addr.space().as_str() {
            "register" => Ok(offset + self.reg_base),
            "ram" => Ok(offset),
            _ => Err(EmuError::UnknownAddr((addr.space(), offset))),
        }
    }
}
