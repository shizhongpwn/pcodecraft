use super::{BlockTranslator, MemMappedMemory, PcodeTranslator, Result};
use crate::{emu::Memory, PcodeOp};
use dynasm::dynasm;
use dynasmrt::{
    x64::{self, X64Relocation},
    AssemblyOffset, DynasmApi, ExecutableBuffer,
};
use std::collections::{BTreeMap, HashMap};
use term::color::WHITE;

/// Jitting pcode translator. Translate pcode by jitting it into x86 asm.
#[derive(Debug)]
pub struct X64JitPcodeTranslator {
    /// register base address
    reg_base: usize,
}

impl PcodeTranslator for X64JitPcodeTranslator {
    type Mem = MemMappedMemory;
    type Reloc = X64Relocation;

    fn int_add(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax // rax is the accumulation value
        );

        for input in inputs {
            if &input.addr().space() == "const" {
                // add a const
                let value = input.addr().offset();
                dynasm!(ops
                    ; add rax, value as _
                );
            } else {
                let input_addr = mem.translate(input.addr())?;
                let size = input.size();
                match size {
                    1 => {
                        dynasm!(ops
                            ; xor rdx, rdx
                            ; mov dl, BYTE [input_addr as _]
                            ; add rax, rdx
                        );
                    }
                    2 => {
                        dynasm!(ops
                            ; xor rdx, rdx
                            ; mov dx, WORD [input_addr as _]
                            ; add rax, rdx
                        );
                    }
                    4 => {
                        dynasm!(ops
                            ; xor rdx, rdx
                            ; mov edx, DWORD [input_addr as _]
                            ; add rax, rdx
                        );
                    }
                    8 => {
                        dynasm!(ops
                            ; add rax, QWORD [input_addr as _]
                        );
                    }
                    _ => unreachable!(),
                }
            }
        }

        let out_addr = mem.translate(out.addr())?;
        let size = out.size();

        match size {
            1 => {
                dynasm!(ops
                    ; mov BYTE [out_addr as _], al
                );
            }
            2 => {
                dynasm!(ops
                    ; mov WORD [out_addr as _], ax
                );
            }
            4 => {
                dynasm!(ops
                    ; mov DWORD [out_addr as _], eax
                );
            }
            8 => {
                dynasm!(ops
                    ; mov QWORD [out_addr as _], rax
                );
            }
            _ => unreachable!(),
        }

        Ok(())
    }
    fn copy(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax // rax is the accumulation value
        );

        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            let out_addr = mem.translate(out.addr())?;
            dynasm!(ops
                    ; add rax, value as _
                    ; mov QWORD [out_addr as _], rax
                );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            let size = inputs[0].size();
            let out_addr = mem.translate(out.addr())?;
            match size {
                1 => {
                    dynasm!(ops
                    ; mov al, BYTE [input_addr as _]
                    ; mov BYTE [out_addr as _], al
                )
                }
                2 => {
                    dynasm!(ops
                    ; mov ax, WORD [input_addr as _]
                    ; mov WORD [out_addr as _], ax
                )
                }
                4 => {
                    dynasm!(ops
                    ; mov eax, DWORD [input_addr as _]
                    ; mov DWORD [out_addr as _], eax
                )
                }
                8 => {
                    dynasm!(ops
                    ; mov rax, QWORD [input_addr as _]
                    ; mov QWORD [out_addr as _], rax
                )
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }
    fn load(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        let input_addr = mem.translate(inputs[0].addr())?;
        let out_addr = mem.translate(out.addr())?;
        dynasm!(ops
            ; mov rax, QWORD [input_addr as _]
            ; mov rax, QWORD [rax]
            ; mov QWORD [out_addr as _], rax
        );
        Ok(())
    }
    fn store(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        let value = inputs[0].addr().offset();
        let out_addr = mem.translate(out.addr())?;
        dynasm!(ops
            ; mov rax, value as _
            ; mov QWORD [out_addr as _], rax
        );
        Ok(())
    }
    fn branch(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        let input_addr = mem.translate(inputs[0].addr())?;
        todo!();// the way to finish jz

    }
    fn cbranch(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        todo!();
    }
    fn branchInd(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        todo!();
    }

    fn intXor(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rbx, rbx
        );
        let out_addr = mem.translate(out.addr())?;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            dynasm!(ops
                ; mov rax, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            dynasm!(ops
                ; mov rax, QWORD [input_addr as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov rbx, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov rbx, QWORD [input_addr as _]
            );
        }
        dynasm!(ops
            ; xor rax, rbx
            ; mov QWORD [out_addr as _], rax
        );
        Ok(())
    }
    fn intAnd(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rbx, rbx
        );
        let out_addr = mem.translate(out.addr())?;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            dynasm!(ops
                ; mov rax, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            dynasm!(ops
                ; mov rax, QWORD [input_addr as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov rbx, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov rbx, QWORD [input_addr as _]
            );
        }
        dynasm!(ops
            ; and rax, rbx
            ; mov QWORD [out_addr as _], rax
        );
        Ok(())
    }
    fn intOr(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rbx, rbx
        );
        let out_addr = mem.translate(out.addr())?;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            dynasm!(ops
                ; mov rax, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            dynasm!(ops
                ; mov rax, QWORD [input_addr as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov rbx, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov rbx, QWORD [input_addr as _]
            );
        }
        dynasm!(ops
            ; or rax, rbx
            ; mov QWORD [out_addr as _], rax
        );
        Ok(())
    }
    fn intLeft(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rcx, rcx
        );
        let out_addr = mem.translate(out.addr())?;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            dynasm!(ops
                ; mov rax, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            dynasm!(ops
                ; mov rax, QWORD [input_addr as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov cl, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov cl, BYTE [input_addr as _]
            );
        }
        dynasm!(ops
            ; shl rax, cl
            ; mov QWORD [out_addr as _], rax
        );
        Ok(())
    }
    fn intRight(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rcx, rcx
        );
        let out_addr = mem.translate(out.addr())?;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            dynasm!(ops
                ; mov rax, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            dynasm!(ops
                ; mov rax, QWORD [input_addr as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov cl, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov cl, BYTE [input_addr as _]
            );
        }
        dynasm!(ops
            ; shr rax, cl
            ; mov QWORD [out_addr as _], rax
        );
        Ok(())
    }
    fn intSright(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rcx, rcx
        );
        let out_addr = mem.translate(out.addr())?;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            dynasm!(ops
                ; mov rax, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            dynasm!(ops
                ; mov rax, QWORD [input_addr as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov cl, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov cl, BYTE [input_addr as _]
            );
        }
        dynasm!(ops
            ; sar rax, cl
            ; mov QWORD [out_addr as _], rax
        );
        Ok(())
    }
    fn intMult(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rbx, rbx
        );
        let out_addr = mem.translate(out.addr())?;
        let out_addr_low = out_addr + 8;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            dynasm!(ops
                ; mov rax, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            dynasm!(ops
                ; mov rax, QWORD [input_addr as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov rbx, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov rbx, QWORD [input_addr as _]
            );
        }

        dynasm!(ops
            ; mul rbx
            ; mov QWORD [out_addr as _], rdx
            ; mov QWORD [out_addr_low as _], rax
        );
        Ok(())
    }
    fn intDiv(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rdx, rdx
            ; xor rbx, rbx
        );
        let out_addr = mem.translate(out.addr())?;
        let out_addr_low = out_addr + 8;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            let value_high = value & 0x00000000;
            let value_low = value & 0xFFFFFFFF;
            dynasm!(ops
                ; mov rdx, value_high as _
                ; mov rax, value_low as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            let input_addr_low = input_addr + 8;
            dynasm!(ops
                ; mov rdx, QWORD [input_addr as _]
                ; mov rax, QWORD [input_addr_low as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov rbx, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov rbx, QWORD [input_addr as _]
            );
        }

        dynasm!(ops
            ; div rbx
            ; mov QWORD [out_addr as _], rax
            ; mov QWORD [out_addr_low as _], rdx
        );
        Ok(())
    }
    fn intRem(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rdx, rdx
            ; xor rbx, rbx
        );
        let out_addr = mem.translate(out.addr())?;
        let out_addr_low = out_addr + 8;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            let value_high = value & 0x00000000;
            let value_low = value & 0xFFFFFFFF;
            dynasm!(ops
                ; mov rdx, value_high as _
                ; mov rax, value_low as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            let input_addr_low = input_addr + 8;
            dynasm!(ops
                ; mov rdx, QWORD [input_addr as _]
                ; mov rax, QWORD [input_addr_low as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov rbx, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov rbx, QWORD [input_addr as _]
            );
        }
        dynasm!(ops
            ; div rbx
            ; mov QWORD [out_addr as _], rdx
        );
        Ok(())
    }
    fn intSdiv(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rdx, rdx
            ; xor rbx, rbx
        );
        let out_addr = mem.translate(out.addr())?;
        let out_addr_low = out_addr + 8;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            let value_high = value & 0x00000000;
            let value_low = value & 0xFFFFFFFF;
            dynasm!(ops
                ; mov rdx, value_high as _
                ; mov rax, value_low as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            let input_addr_low = input_addr + 8;
            dynasm!(ops
                ; mov rdx, QWORD [input_addr as _]
                ; mov rax, QWORD [input_addr_low as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov rbx, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov rbx, QWORD [input_addr as _]
            );
        }
        dynasm!(ops
            ; idiv rbx
            ; mov QWORD [out_addr as _], rax
            ; mov QWORD [out_addr_low as _], rdx
        );
        Ok(())
    }
    fn intSrem(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rdx, rdx
            ; xor rbx, rbx
        );
        let out_addr = mem.translate(out.addr())?;
        let out_addr_low = out_addr + 8;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            let value_high = value & 0x00000000;
            let value_low = value & 0xFFFFFFFF;
            dynasm!(ops
                ; mov rdx, value_high as _
                ; mov rax, value_low as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            let input_addr_low = input_addr + 8;
            dynasm!(ops
                ; mov rdx, QWORD [input_addr as _]
                ; mov rax, QWORD [input_addr_low as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov rbx, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov rbx, QWORD [input_addr as _]
            );
        }
        dynasm!(ops
            ; idiv rbx
            ; mov QWORD [out_addr as _], rdx
        );
        Ok(())
    }
    fn boolNegate(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
        );
        let out_addr = mem.translate(out.addr())?;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            dynasm!(ops
                ; mov rax, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            dynasm!(ops
                ; mov al, BYTE [input_addr as _]
            );
        }
        dynasm!(ops
            ; not al
            ; mov BYTE [out_addr as _], al
        );
        Ok(())
    }
    fn boolXor(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rbx, rbx
        );
        let out_addr = mem.translate(out.addr())?;
        let out_addr_low = out_addr + 8;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            dynasm!(ops
                ; mov cl, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            dynasm!(ops
                ; mov cl, BYTE [input_addr as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov bl, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov bl, BYTE [input_addr as _]
            );
        }

        dynasm!(ops
            ; xor al, bl
            ; mov BYTE [out_addr_low as _], al
        );
        Ok(())
    }
    fn boolAnd(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rbx, rbx
        );
        let out_addr = mem.translate(out.addr())?;
        let out_addr_low = out_addr + 8;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            dynasm!(ops
                ; mov cl, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            dynasm!(ops
                ; mov cl, BYTE [input_addr as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov bl, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov bl, BYTE [input_addr as _]
            );
        }

        dynasm!(ops
            ; and al, bl
            ; mov BYTE [out_addr_low as _], al
        );
        Ok(())
    }
    fn boolOr(
        &mut self,
        ops: &mut dynasmrt::Assembler<Self::Reloc>,
        mem: &MemMappedMemory,
        inputs: &[&dyn crate::Varnode],
        out: &dyn crate::Varnode,
    ) -> Result<()> {
        dynasm!(ops
            ; xor rax, rax
            ; xor rbx, rbx
        );
        let out_addr = mem.translate(out.addr())?;
        let out_addr_low = out_addr + 8;
        if &inputs[0].addr().space() == "const" {
            let value = inputs[0].addr().offset();
            dynasm!(ops
                ; mov cl, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[0].addr())?;
            dynasm!(ops
                ; mov cl, BYTE [input_addr as _]
            );
        }
        if &inputs[1].addr().space() == "const" {
            let value = inputs[1].addr().offset();
            dynasm!(ops
                ; mov bl, value as _
            );
        } else {
            let input_addr = mem.translate(inputs[1].addr())?;
            dynasm!(ops
                ; mov bl, BYTE [input_addr as _]
            );
        }

        dynasm!(ops
            ; or al, bl
            ; mov BYTE [out_addr_low as _], al
        );
        Ok(())
    }


















}

/// Pcode cache only block translator that does not translate anything not in the cache.
/// In other words, no actual translation engine is included.
#[derive(Debug)]
pub struct PcodeCacheOnlyTranslator<'a, PcodeTrans: PcodeTranslator> {
    /// addr to index into `pcode_cache`
    cache: BTreeMap<usize, &'a dyn PcodeOp>,
    block_cache: HashMap<usize, (AssemblyOffset, ExecutableBuffer)>,
    pcode_trans: PcodeTrans,
}

impl<'a, PcodeTrans: PcodeTranslator> PcodeCacheOnlyTranslator<'a, PcodeTrans> {
    pub fn from_cache(cache: BTreeMap<usize, &'a dyn PcodeOp>, pcode_trans: PcodeTrans) -> Self {
        Self {
            cache,
            block_cache: HashMap::default(),
            pcode_trans,
        }
    }

    pub fn add_pcode(&mut self, pcode: &'a dyn PcodeOp, addr: usize) {
        self.cache.insert(addr, pcode);
    }
}

impl<'a, PcodeTrans: PcodeTranslator<Reloc = X64Relocation, Mem = MemMappedMemory>>
    BlockTranslator<MemMappedMemory> for PcodeCacheOnlyTranslator<'a, PcodeTrans>
{
    fn translate(&mut self, mem: &mut MemMappedMemory, addr: usize) -> Result<*const u8> {
        let cache_op_iter = self.cache.iter().skip_while(|c| *c.0 != addr);

        let mut ops = x64::Assembler::new().unwrap();

        dynasm!(ops
            ; .arch x64
        );
        let offset = ops.offset();

        for (_, pcode) in cache_op_iter {
            self.pcode_trans.translate_pcode(&mut ops, mem, *pcode)?;
        }

        let block_result = ops.finalize().unwrap();
        let buf = block_result.ptr(offset);

        self.block_cache.insert(addr, (offset, block_result));

        Ok(buf)
    }
}
