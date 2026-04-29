from __future__ import annotations
from typing import List, TYPE_CHECKING, Optional, Type

import envi
from envi.archs.arm import ArmOpcode, IF_PSR_S
from envi.archs.h8.operands import H8Opcode
from envi.archs.i386 import PREFIX_REP_MASK
from envi.archs.msp430 import Msp430Opcode
from envi.memcanvas import StringMemoryCanvas
from vivisect import LOC_OP

from dragodis.exceptions import NotExistError
from dragodis.vivisect.operand import VivisectOperand, Vivisectx86Operand, VivisectARMOperand
from dragodis.interface.types import FlowType
from dragodis.interface.instruction import Instruction, x86Instruction, ARMInstruction, ARMConditionCode
from dragodis.vivisect.viv import Location

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectInstruction(Instruction):
    _Operand = VivisectOperand

    @classmethod
    def _get_class(cls, api: VivisectFlatAPI) -> Type[Instruction]:
        arch_id = api._workspace.arch.getArchId()
        if arch_id in (envi.ARCH_I386, envi.ARCH_AMD64):
            return cls._x86Instruction
        elif arch_id == envi.ARCH_ARMV7:
            return cls._ARMInstruction
        # Vivisect fails to obtain the arch id constants for its default ARM module name.
        elif api._workspace.arch.getArchName() == "ARMv7A":
            return cls._ARMInstruction
        else:
            return cls

    def __init__(self, vivisect: VivisectFlatAPI, location: Location):
        super().__init__(vivisect)
        self._location = Location(*location)
        if self._location.ltype != LOC_OP:
            raise NotExistError(f"Instruction does not exist at: {hex(self._location.va)}")

    @property
    def _opcode(self) -> envi.Opcode:
        return self._api._workspace.parseOpcode(self._location.va)

    @property
    def address(self) -> int:
        return self._opcode.va

    @property
    def flow_type(self) -> FlowType:
        iflags = self._opcode.iflags
        if iflags & envi.IF_CALL:
            return FlowType.call
        elif iflags & envi.IF_RET:
            return FlowType.terminal
        elif iflags & envi.IF_BRANCH:
            if iflags & envi.IF_COND:
                return FlowType.conditional_jump
            else:
                return FlowType.unconditional_jump
        elif iflags & envi.IF_NOFALL:
            return FlowType.terminal  # interrupt (e.g. int3)
        else:
            return FlowType.fall_through

    @property
    def mnemonic(self) -> str:
        # Vivisect hardcodes the generation of the full mnemonic within the repr() function.
        # Thankfully, these architectures don't have prefixes, so we can easily parse it.
        opcode = self._opcode
        if isinstance(opcode, (H8Opcode, ArmOpcode, Msp430Opcode)):
            mnem, _, _ = repr(self._opcode).partition(" ")
        else:
            mnem = opcode.mnem
        return mnem.lower()

    @property
    def root_mnemonic(self) -> str:
        return self._opcode.mnem.lower()

    @property
    def operands(self) -> List[VivisectOperand]:
        return [
            self._Operand(self, self._api, index, operand)
            for index, operand in enumerate(self._opcode.getOperands())
        ]

    @property
    def text(self) -> str:
        # Using "memory canvas" to allow support for symbol resolution.
        vw = self._api._workspace
        mcanv = StringMemoryCanvas(vw, vw)
        self._opcode.render(mcanv)

        # Include comments, because they are helpful.
        if cmnt := vw.getComment(self._location.va):
            mcanv.addText(f"    ;{cmnt}")

        return str(mcanv)

    @property
    def stack_depth(self) -> int:
        funcva = self._api._workspace.getFunction(self.address)
        emu = self._api._workspace.getEmulator()
        stack = emu.getStackCounter()
        emu.runFunction(funcva, stopva=self.address, maxhit=2)
        if emu.getProgramCounter() != self.address:
            raise RuntimeError(f"Failed to determine stack_depth for: {self}")
        return emu.getStackCounter() - stack

    @property
    def stack_delta(self) -> int:
        opcode = self._opcode

        # If a call or return, we know it is 0.
        # Avoid the emulator, since it would set itself into/outside the function.
        if opcode.isCall() or opcode.isReturn():
            return 0

        emu = self._api._workspace.getEmulator()
        stack = emu.getStackCounter()
        emu.executeOpcode(opcode)
        return emu.getStackCounter() - stack


class Vivisectx86Instruction(VivisectInstruction, x86Instruction):
    _Operand = Vivisectx86Operand

    @property
    def rep(self) -> Optional[str]:
        opcode = self._opcode
        if opcode.prefixes & PREFIX_REP_MASK:
            return opcode.getPrefixName()


class VivisectARMInstruction(VivisectInstruction, ARMInstruction):
    _Operand = VivisectARMOperand

    @property
    def update_flags(self) -> bool:
        opcode: ArmOpcode = self._opcode
        return (opcode.iflags & opcode.S_FLAG_MASK) == IF_PSR_S

    @property
    def condition_code(self) -> ARMConditionCode:
        return ARMConditionCode(self._opcode.prefixes)

    @property
    def writeback(self) -> bool:
        for operand in self._opcode.getOperands():
            if hasattr(operand, "pubwl"):
                # from vivisect source code:
                # write-back if (P==0 || W==1)
                pubwl = operand.pubwl
                return bool(pubwl & 0x2 or not pubwl & 0x10)
        return False

    @property
    def pre_indexed(self) -> bool:
        for operand in self._opcode.getOperands():
            if hasattr(operand, "pubwl"):
                idxing = operand.pubwl & 0x12
                return (idxing & 0x10) != 0
        return False

    @property
    def post_indexed(self) -> bool:
        for operand in self._opcode.getOperands():
            if hasattr(operand, "pubwl"):
                idxing = operand.pubwl & 0x12
                return (idxing & 0x10) == 0
        return False


VivisectInstruction._x86Instruction = Vivisectx86Instruction
VivisectInstruction._ARMInstruction = VivisectARMInstruction
