from __future__ import annotations
from typing import Optional, TYPE_CHECKING, Union, Tuple

import envi
from envi.archs.amd64 import Amd64RipRelOper
from envi.archs.arm import ArmPcOffsetOper, ArmRegOper, ArmRegListOper, ArmImmOper, ArmImmOffsetOper, \
    ArmScaledOffsetOper, ArmRegOffsetOper, ArmRegShiftImmOper, ArmRegShiftRegOper, REG_PC
from envi.archs.i386 import i386PcRelOper, i386SibOper, i386ImmMemOper, i386RegMemOper
from envi.memcanvas import StringMemoryCanvas

from dragodis.exceptions import NotExistError
from dragodis.interface.operand import Operand, ARMOperand, x86Operand, OperandType
from dragodis.interface.operand_value import OperandValue, Phrase
from dragodis.interface.types import ARMShiftType
from dragodis.vivisect.operand_value import (
    VivisectRegister, VivisectImmediate, VivisectMemoryReference,
    VivisectARMPhrase, Vivisectx86Phrase, VivisectRegisterList,
)
from dragodis.vivisect.variable import VivisectVariable

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI
    from dragodis.vivisect.instruction import VivisectInstruction


class VivisectOperand(Operand):

    _type_map = {
        envi.RegisterOper: OperandType.register,
        envi.ImmedOper: OperandType.immediate,
        envi.DerefOper: OperandType.phrase,
    }

    def __init__(self, instruction: VivisectInstruction, vivisect: VivisectFlatAPI, index: int, operand: envi.Operand):
        super().__init__(instruction)
        self._vivisect = vivisect
        self._index = index
        self._opcode = instruction._opcode
        self._operand = operand

    @property
    def address(self) -> int:
        return self.instruction.address

    @property
    def index(self) -> int:
        return self._index

    @property
    def text(self) -> str:
        # Using "memory canvas" to allow support for symbol resolution.
        vw = self._vivisect._workspace
        mcanv = StringMemoryCanvas(vw, vw)
        self._operand.render(mcanv, self._opcode, self._index)
        return str(mcanv)

    @property
    def type(self) -> OperandType:
        operand = self._operand
        for klass, operand_type in reversed(self._type_map.items()):
            if isinstance(operand, klass):
                return operand_type
        raise ValueError(f"Unknown operand type: {operand}")

    @property
    def value(self) -> OperandValue:
        operand_type = self.type
        operand = self._operand

        if operand_type == OperandType.register:
            assert hasattr(operand, "reg")
            return VivisectRegister(self._vivisect, operand.reg)

        elif operand_type == OperandType.memory:
            assert isinstance(operand, (Amd64RipRelOper, i386ImmMemOper))
            return VivisectMemoryReference(operand.getOperAddr(self._opcode))

        elif operand_type == OperandType.code:
            assert isinstance(operand, (i386PcRelOper, ArmPcOffsetOper))
            return VivisectMemoryReference(operand.getOperValue(self._opcode))

        elif operand_type == OperandType.immediate:
            assert isinstance(operand, (envi.ImmedOper, ArmImmOper))
            return VivisectImmediate(operand.getOperValue(self._opcode))

    @property
    def width(self) -> int:
        return self._operand.tsize

    @property
    def variable(self) -> Optional[VivisectVariable]:
        value = self.value

        if isinstance(value, Phrase):
            address = self.instruction.address
            spdelta = self._vivisect._workspace.getFref(address, self.index)
            if spdelta is not None:
                if func := self._vivisect.get_function(address, None):
                    if var := func.stack_frame.get(spdelta):
                        return var

        elif isinstance(value, int):  # memory or immediate
            try:
                # Cast to int() to strip off custom classes.
                return self._vivisect.get_variable(int(value))
            except NotExistError:
                pass


class Vivisectx86Operand(VivisectOperand, x86Operand):

    _type_map = {
        **VivisectOperand._type_map,
        i386PcRelOper: OperandType.code,
        Amd64RipRelOper: OperandType.memory,
        i386ImmMemOper: OperandType.memory,
    }

    @property
    def value(self) -> OperandValue:
        operand_type = self.type
        operand = self._operand
        if operand_type == OperandType.phrase:
            assert isinstance(operand, (i386SibOper, i386RegMemOper))
            return Vivisectx86Phrase(self._vivisect, operand)
        elif isinstance(operand, i386ImmMemOper):
            return VivisectMemoryReference(operand.imm)
        return super().value


class VivisectARMOperand(VivisectOperand, ARMOperand):

    # Vivisect doesn't subclass operands appropriately for ARM.
    _type_map = {
        **VivisectOperand._type_map,
        ArmRegOper: OperandType.register,
        ArmRegShiftImmOper: OperandType.register,  # register with immediate shift
        ArmRegShiftRegOper: OperandType.register,  # register with register shift
        ArmPcOffsetOper: OperandType.code,
        ArmImmOper: OperandType.immediate,
        ArmRegListOper: OperandType.register_list,
        ArmImmOffsetOper: OperandType.phrase,
        ArmScaledOffsetOper: OperandType.phrase,
        ArmRegOffsetOper: OperandType.phrase,
    }

    @property
    def shift(self) -> Tuple[ARMShiftType, Union[int, VivisectRegister]]:
        operand = self._operand
        shift_type, shift_count = ARMShiftType.LSL, 0  # not shifted

        if hasattr(operand, "shval"):
            shift_count = operand.shval
        elif hasattr(operand, "shimm"):
            shift_count = operand.shimm
        elif hasattr(operand, "shreg"):
            shift_count = VivisectRegister(self._vivisect, operand.shreg)

        if hasattr(operand, "shtype") and shift_count != 0:
            shift_type = ARMShiftType(operand.shtype)

        return shift_type, shift_count

    @property
    def type(self) -> OperandType:
        operand = self._operand
        if isinstance(operand, ArmImmOffsetOper):
            if operand.base_reg == REG_PC:
                return OperandType.memory
            else:
                return OperandType.phrase
        return super().type

    @property
    def value(self) -> OperandValue:
        # Get value ofr ARM specific types.
        operand_type = self.type
        operand = self._operand

        if operand_type == OperandType.register_list:
            assert isinstance(operand, ArmRegListOper)
            # Register indexes are stored as positions in a bitmap.
            reg_bitmap = operand.val
            return VivisectRegisterList([
                VivisectRegister(self._vivisect, idx)
                for idx in range(16) if reg_bitmap & (1 << idx)
            ])

        if operand_type == OperandType.phrase:
            assert isinstance(operand, (ArmImmOffsetOper, ArmScaledOffsetOper, ArmRegOffsetOper))
            return VivisectARMPhrase(self._vivisect, operand)

        if isinstance(operand, ArmImmOffsetOper):
            return VivisectMemoryReference(operand.getOperAddr(self._opcode))

        return super().value
