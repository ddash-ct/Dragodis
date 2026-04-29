
from __future__ import annotations

import functools
from typing import Union, TYPE_CHECKING, Optional

import envi.archs.arm
from envi.archs.arm import ArmScaledOffsetOper, ArmImmOffsetOper, ArmRegOffsetOper
from envi.archs.i386 import i386SibOper, i386RegMemOper

from dragodis.interface.operand_value import (
    Immediate, MemoryReference, Register, RegisterList,
    Phrase,
)

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectImmediate(Immediate):
    ...


class VivisectMemoryReference(MemoryReference):
    ...



@functools.cache
def _get_reg_ctx(vw):
    # Cached to improve performance.
    return vw.arch.archGetRegCtx()


class VivisectRegister(Register):

    def __init__(self, vivisect: VivisectFlatAPI, idx: int):
        self._vivisect = vivisect
        self._idx = idx

    def __eq__(self, other: VivisectRegister):
        return isinstance(other, VivisectRegister) and self._idx == other._idx

    @property
    def _regctx(self) -> envi.registers.RegisterContext:
        return _get_reg_ctx(self._vivisect._workspace)

    @property
    def base(self) -> VivisectRegister:
        # If the register is a "meta register", the base is the register
        # this register is extracting from.
        if reginfo := self._regctx.getMetaRegInfo(self._idx):
            base_idx, _, _ = reginfo
            return VivisectRegister(self._vivisect, base_idx)
        else:
            return self

    @property
    def bit_width(self) -> int:
        return self._regctx.getRegisterWidth(self._idx)

    @property
    def mask(self) -> int:
        if reginfo := self._regctx.getMetaRegInfo(self._idx):
            _, offset, mask = reginfo
            return mask << offset
        else:
            return (1 << self.bit_width) - 1

    @property
    def name(self) -> str:
        return self._regctx.getRegisterName(self._idx)


class VivisectRegisterList(RegisterList):
    ...


class VivisectARMPhrase(Phrase):

    def __init__(self, vivisect: VivisectFlatAPI, operand: Union[ArmImmOffsetOper, ArmScaledOffsetOper, ArmRegOffsetOper]):
        self._vivisect = vivisect
        self._operand = operand

    @property
    def base(self) -> VivisectRegister:
        return VivisectRegister(self._vivisect, self._operand.base_reg)

    @property
    def offset(self) -> Union[VivisectRegister, int]:
        operand = self._operand
        if isinstance(operand, ArmImmOffsetOper):
            offset = operand.offset
            if not (operand.pubwl >> 3) & 1:
                offset *= -1
            return offset
        else:
            return VivisectRegister(self._vivisect, operand.offset_reg)

    @property
    def scale(self) -> int:
        return 1

    @property
    def index(self) -> Optional[Register]:
        # Index register is not a thing for ARM.
        return None


class Vivisectx86Phrase(Phrase):

    def __init__(self, vivisect: VivisectFlatAPI, operand: Union[i386SibOper, i386RegMemOper]):
        self._vivisect = vivisect
        self._operand = operand
        self._scaled = isinstance(operand, i386SibOper)

    @property
    def base(self) -> Optional[VivisectRegister]:
        if self._operand.reg is not None:
            return VivisectRegister(self._vivisect, self._operand.reg)

    @property
    def offset(self) -> int:
        if imm := getattr(self._operand, "imm", None):
            # Ping if we run into having both, since that means our assumptions with how
            # vivisect handles phrases is wrong.
            assert not self._operand.disp
            return imm
        return self._operand.disp

    @property
    def scale(self) -> int:
        if self._scaled:
            return self._operand.scale
        else:
            return 1

    @property
    def index(self) -> Optional[Register]:
        if self._scaled and self._operand.index is not None:
            return VivisectRegister(self._vivisect, self._operand.index)
