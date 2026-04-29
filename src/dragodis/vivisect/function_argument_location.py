
from __future__ import annotations
from typing import TYPE_CHECKING

from dragodis.vivisect.operand_value import VivisectRegister
from dragodis.interface.function_argument_location import (
    ArgumentLocation, StackLocation, RegisterLocation,
)

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectArgumentLocation(ArgumentLocation):
    ...


class VivisectStackLocation(StackLocation, VivisectArgumentLocation):

    def __init__(self, stack_offset):
        self._stack_offset = stack_offset

    @property
    def stack_offset(self) -> int:
        return self._stack_offset


class VivisectRegisterLocation(RegisterLocation, VivisectArgumentLocation):

    def __init__(self, vivisect: VivisectFlatAPI, idx: int):
        self._vivisect = vivisect
        self._idx = idx

    @property
    def register(self) -> VivisectRegister:
        return VivisectRegister(self._vivisect, self._idx)

# The following argument locations don't seem to be supported by vivisect.

# class VivisectRegisterPairLocation(RegisterPairLocation, VivisectArgumentLocation):
#
#     @property
#     def registers(self) -> Tuple[VivisectRegister, VivisectRegister]:
#         ...
#
#
# class VivisectRelativeRegisterLocation(RelativeRegisterLocation, VivisectArgumentLocation):
#
#     @property
#     def offset(self) -> int:
#         ...
#
#     @property
#     def register(self) -> VivisectRegister:
#         ...
#
#
# class VivisectStaticLocation(StaticLocation, VivisectArgumentLocation):
#
#     @property
#     def address(self) -> int:
#         ...


