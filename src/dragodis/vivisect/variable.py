from __future__ import annotations
from typing import TYPE_CHECKING, Union

from vivisect.const import *

from dragodis.exceptions import UnsupportedError
from dragodis.interface.variable import StackVariable, GlobalVariable
from dragodis.vivisect.data_type import VivisectDataType
from dragodis.vivisect.viv import FunctionLocal, Symbol, Location

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectGlobalVariable(GlobalVariable):

    def __init__(self, vivisect: VivisectFlatAPI, addr: int):
        self._vivisect = vivisect
        self._addr = addr

    @property
    def _location(self) -> Location:
        return Location(*self._vivisect._workspace.getLocation(self._addr))

    @property
    def address(self) -> int:
        return self._addr

    @property
    def name(self) -> str:
        return self._vivisect._workspace.getName(self._addr)

    @name.setter
    def name(self, new_name: str):
        self._vivisect._workspace.setName(self._addr, new_name)

    @property
    def size(self) -> int:
        return self._location.size

    @property
    def data_type(self) -> VivisectDataType:
        # Vivisect defaults to "int"
        return VivisectDataType(self._vivisect, "int")


class VivisectStackVariable(StackVariable):

    def __init__(self, vivisect: VivisectFlatAPI, func_addr: int, spdelta: int):
        self._vivisect = vivisect
        self._func_addr = func_addr
        self._spdelta = spdelta

    @property
    def _function_local(self) -> FunctionLocal:
        return FunctionLocal(*self._vivisect._workspace.localsyms[self._func_addr][self._spdelta])

    @property
    def _symbol(self) -> Symbol:
        return Symbol(*self._vivisect._workspace.getFunctionLocal(self._func_addr, self._spdelta))

    @property
    def stack_offset(self) -> int:
        return self._spdelta

    @property
    def name(self) -> str:
        return self._symbol.symname

    @name.setter
    def name(self, new_name: str):
        symbol = self._symbol._replace(symname=new_name)
        local = self._function_local
        if local.symtype == LSYM_NAME:
            local = local._replace(syminfo=tuple(symbol))
            self._vivisect._workspace.setFunctionLocal(*local)
        elif local.symtype == LSYM_FARG:
            idx = local.syminfo
            self._vivisect._workspace.setFunctionArg(local.fva, idx, *symbol)
        else:
            raise TypeError(f"Unknown symbol type: {local.symtype}")

    @property
    def size(self) -> int:
        return self.data_type.size

    @property
    def data_type(self) -> VivisectDataType:
        return VivisectDataType(self._vivisect, self._symbol.typename)


VivisectVariable = Union[VivisectGlobalVariable, VivisectStackVariable]
