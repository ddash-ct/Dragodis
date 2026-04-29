from __future__ import annotations
from typing import Union, Iterable, TYPE_CHECKING

from dragodis.exceptions import UnsupportedError
from dragodis.vivisect.variable import VivisectStackVariable
from dragodis.interface.stack import StackFrame
from dragodis.vivisect.viv import FunctionLocal

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectStackFrame(StackFrame):

    def __init__(self, vivisect: VivisectFlatAPI, func_addr: int):
        self._vivisect = vivisect
        self._func_addr = func_addr

    def __eq__(self, other: VivisectStackFrame) -> bool:
        return self._func_addr == other._func_addr

    def __getitem__(self, name_or_offset: Union[str, int]) -> VivisectStackVariable:
        if isinstance(name_or_offset, int):
            offset = name_or_offset
            local = self._vivisect._workspace.getFunctionLocal(self._func_addr, offset)
            if not local:
                raise KeyError(f"Stack variable with offset {offset} not found")
            return VivisectStackVariable(self._vivisect, self._func_addr, offset)
        else:
            name = name_or_offset
            for var in self:
                if var.name == name:
                    return var
            raise KeyError(f"Stack variable with name {name} not found")

    def __delitem__(self, name_or_offset: Union[str, int]):
        # No way to remove a stack variable from what I can determine.
        raise UnsupportedError("Removing a stack variable is not supported")

    def __iter__(self) -> Iterable[VivisectStackVariable]:
        for local in sorted(self._vivisect._workspace.getFunctionLocals(self._func_addr)):
            local = FunctionLocal(*local)
            # Sometimes Vivisect lies to us and will provide a local but have no symbol information.
            # (Because the function api doesn't have the arg)
            # We can check for this by seeing if getFunctionLocal() returns symbol information.
            if self._vivisect._workspace.getFunctionLocal(self._func_addr, local.spdelta):
                yield VivisectStackVariable(self._vivisect, self._func_addr, local.spdelta)

    def __len__(self) -> int:
        return len(self._vivisect._workspace.getFunctionLocals(self._func_addr))
