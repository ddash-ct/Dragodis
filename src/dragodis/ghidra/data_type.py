
from __future__ import annotations
from typing import TYPE_CHECKING

from dragodis.interface.data_type import DataType

if TYPE_CHECKING:
    import ghidra


class GhidraDataType(DataType):

    def __init__(self, data_type: "ghidra.program.model.data.DataType"):
        self._data_type = data_type

    @property
    def name(self) -> str:
        return self._data_type.getName()

    @property
    def size(self) -> int:
        return self._data_type.getLength()

    @property
    def base(self) -> GhidraDataType:
        from ghidra.program.model.data import Array
        if isinstance(self._data_type, Array):
            return GhidraDataType(self._data_type.getDataType())
        return self

    @property
    def count(self) -> int:
        from ghidra.program.model.data import Array
        if isinstance(self._data_type, Array):
            return self._data_type.getNumElements()
        return 1
