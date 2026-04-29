
from __future__ import annotations
from typing import TYPE_CHECKING

from dragodis.exceptions import UnsupportedError
from dragodis.interface.data_type import DataType

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectDataType(DataType):

    _size_map = {
        "byte": 1,
        "char": 1,
        "word": 2,
        "short": 2,
        "dword": 4,
        "qword": 8,
    }

    def __init__(self, vivisect: VivisectFlatAPI, typename: str):
        self._vivisect = vivisect
        self._typename = typename

    @property
    def name(self) -> str:
        return self._typename

    @property
    def size(self) -> int:
        # From what I can tell Vivisect more or less hardcodes "int" for all argument types.
        # There is only a small handful of data types seen in use. So we will manually calculate.
        name = self.name
        if name == "int" or name.endswith("*"):
            return self._vivisect._workspace.getPointerSize()
        try:
            return self._size_map[name.lower()]
        except KeyError:
            raise ValueError(f"Unexpected data type: {self.name}")
