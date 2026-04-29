from __future__ import annotations
from typing import TYPE_CHECKING

from vivisect import LOC_UNI, LOC_STRING

from dragodis.interface.string import String
from dragodis.vivisect.viv import Location

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectString(String):

    def __init__(self, vivisect: VivisectFlatAPI, location: Location):
        self._vivisect = vivisect
        self._location = Location(*location)

    @property
    def value(self) -> str:
        data = self.data
        if self._location.ltype == LOC_UNI:
            try:
                string = data.decode("utf16")
            except UnicodeDecodeError:
                string = (data + b"\x00").decode("utf16")
        elif self._location.ltype == LOC_STRING:
            string = data.decode("utf8")
        else:
            raise ValueError(f"Unknown location type: {self._location.ltype}")
        return string.rstrip("\0")

    @property
    def data(self) -> bytes:
        return self._vivisect.get_bytes(self._location.va, self._location.size).rstrip(b"\x00")

    @property
    def address(self) -> int:
        return self._location.va
