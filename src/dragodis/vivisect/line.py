from __future__ import annotations

import logging
from typing import Optional, Any, TYPE_CHECKING

from vivisect.const import *

from dragodis.exceptions import NotExistError, UnsupportedError
from dragodis.interface import Line, LineType, CommentType
from dragodis.vivisect.instruction import VivisectInstruction
from dragodis.vivisect.string import VivisectString
from dragodis.vivisect.viv import Location

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


logger = logging.getLogger(__name__)


class VivisectLine(Line):

    _loc_map = {
        LOC_UNDEF: LineType.undefined,
        LOC_STRING: LineType.string,
        LOC_UNI: LineType.string16,
        LOC_POINTER: LineType.pointer,
        LOC_OP: LineType.code,
        LOC_STRUCT: LineType.struct,
        # LOC_CLSID: TODO,
        # LOC_VFTABLE: TODO,
        LOC_PAD: LineType.align,
    }

    def __init__(self, vivisect: VivisectFlatAPI, location: Location):
        super().__init__(vivisect)
        location = Location(*location)
        self._addr = location.va
        self._vivisect = vivisect

    @property
    def _location(self) -> Location:
        location = Location(*self._vivisect._workspace.getLocation(self._addr))
        # Vivisect sometimes includes the null character for strings in size, and other times doesn't.
        # We will always count the null character to be consistent.
        if location.ltype == LOC_STRING:
            data = self._vivisect.get_bytes(location.va, location.size)
            if not data.endswith(b"\x00"):
                assert self._vivisect.get_bytes(location.va + location.size, 1) == b"\x00"
                location = location._replace(size=location.size + 1)
        elif location.ltype == LOC_UNI:
            data = self._vivisect.get_bytes(location.va, location.size)
            if not data.endswith(b"\x00\x00"):
                assert self._vivisect.get_bytes(location.va + location.size, 2) == b"\x00\x00"
                location = location._replace(size=location.size + 2)
        return location

    @_location.setter
    def _location(self, location: Location):
        self._vivisect._workspace.addLocation(*location)

    @property
    def address(self) -> int:
        return self._location.va

    @property
    def data(self) -> bytes:
        if not self.is_loaded:
            return b""
        return self._vivisect.get_bytes(self.address, self.size)

    @data.setter
    def data(self, new_data: bytes):
        location = self._location
        if location.ltype == LOC_STRING and not new_data.endswith(b"\x00"):
            new_data += b"\x00"
        elif location.ltype == LOC_UNI and not new_data.endswith(b"\x00\x00"):
            new_data += b"\x00\x00"
        size = len(new_data)
        if size != location.size:
            self._location = location._replace(size=size)
        self._vivisect.set_bytes(location.va, new_data)

    def get_comment(self, comment_type=CommentType.eol) -> Optional[str]:
        return self._vivisect.get_comment(self.address)

    def set_comment(self, comment: Optional[str], comment_type=CommentType.eol):
        return self._vivisect.set_comment(self.address, comment)

    @property
    def name(self) -> Optional[str]:
        return self._vivisect._workspace.getName(self.address)

    @name.setter
    def name(self, value: Optional[str]):
        if not value:
            # Reset original name.
            value = self._vivisect._names.get(self._addr, None)
        self._vivisect._workspace.makeName(self._addr, value, makeuniq=True)

    @property
    def next(self) -> Optional[VivisectLine]:
        # Find the next defined locations.
        # There is no getNextLocation(), so we have to do this manually.
        address = self._location.va + self.size
        max_address = self._vivisect.max_address
        while address < max_address:
            if location := self._vivisect._workspace.getLocation(address):
                return VivisectLine(self._vivisect, location)
            address += 1

    @property
    def prev(self) -> Optional[VivisectLine]:
        # May want to set adjacent parameter to false
        if prev_location := self._vivisect._workspace.getPrevLocation(self.address, adjacent=False):
            try:
                return VivisectLine(self._vivisect, prev_location)
            except NotExistError:
                return

    @property
    def size(self) -> int:
        return self._location.size

    @property
    def type(self) -> LineType:
        ltype = self._location.ltype
        if ltype in (LOC_NUMBER, LOC_IMPORT):
            return {
                1: LineType.byte,
                2: LineType.word,
                4: LineType.dword,
                8: LineType.qword,
                16: LineType.oword,
            }[self.size]
        return self._loc_map[ltype]

    @type.setter
    def type(self, new_type: LineType):
        address = self._location.va

        # TODO: Switch these to calling define_*() function.
        if new_type == LineType.string:
            self._vivisect._workspace.makeString(address)

        elif new_type == LineType.string16:
            self._vivisect._workspace.makeUnicode(address)

        elif new_type == LineType.byte:
            self._vivisect._workspace.makeNumber(address, 1)

        elif new_type == LineType.word:
            self._vivisect._workspace.makeNumber(address, 2)

        elif new_type == LineType.dword:
            self._vivisect._workspace.makeNumber(address, 4)

        elif new_type == LineType.qword:
            self._vivisect._workspace.makeNumber(address, 8)

        elif new_type == LineType.oword:
            self._vivisect._workspace.makeNumber(address, 16)

        elif new_type == LineType.pointer:
            self._vivisect._workspace.makePointer(address)

        elif new_type == LineType.code:
            self._vivisect._workspace.makeCode(address)

        elif new_type == LineType.undefined:
            self._vivisect._workspace.addLocation(address, 1, LOC_UNDEF)

        else:
            raise UnsupportedError(f"Unsupported line type: {new_type}")

    def undefine(self):
        self._vivisect._workspace.delLocation(self._location.va)

    @property
    def value(self) -> Any:
        loc = self._location

        if loc.ltype in (LOC_STRING, LOC_UNI):
            string = VivisectString(self._vivisect, loc)
            return str(string)

        if loc.ltype in (LOC_NUMBER, LOC_POINTER, LOC_IMPORT, LOC_UNDEF):
            return int.from_bytes(self.data, byteorder=self._vivisect.byteorder)

        if loc.ltype == LOC_OP:
            return VivisectInstruction(self._vivisect, loc)

        if loc.ltype == LOC_PAD:
            return self.data

        raise UnsupportedError(f"Unsupported location type: {loc.ltype}")

    @value.setter
    def value(self, new_value: Any):
        matched_types = LineType.match_type(new_value)
        if not matched_types:
            raise TypeError(f"Unsupported value type: {type(new_value)}")

        type_ = self.type
        # First see if setting this new value would require changing the line type.
        if type_ not in matched_types:
            # Use the first entry of matched types to be the type we change it to.
            # Type must be changed after we patch to avoid the type change failing
            # due to bytes originally set at location.
            new_type = matched_types[0]
            logger.debug(f"Changing line type from {type_} to {new_type}")
            if new_type != type_:
                self.type = new_type
            type_ = new_type

        # Patch the value based on line type.
        if type_ == LineType.code:
            raise NotImplementedError(f"Setting an instruction is not currently supported.")

        elif type_ in (LineType.byte, LineType.undefined):
            if isinstance(new_value, int):
                new_value = bytes([new_value])
            self.data = new_value

        elif type_ in (LineType.word, LineType.dword, LineType.qword, LineType.oword):
            size = {
                LineType.word: 2,
                LineType.dword: 4,
                LineType.qword: 8,
                LineType.oword: 16,
                LineType.pointer: self._vivisect.bit_size / 8,
            }[type_]
            self.data = new_value.to_bytes(size, self._vivisect.byteorder)

        elif type_ == LineType.string:
            self.data = new_value.encode("utf8")

        elif type_ == LineType.string16:
            self.data = new_value.encode("utf-16-le")

        elif type_ == LineType.align:
            self.data = new_value
