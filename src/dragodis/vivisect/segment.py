from __future__ import annotations
from typing import Iterable, Optional, TYPE_CHECKING

import envi

from dragodis.exceptions import NotExistError, UnsupportedError
from dragodis.vivisect.line import VivisectLine
from dragodis.vivisect.memory import VivisectMemory
from dragodis.interface import Segment, SegmentPermission, Line, Memory
from dragodis.vivisect.viv import Segment as _Segment, MemoryMap

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectSegment(Segment):

    def __init__(self, vivisect: VivisectFlatAPI, addr: int):
        if not vivisect._workspace.getSegment(addr):
            raise NotExistError(f"Could not find segment containing address: 0x{addr:08x}")
        self._vivisect = vivisect
        self._addr = addr

    @property
    def _segment(self) -> _Segment:
        return _Segment(*self._vivisect._workspace.getSegment(self._addr))

    @property
    def _memory_map(self) -> Optional[MemoryMap]:
        mmap = self._vivisect._workspace.getMemoryMap(self._addr)
        if mmap:
            return MemoryMap(*mmap)

    @property
    def name(self) -> str:
        return self._segment.name

    @name.setter
    def name(self, new_name: Optional[str]):
        raise UnsupportedError("Vivisect doesn't support modifying the segment.")

    @property
    def start(self) -> int:
        return self._segment.va

    @property
    def end(self) -> int:
        return self.start + self._segment.size

    @property
    def initialized(self) -> bool:
        return bool(self._memory_map)  # TODO: validate logic here

    @property
    def bit_size(self) -> int:
        # Don't believe Vivisect is capable of representing segments of diff bitsizes.
        # So just pull global pointer size.
        return self._vivisect.bit_size

    @property
    def permissions(self) -> SegmentPermission:
        perm = SegmentPermission(0)
        if mmap := self._memory_map:
            if mmap.flags & envi.MM_EXEC:
                perm |= SegmentPermission.execute
            if mmap.flags & envi.MM_WRITE:
                perm |= SegmentPermission.write
            if mmap.flags & envi.MM_READ:
                perm |= SegmentPermission.read
        return perm

    def lines(self, start: int = None, reverse: bool = False) -> Iterable[VivisectLine]:
        if self.initialized:
            if reverse:
                yield from self._vivisect.lines(start or self.end, self.start - 1, reverse=True)
            else:
                yield from self._vivisect.lines(start or self.start, self.end)

    def open(self) -> VivisectMemory:
        if not self.initialized:
            # Empty memory
            return self._vivisect.open_memory(self.start, self.start)
        return self._vivisect.open_memory(self.start, self.end)
