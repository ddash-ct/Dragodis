from __future__ import annotations

from typing import TYPE_CHECKING

from dragodis.exceptions import NotExistError
from dragodis.interface import Memory

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectMemory(Memory):

    def __init__(self, vivisect: VivisectFlatAPI, start: int, end: int) -> None:
        super().__init__(start, end)
        self._vivisect = vivisect

    def read(self, size: int = None) -> bytes:
        remaining_size = self.end - (self.start + self._offset)
        if size is None:
            size = remaining_size
        size = min(size, remaining_size)
        if not size:
            return b""

        with self._vivisect._workspace.getAdminRights():
            data = self._vivisect._workspace.readMemory(self.start + self._offset, size)
        self._offset += len(data)
        return data

    def reset(self, size: int = None) -> int:
        remaining_bytes = self.end - (self.start + self._offset)
        if size is None:
            size = remaining_bytes
        size = min(size, remaining_bytes)
        if not size:
            return 0

        # Restore original memory snap, so we can read in original data.
        address = self.start + self._offset
        orig_snap = self._vivisect._snap
        if not orig_snap:
            raise RuntimeError(f"Missing memory snapshot")  # shouldn't happen.
        current_snap = self._vivisect._workspace.getMemorySnap()
        try:
            self._vivisect._workspace.setMemorySnap(orig_snap)
            with self._vivisect._workspace.getAdminRights():
                data = self._vivisect._workspace.readMemory(address, size)
        finally:
            self._vivisect._workspace.setMemorySnap(current_snap)
        with self._vivisect._workspace.getAdminRights():
            self._vivisect._workspace.writeMemory(address, data)
        self._offset += size
        return size

    def write(self, data: bytes) -> int:
        # Trim given data to ensure we only write within the window.
        data = data[:self.end - (self.start + self._offset)]
        if not data:
            return 0

        address = self.start + self._offset
        try:
            self._vivisect.set_bytes(address, data)
        except NotExistError as e:
            raise IOError(e)
        self._offset += len(data)
        return len(data)
