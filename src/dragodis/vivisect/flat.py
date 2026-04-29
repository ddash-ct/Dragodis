import bisect
import itertools
from pathlib import Path
from typing import Optional, Iterable, Union

import envi
import vivisect
from Elf import Elf
from PE import PE
from envi import SegmentationViolation
from vivisect import InvalidLocation, LOC_UNDEF

from dragodis.exceptions import NotExistError, UnsupportedError
from dragodis.interface.flat import FlatAPI, MISSING
from dragodis.interface.types import CommentType, CompilerType, SegmentPermission

from .disassembler import VivisectDisassembler
from .data_type import VivisectDataType
from .function import VivisectFunction
from .function_signature import VivisectFunctionSignature
from .instruction import VivisectInstruction
from .line import VivisectLine
from .memory import VivisectMemory
from .operand_value import VivisectRegister
from .reference import VivisectReference
from .segment import VivisectSegment
from .string import VivisectString
from .symbol import VivisectImport, VivisectExport
from .variable import VivisectGlobalVariable
from .viv import Location, XRef, MemoryMap

from ..interface import ReferenceType, Function
from ..utils import genproperty


class VivisectFlatAPI(FlatAPI, VivisectDisassembler):

    @property
    def _filename(self) -> str:
        # We expect there to be just one file in the workspace.
        return self._workspace.getFiles()[0]

    @property
    def version(self) -> str:
        return vivisect.verstring

    @property
    def project_path(self) -> Path:
        return Path(self._workspace.getMeta("StorageName"))

    @property
    def processor_name(self) -> str:
        return self._workspace.arch.getArchName()

    @property
    def compiler_name(self) -> str:
        # Vivisect does not provide compiler information,
        # but don't want to break a lot of code because of this.
        return "unknown"

    @property
    def bit_size(self) -> int:
        return self._workspace.getPointerSize() * 8

    @property
    def is_big_endian(self) -> bool:
        return self._workspace.bigend

    @property
    def entry_point(self) -> Optional[int]:
        # Only a single file should be loaded into a workspace at a time,
        # so there should only be at most one or entry point.
        for ep in self._workspace.getEntryPoints():
            return ep

    def functions(self, start=None, end=None) -> Iterable[VivisectFunction]:
        addrs = sorted(self._workspace.getFunctions())
        if start:
            start = bisect.bisect_left(addrs, start)
        if end:
            end = bisect.bisect_right(addrs, end)
        for addr in itertools.islice(addrs, start, end):
            yield VivisectFunction(self, addr)

    def get_virtual_address(self, file_offset: int, default=MISSING) -> int:
        fmt = self._workspace.getMeta("Format")

        if fmt == "pe":
            parsedbin: PE = self._workspace.parsedbin
            addr = parsedbin.offsetToRva(file_offset)
            if addr == 0:
                if default is MISSING:
                    raise NotExistError(f"unable to get virtual address from PE")
                return default
            addr += parsedbin.IMAGE_NT_HEADERS.OptionalHeader.ImageBase  # Reverse of vaToRva()
            return addr

        elif fmt == "elf":
            # NOTE: section headers are optional, program headers are required
            try:
                parsedbin: Elf = self._workspace.parsedbin
                for phdr in parsedbin.pheaders:
                    if phdr.p_filesz == 0:
                        # skip memory regions without any file data
                        continue
                    if file_offset >= phdr.p_offset and file_offset < (phdr.p_offset + phdr.p_filesz):
                        return phdr.p_vaddr + (file_offset - phdr.p_offset)
            except Exception as e:
                if default is MISSING:
                    raise NotExistError(f"Unable to get file offset from ELF: {e}")
            return default

        elif fmt == "blob":
            baseaddr: int = self._workspace.config.viv.parsers.blob.baseaddr
            return file_offset + baseaddr

        raise UnsupportedError(f"Vivisect does not support getting the virtual address for format: {fmt}")

    def get_file_offset(self, addr: int, default=MISSING) -> int:
        if addr not in range(self.min_address, self.max_address):
            if default is MISSING:
                raise NotExistError(f"Unable to get file offset for {addr}: out of range")
            return default

        fmt = self._workspace.getMeta("Format")

        if fmt == "pe":
            parsedbin: PE = self._workspace.parsedbin
            offset = parsedbin.vaToOffset(addr)
            if offset == 0:
                if default is MISSING:
                    raise NotExistError(f"unable to get file offset from PE")
                return default
            return offset

        elif fmt == "elf":
            try:
                parsedbin: Elf = self._workspace.parsedbin
                return parsedbin.rvaToOffset(addr - parsedbin.getBaseAddress())
            except Exception as e:
                if default is MISSING:
                    raise NotExistError(f"Unable to get file offset from ELF: {e}")
                return default

        elif fmt == "blob":
            baseaddr: int = self._workspace.config.viv.parsers.blob.baseaddr
            return addr - baseaddr

        raise UnsupportedError(f"Vivisect does not support getting the file offset for format: {fmt}")

    def get_comment(self, addr: int, comment_type=CommentType.eol) -> Optional[str]:
        return self._workspace.getComment(addr)

    def set_comment(self, addr: int, comment: Optional[str], comment_type=CommentType.eol):
        # Vivisect will clear the comment if comment is None.
        self._workspace.setComment(addr, comment)

    def get_byte(self, addr: int, default=MISSING) -> int:
        try:
            with self._workspace.getAdminRights():
                return ord(self._workspace.readMemory(addr, 1))
        except envi.SegmentationViolation:
            if default is MISSING:
                raise NotExistError(f"Cannot get byte at {hex(addr)}")
            return default

    def get_bytes(self, addr: int, length: int, default: int = None) -> bytes:
        try:
            with self._workspace.getAdminRights():
                return self._workspace.readMemory(addr, length)
        except envi.SegmentationViolation:
            if default is None:
                raise NotExistError(
                    f"Unable to obtain {length} bytes from 0x{addr:08X}: "
                    f"Address range not fully loaded."
                )
            # TODO: can make this more efficient by pulling from getMemoryMaps()
            data = bytearray()
            offset = 0
            while offset < length:
                # current address is at mapped memory, retry pulling from map
                if memory_map := self._workspace.getMemoryMap(addr + offset):
                    memory_map = MemoryMap(*memory_map)
                    index = (addr + offset) - memory_map.va
                    read_length = min(memory_map.size - index, length - offset)
                    with self._workspace.getAdminRights():
                        data.extend(self._workspace.readMemory(addr + offset, read_length))
                    offset += read_length
                else:
                    data.append(default)
                    offset += 1
            return bytes(data)

    def set_compiler(self, compiler):
        raise UnsupportedError("Vivisect does not currently support setting the compiler.")

    def set_bytes(self, addr: int, data: bytes):
        try:
            # Getting admin rights to ignore segment's permissions.
            with self._workspace.getAdminRights():
                self._workspace.writeMemory(addr, data)
        except SegmentationViolation as e:
            raise NotExistError(f"Cannot set data at {hex(addr)}: {e}")

    def find_bytes(self, pattern: bytes, start: int = None, reverse: bool = False) -> int:
        results = self._workspace.searchMemory(pattern)
        if reverse:
            for addr in reversed(results):
                if start is None:
                    return addr
                elif addr <= start:
                    return addr
        else:
            for addr in results:
                if start is None:
                    return addr
                elif addr >= start:
                    return addr
        return -1

    def get_function(self, addr: int, default=MISSING) -> VivisectFunction:
        start_addr = self._workspace.getFunction(addr)
        if start_addr is None:
            if default is MISSING:
                raise NotExistError(f"Function containing {hex(addr)} does not exist.")
            return default
        return VivisectFunction(self, start_addr)

    def get_function_by_name(self, name: str, ignore_underscore: bool = True, ignore_hex_suffix: bool = True, default=MISSING) -> Function:
        """
        Returns a `Function` instance with given name.

        :param str name: Name of function to obtain
        :param bool ignore_underscore: Whether to ignore leading or trailing underscores in function name.
            (Will return the first found function if enabled.)
        :para bool ignore_hex_suffix: Whether to ignore the trailing hex suffix in a function name for non-generic functions.
        :param default: Default value to provide if function doesn't exist. (Raises NotExistError if not provided)

        :return: A :class:`~.Function` instance containing the given address
        :raises NotExistError: If there is no function containing the given address.
        """
        if ignore_hex_suffix:
            # If ignoring hex suffix, we have to manually look through the functions to find
            # a function with the name, but with a hex number.
            for func_addr in self._workspace.getFunctions():
                func_name = self._workspace.getName(func_addr)
                if func_name == name:
                    return self.get_function(func_addr)
                if func_name.startswith(name):
                    suffix = func_name[len(name):].strip("_")
                    try:
                        if int(suffix, 16) == func_addr:
                            return self.get_function(func_addr)
                    except ValueError:
                        continue
        return super().get_function_by_name(name, ignore_underscore=ignore_underscore, default=default)

    def create_function(self, start: int, end: int = None, *, default=MISSING) -> VivisectFunction:
        try:
            func_addr = self._workspace.makeFunction(start, meta={"Size": end - start} if end else None)
            if func_addr is None:
                if default is MISSING:
                    raise ValueError(f"Unable to create function at {hex(start)}")
                return default
            # Fill in function with instructions (if not already.)
            # Vivisect will do code analysis to determine how far to define instructions.
            self._workspace.makeCode(start, fva=func_addr)
            return VivisectFunction(self, func_addr)
        except InvalidLocation as e:
            if default is MISSING:
                raise NotExistError(f"Address {hex(start)} does not exist: {e}")
            return default

    def get_function_signature(self, addr: int, default=MISSING) -> VivisectFunctionSignature:
        try:
            return VivisectFunctionSignature(self, addr)
        except NotExistError:
            if default is MISSING:
                raise
            return default

    def get_line(self, addr: int, default=MISSING) -> VivisectLine:
        try:
            # Need to pull location first, in order to get head of line.
            if location := self._workspace.getLocation(addr):
                return VivisectLine(self, location)
            else:
                try:
                    # If not a defined location, pull a single byte to make an "undefined" line.
                    with self._workspace.getAdminRights():
                        self._workspace.readMemory(addr, 1)
                    self._workspace.addLocation(addr, 1, LOC_UNDEF)
                    return VivisectLine(self, self._workspace.getLocation(addr))
                except envi.SegmentationViolation:
                    raise NotExistError(f"Lines at address {hex(addr)} does not exist.")
        except NotExistError:
            if default is MISSING:
                raise
            return default

    def get_instruction(self, addr: int, default=MISSING) -> VivisectInstruction:
        try:
            # Need to pull location first, in order to get head of instruction.
            if location := self._workspace.getLocation(addr):
                return VivisectInstruction(self, location)
            else:
                raise NotExistError(f"Instruction at address {hex(addr)} does not exist.")
        except NotExistError:
            if default is MISSING:
                raise
            return default

    def get_data_type(self, name: str, default=MISSING) -> VivisectDataType:
        # TODO: Determine if we can pull standardized names.
        return VivisectDataType(self, name)

    def get_register(self, name: str, default=MISSING) -> VivisectRegister:
        reg_ctx: envi.registers.RegisterContext = self._workspace.arch.archGetRegCtx()
        idx = reg_ctx.getRegisterIndex(name)
        if idx is None:
            if default is MISSING:
                raise NotExistError(f"Register {name} does not exist.")
            return default
        return VivisectRegister(self, idx)

    def get_segment(self, addr_or_name: Union[int, str], default=MISSING) -> VivisectSegment:
        if isinstance(addr_or_name, str):
            name = addr_or_name
            for segment in self._workspace.getSegments():
                seg_addr, _, seg_name, _ = segment
                if name.lower() == seg_name.lower():
                    return VivisectSegment(self, seg_addr)
            if default is MISSING:
                raise NotExistError(f"Could not find segment with name: {name}")
            return default
        elif isinstance(addr_or_name, int):
            addr = addr_or_name
            try:
                return VivisectSegment(self, addr)
            except NotExistError:
                if default is MISSING:
                    raise
                return default
        else:
            raise ValueError(f"Invalid input: {addr_or_name!r}")

    def create_segment(self, name: str, start: int, size: int) -> VivisectSegment:
        # Create segment definition and new memory map if necessary.
        self._workspace.addSegment(start, size, name, self._filename)
        # TODO: Add argument to specify if they want the segment initialized?
        # if not self._workspace.getMemoryMap(start):
        #     perm = SegmentPermission.read | SegmentPermission.write | SegmentPermission.execute
        #     self._workspace.addMemoryMap(start, perm, self._filename, b"\x00" * size)
        return VivisectSegment(self, start)

    @genproperty
    def segments(self) -> Iterable[VivisectSegment]:
        for segment in self._workspace.segments:
            seg_addr, _, _, _ = segment
            yield VivisectSegment(self, seg_addr)

    # Copy of Vivisect's but without the permissions check.
    def _readMemString(self, va, maxlen=0xfffffff, wide=False):
        '''
        Returns a C-style string from memory.  Stops at Memory Map boundaries, or the first NULL (\x00) byte.
        '''
        terminator = (b'\0', b'\0\0')[bool(wide)]
        for mva, mmaxva, mmap, mbytes in self._workspace._map_defs:
            if mva <= va < mmaxva:
                mva, msize, mperms, mfname = mmap
                offset = va - mva

                # now find the end of the string based on either \x00, maxlen, or end of map
                end = mbytes.find(terminator, offset)
                while (end > offset) and (end-offset) % len(terminator) != 0:
                    # with codepage 0, we really need \0\0\0 because the first
                    #   0 is part of the last character
                    end = mbytes.find(terminator, end+1)

                left = end - offset
                if end == -1:
                    # couldn't find the NULL byte
                    mend = offset + maxlen
                    cstr = mbytes[offset:mend]
                else:
                    # couldn't find the NULL byte go to the end of the map or maxlen
                    mend = offset + (maxlen, left)[left < maxlen]
                    cstr = mbytes[offset:mend]
                return cstr

        raise envi.SegmentationViolation(va)

    def get_string_bytes(self, addr: int, length: int = None, bit_width: int = None, default=MISSING) -> bytes:
        # First see if we can use detect string.
        size = -1
        if not bit_width or bit_width == 8:
            size = self._workspace.detectString(addr)
        elif bit_width == 16:
            size = self._workspace.detectUnicode(addr)
        if size != -1:
            with self._workspace.getAdminRights():
                return self._workspace.readMemory(addr, size)

        # Otherwise just pull null terminated bytes.
        if bit_width and bit_width != 8:
            raise UnsupportedError("Only 8-bit widths are supported")
        try:
            if length is None:
                length = 0xfffffff  # Vivisect's sentinal
            with self._workspace.getAdminRights():
                return self._readMemString(addr, maxlen=length, wide=bit_width == 16)
        except envi.SegmentationViolation:
            if default is MISSING:
                raise NotExistError(f"Cannot get string bytes at {hex(addr)}")
            return default

    def strings(self, min_length=3) -> Iterable[VivisectString]:
        for loc in self._workspace.getLocations(vivisect.LOC_STRING):
            yield VivisectString(self, loc)
        for loc in self._workspace.getLocations(vivisect.LOC_UNI):
            yield VivisectString(self, loc)

    @property
    def max_address(self) -> int:
        return max(addr + size for addr, size, *_ in self._workspace.getSegments())

    @property
    def min_address(self) -> int:
        return min(addr for addr, *_ in self._workspace.getSegments())

    @property
    def base_address(self) -> int:
        return self._workspace.getFileMeta(self._filename, "imagebase")

    def open_memory(self, start: int, end: int) -> VivisectMemory:
        return VivisectMemory(self, start, end)

    def references_from(self, addr: int) -> Iterable[VivisectReference]:
        seen = set()
        for xref in self._workspace.getXrefsFrom(addr):
            xref = XRef(*xref)
            key = (xref.fromva, xref.tova, xref.rtype)
            if key not in seen:
                # Vivisect can create duplicate references.
                seen.add(key)
                yield VivisectReference(self, xref)

    def references_to(self, addr: int) -> Iterable[VivisectReference]:
        seen = set()
        for xref in self._workspace.getXrefsTo(addr):
            xref = XRef(*xref)
            key = (xref.fromva, xref.tova, xref.rtype)
            if key not in seen:
                # Vivisect can create duplicate references.
                seen.add(key)
                yield VivisectReference(self, xref)

    def create_reference(self, from_address: int, to_address: int, ref_type: ReferenceType) -> VivisectReference:
        rflags = 0
        if ref_type.is_code():
            rtype = vivisect.REF_CODE
            if ref_type == ReferenceType.code_call:
                rflags |= envi.BR_PROC
            elif ref_type == ReferenceType.code_jump:
                rflags |= envi.BR_COND
            elif ref_type == ReferenceType.ordinary_flow:
                rflags |= envi.BR_FALL
            self._workspace.makeCode(from_address)
            self._workspace.makeCode(to_address)
        else:
            rtype = vivisect.REF_DATA
        # Architecture gets to decide on actual final VA (ARM/THUMB/etc...)
        to_address, rtype, rflags = self._workspace.arch.archModifyXrefAddr(to_address, rtype, rflags)
        xref = (from_address, to_address, rtype, rflags)
        self._workspace.addXref(*xref)
        return VivisectReference(self, xref)

    def get_variable(self, addr: int, default=MISSING) -> VivisectGlobalVariable:
        if loc := self._workspace.getLocation(addr):
            loc = Location(*loc)
            if loc.ltype not in (vivisect.LOC_UNDEF, vivisect.LOC_OP):
                if self._workspace.getName(loc.va):
                    return VivisectGlobalVariable(self, loc.va)

    @genproperty
    def imports(self) -> Iterable[VivisectImport]:
        for location in self._workspace.getImports():
            yield VivisectImport(self, location)

    @genproperty
    def exports(self) -> Iterable[VivisectExport]:
        for export in self._workspace.getExports():
            yield VivisectExport(self, export)

    def undefine(self, start: int, end: int = None) -> bool:
        if end:
            if end <= start:
                raise ValueError(f"End address {hex(end)} is smaller than starting address {hex(start)}")
        else:
            end = start + 1

        address = start
        while True:
            if location := self._workspace.getLocation(address):
                location = Location(*location)
                self._workspace.delLocation(location.va)
                address += location.size
            else:
                address += 1
            if address >= end:
                break
        return True


class Vivisect(VivisectFlatAPI, VivisectDisassembler):
    ...
