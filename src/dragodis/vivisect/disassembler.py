import logging
from typing import Optional

import vivisect

from dragodis.interface import BackendDisassembler
from dragodis.constants import BACKEND_VIVISECT
from dragodis.vivisect.viv import MemoryMapDef

logger = logging.getLogger(__name__)


# Vivisect doesn't close files after loading them into a workspace.
# Fixes for the PE and ELF parsers are patched in below to prevent issues with this.
import vivisect.parsers.pe as pe_parser
import vivisect.parsers.elf as elf_parser
import PE
import Elf

def pe_parseFile(vw, filename, baseaddr=None):
    with open(filename, "rb") as f:
        pe = PE.PE(f)
        return pe_parser.loadPeIntoWorkspace(vw, pe, filename=filename, baseaddr=baseaddr)

def elf_parseFile(vw, filename, baseaddr=None):
    with open(filename, "rb") as f:
        elf = Elf.Elf(f)
        return elf_parser.loadElfIntoWorkspace(vw, elf, filename=filename, baseaddr=baseaddr)

pe_parser.parseFile = pe_parseFile
elf_parser.parseFile = elf_parseFile


class VivisectDisassembler(BackendDisassembler):
    name = BACKEND_VIVISECT
    is_local = True

    PROCESSOR_ARM = "arm"
    PROCESSOR_ARM64 = "arm64"
    PROCESSOR_X86 = "i386"
    PROCESSOR_X64 = "amd64"

    FILETYPE_BINARY = "blob"
    FILETYPE_PE = "pe"
    FILETYPE_ELF = "elf"
    FILETYPE_MACH_O = "macho"

    def __init__(self, input_path, processor=None, filetype=None, **settings):
        """
        Initializes Vivisect disassembler.

        :param input_path: Path of binary to process.
        :param processor: Processor type (defaults to auto-detected)
        :param filetype: File type (defaults to auto-detected)
        :param settings: Additional Vivisect specific settings that are also configurable in `settings.toml`.
        """
        super().__init__(input_path, processor=processor, filetype=filetype, **settings)
        self._workspace = vivisect.VivWorkspace()
        if config := self._settings.config:
            self._workspace.config.setConfigPrimitive(config)
        self._running = False
        self._snap: Optional[list[MemoryMapDef]] = None
        self._names: Optional[dict[int, str]] = None

    def start(self):
        if self._running:
            raise ValueError(f"Vivisect disassembler already running.")
        # If the workspace is set to None, the disassembler has finished running.
        if not self._workspace:
            raise ValueError("Vivisect disassembler has already been started and stopped.")
        # If user provided a processor, we must be working with a blob (shellcode).
        if self._processor:
            self._workspace.config.viv.parsers.blob.arch = self._processor
            self._workspace.config.viv.parsers.blob.baseaddr = 0x0
        self._workspace.loadFromFile(str(self.input_path), fmtname=self._filetype)
        self._running = True
        if self._analyze:
            self.analyze()
        else:
            logger.debug("Skipping autoanalysis.")
        logger.debug("Vivisect Disassembler ready!")

    def stop(self, *exc_info):
        if not self._running:
            return
        self._workspace.saveWorkspace(fullsave=True)
        self._running = False
        self._snap = None
        self._names = None
        self._workspace = None

    def _cleanup_analysis(self):
        """
        Fixes up analysis created by Vivisect
        """
        # Cleanup incorrectly detected functions.
        for address in self._workspace.getFunctions():
            # remove addresses that aren't the start of a location.
            if self._workspace.getLocation(address)[0] != address:
                self._workspace.delFunction(address)
            # remove addresses that failed analysis.
            elif any(key.endswith(" fail") for key in self._workspace.getFunctionMetaDict(address)):
                self._workspace.delFunction(address)

    def analyze(self):
        """
        Instruct Vivisect to initiate analysis.
        """
        if not self._running:
            logging.error("Cannot run VivisectDisassembler.analyze() without a connected Vivisect instance.")
            return

        self._workspace.analyze()

        # Kick things off if the disassembler doesn't know where to start.
        if self._processor and not self._workspace.getLocations():
            self._workspace.makeFunction(0x0)
            self._workspace.makeCode(0x0, fva=0x0)

        if self._settings.cleanup_analysis:
            self._cleanup_analysis()

        # Save memory, before anyone does any patching.
        self._snap = self._workspace.getMemorySnap()
        # Save names, to allow reverting.
        self._names = self._workspace.name_by_va.copy()
