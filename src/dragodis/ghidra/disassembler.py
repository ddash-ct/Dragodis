
import logging
import os
import pathlib
from typing import TYPE_CHECKING, Optional

import pyhidra
from pyhidra.core import _analyze_program

from dragodis.exceptions import NotInstalledError
from dragodis.interface import BackendDisassembler
from dragodis.constants import BACKEND_GHIDRA

# Used for typing to help Pycharm give us autocompletion.
if TYPE_CHECKING:
    import ghidra

logger = logging.getLogger(__name__)


class GhidraDisassembler(BackendDisassembler):

    name = BACKEND_GHIDRA

    PROCESSOR_ARM = "ARM:LE:32:v8"
    PROCESSOR_ARM64 = "AARCH64:LE:64:v8A"
    PROCESSOR_X86 = "x86:LE:32:default"
    PROCESSOR_X64 = "x86:LE:64:default"

    FILETYPE_BINARY = "ghidra.app.util.opinion.BinaryLoader"
    FILETYPE_PE = "ghidra.app.util.opinion.PeLoader"
    FILETYPE_ELF = "ghidra.app.util.opinion.ElfLoader"
    FILETYPE_MACH_O = "ghidra.app.util.opinion.MachoLoader"

    def __init__(self, input_path, processor=None, filetype=None, **settings):
        super().__init__(input_path, processor=processor, filetype=filetype, **settings)
        # Build on start()
        self._flatapi = None     # type: Optional[ghidra.program.flatapi.FlatProgramAPI]
        self._program = None     # type: Optional[ghidra.program.database.ProgramDB]
        self._listing = None     # type: Optional[ghidra.program.model.listing.Listing]
        # Built on demand
        self.__decomp_api = None
        self.__basic_block_model = None
        self.__monitor = None

    # region Helper Functions

    def stop(self, *exc_info):
        if self.__decomp_api is not None:
            # don't create one just to destroy it
            self._decomp_api.dispose()

    @property
    def _decomp_api(self) -> "ghidra.app.decompiler.flatapi.FlatDecompilerAPI":
        if not self.__decomp_api:
            from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
            self.__decomp_api = FlatDecompilerAPI(self._flatapi)
            self.__decomp_api.initialize()
        return self.__decomp_api

    @property
    def _basic_block_model(self) -> "ghidra.program.model.block.BasicBlockModel":
        if not self.__basic_block_model:
            from ghidra.program.model.block import BasicBlockModel
            self.__basic_block_model = BasicBlockModel(self._program)
        return self.__basic_block_model

    @property
    def _monitor(self) -> "ghidra.util.task.TaskMonitor":
        if not self.__monitor:
            from ghidra.util.task import TaskMonitor
            self.__monitor = TaskMonitor.DUMMY
        return self.__monitor

    # endregion


class GhidraRemoteDisassembler(GhidraDisassembler):
    is_local = False

    def __init__(self, input_path, ghidra_path=None, processor=None, filetype=None, **settings):
        """
        Initializes Ghidra disassembler.

        :param input_path: Path of binary to process.
        :param ghidra_path: Path to Ghidra directory.
            This may also be set using the environment variable GHIDRA_INSTALL_DIR
        :param processor: Processor type (defaults to auto-detected)
        :param filetype: File type (defaults to auto-detected)
        :param settings: Additional Ghidra specific settings that are also configurable in `settings.toml`.
        """
        super().__init__(input_path, processor=processor, filetype=filetype, **settings)
        ghidra_path = ghidra_path or self._settings.install_dir
        if not ghidra_path:
            raise NotInstalledError(
                "Failed to get Ghidra install directory. "
                "Please provide it during instantiation or set the GHIDRA_INSTALL_DIR environment variable."
            )
        # Set environment variable for pyhidra.
        os.environ["GHIDRA_INSTALL_DIR"] = ghidra_path

        self._running = False
        self._bridge = None

    def start(self):
        if self._running:
            raise ValueError(f"Ghidra disassembler already running.")

        try:
            logger.debug(f"Starting pyhidra connection to {self.input_path}")
            kwargs = {
                "language": self._processor,
                "loader": self._filetype,
                "analyze": self._analyze,
                **self._settings.config,
            }
            self._bridge = pyhidra.open_program(self.input_path, **kwargs)
            self._flatapi = self._bridge.__enter__()
        except ValueError:
            if self._filetype:
                raise ValueError(f"The specified filetype does not match a class name of a loader in Ghidra: {self._filetype}")
            raise
        except Exception as e:
            if self._filetype:
                try:
                    from ghidra.app.util.opinion import LoadException
                except ImportError:
                    raise e
                if isinstance(e, LoadException):
                    raise ValueError("No load spec found within Ghidra for the specified filetype and processor combination: "
                                    f"{self._processor or 'Default'}/{self._filetype}")
            raise
        self._program = self._flatapi.getCurrentProgram()
        self._listing = self._program.getListing()

        self._running = True
        if not self._analyze:
            logger.debug("Skipping autoanalysis.")
        logger.debug("Ghidra Disassembler ready!")

    def stop(self, *exc_info):
        if not self._running:
            return
        logger.debug("Shutting down Ghidra connection...")
        super().stop(*exc_info)
        try:
            from java.io import IOException
            self._bridge.__exit__(*exc_info)
        except IOException as e:
            # Sometimes Ghidra fails to save.
            logger.error(f"Failed to close Ghidra bridge: {e}")
        self._bridge = None
        self._running = False
        logger.debug("Ghidra connection closed.")

    def analyze(self):
        """
        Instruct Ghidra to initiate and wait for auto analysis completion.
        """
        if not self._running:
            logger.error("Cannot run GhidraRemoteDisassembler.analyze() without a connected Ghidra instance.")
            return
        logger.debug("Running autoanalysis.")
        _analyze_program(self._flatapi, self._program)


class GhidraLocalDisassembler(GhidraDisassembler):
    is_local = True

    def __init__(self, input_path=None, currentProgram=None, **settings):
        if not currentProgram:
            interpreter = pyhidra.get_current_interpreter()
            currentProgram = interpreter.currentProgram

        super().__init__(currentProgram.executablePath, **settings)
        self._program = currentProgram
        # Input path is not required when inside Ghidra, but if provided
        # let's use it to validate we are looking at the right file.
        if input_path and pathlib.Path(input_path).resolve() != self.input_path:
            raise ValueError(
                f"Expected input path isn't the same as the file loaded in Ghidra: {input_path} != {self.input_path}"
            )
        self.start()

    def start(self):
        self._listing = self._program.getListing()
        from ghidra.program.flatapi import FlatProgramAPI
        self._flatapi = FlatProgramAPI(self._program)
