
from __future__ import annotations
import abc
import pathlib
from typing import Union, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from dynaconf.utils import DynaBox

from dragodis.interface.types import ProcessorType, FileType
from dragodis.config import settings as global_settings


class BackendDisassembler(metaclass=abc.ABCMeta):
    """
    Disassembler Interface

    Handles the setup and teardown of a backend disassembler.
    Should be combined as a mixin with a FlatAPI class.
    """

    # This should be filled in.
    name: str
    is_local: bool

    # Common processor types dragodis supports.
    PROCESSOR_ARM: str
    PROCESSOR_ARM64: str
    PROCESSOR_X86: str
    PROCESSOR_X64: str

    # Common file types
    FILETYPE_BINARY: str
    FILETYPE_PE: str
    FILETYPE_ELF: str
    FILETYPE_MACH_O: str

    def __init__(
            self,
            input_path: Union[str, pathlib.Path],
            processor: Union[ProcessorType, str] = None,
            filetype: Union[FileType, str] = None,
            **settings,
    ):
        """
        Initialization method.

        This must perform any initialization, setup, or preparation needed to begin making
        regular calls to the disassembler. For instance, executing the
        disassembler binary, performing initial auto-analysis, and/or
        starting a communications server would all be appropriate actions to
        perform here.

        :param input_path: The path of the file to process
        :param processor: Processor spec to use. (defaults to auto-detection by underlying disassembler)
        :param filetype: Type of file to use. (defaults to auto-detection by underlying disassembler)
        :param settings: Additional disassembler specific settings that are also configurable in `settings.toml`.

        :raises NotInstalledError: If the disassembler was not installed on the system.
        """
        self.input_path = pathlib.Path(input_path).resolve()
        if not self.input_path.exists():
            raise ValueError(f"{input_path} does not exist")
        if processor:
            processor = self._get_processor_spec(processor)
        self._processor = processor
        if filetype:
            filetype = self._get_filetype(filetype)
        self._filetype = filetype
        self._settings: DynaBox = global_settings[self.name.lower()].copy()
        self._settings.merge_update(settings)
        self._analyze = self._settings.analyze

    def __enter__(self):
        """
        Entry method for context manager interface.
        Used to create a context manager for the disassembler.
        """
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """
        Exit method for context manager interface.
        Used to create a context manager for the disassembler.
        """
        self.stop(*(exc_type, exc_value, exc_traceback))

    def _get_processor_spec(self, processor: Union[ProcessorType, str]) -> str:
        """
        Generate the appropriate processor spec for the underlying disassembler.
        """
        if isinstance(processor, ProcessorType):
            return {
                ProcessorType.ARM: self.PROCESSOR_ARM,
                ProcessorType.ARM64: self.PROCESSOR_ARM64,
                ProcessorType.x86: self.PROCESSOR_X86,
                ProcessorType.x64: self.PROCESSOR_X64,
            }[processor]
        return processor

    def _get_filetype(self, filetype: Union[FileType, str]) -> str:
        """
        Generate the appropriate filetype for the underlying disassembler.
        """
        if isinstance(filetype, FileType):
            return {
                FileType.BINARY: self.FILETYPE_BINARY,
                FileType.PE: self.FILETYPE_PE,
                FileType.ELF: self.FILETYPE_ELF,
                FileType.MACH_O: self.FILETYPE_MACH_O,
            }[filetype]
        return filetype

    def start(self):
        """
        Setup method.

        This should be called before starting analysis. Any setup should be done here.

        This can include spawning a process to handle the disassembler, creating a temporary
        workspace for the disassembler, etc...
        """
        pass

    def stop(self, *exc_info):
        """
        Teardown method.

        This should be called upon completion of analysis. Any teardown should be done here.

        This can include saving a generated file (such as an IDB), deleting temporary directories,
        shutting down spawned processes, etc...
        """
        pass

    def analyze(self) -> None:
        """
        Analyzes the sample.
        By default, this function is run automatically when the disassembler is started.
        If 'analyze' was set to false, this must be called manually.

        e.g.
            with dragodis.open_program("sample.exe", analyze=False) as dis:
                # do things before analysis.
                dis.analyze()
        """

    def teleport(self, func: Callable) -> Callable:
        """
        Teleports function into the underlying disassembler to do disassembler specific things.
        NOTE: This function only applies for certain disassemblers. For others, this does nothing
        but pass back the same function.

        e.g.
            def my_func(addr):
                import ida_funcs
                func = ida_funcs.get_func(addr)
                return func.start_ea

            if dis.name == "IDA":
                start_addr = dis.teleport(my_func)(0x123)

        :param func: Callback function to run in underlying disassembler.
        :return: A new function which when called will be run in the underlying disassembler.
        """
        return func
