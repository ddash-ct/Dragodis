
from __future__ import annotations

import pathlib

import atexit
import re
import logging
import os
import socket
import subprocess
import sys
import tempfile
import time
import typing
import warnings
from typing import Callable
import uuid

import rpyc
from rpyc.core.stream import NamedPipeStream, SocketStream
from rpyc.utils import factory

from dragodis.exceptions import DragodisError, NotInstalledError, BackendError
from dragodis.interface import BackendDisassembler
from dragodis.interface.types import ProcessorType
from dragodis.ida import ida_server, constants
from dragodis.constants import BACKEND_IDA
from dragodis import utils

try:
    import idapro
except ImportError:
    idapro = None

# Used for typing to help Pycharm give us autocompletion.
# To setup, add %IDA_DIR%\python\3 directory into the interpreter path using Pycharm.
if typing.TYPE_CHECKING:
    import idaapi
    import idc
    import idautils
    import ida_auto
    import ida_bitrange
    import ida_bytes
    import ida_funcs
    import ida_gdl
    import ida_name
    import ida_xref
    import ida_ua
    import ida_idp
    import ida_ida
    import ida_lines
    import ida_nalt
    import ida_hexrays
    import ida_segment
    import ida_loader
    import ida_typeinf
    import ida_entry
    import ida_struct
    import ida_frame
    import ida_search
    from .sdk import ida_arm
    from .sdk import ida_intel
    from .sdk import ida_helpers

logger = logging.getLogger(__name__)


class IDADisassembler(BackendDisassembler):
    """
    Backend IDA disassembler (interface)
    """
    name = BACKEND_IDA

    PROCESSOR_ARM = constants.PROCESSOR_ARM
    PROCESSOR_ARM64 = constants.PROCESSOR_ARM
    PROCESSOR_X86 = constants.PROCESSOR_METAPC
    PROCESSOR_X64 = constants.PROCESSOR_METAPC

    FILETYPE_BINARY = "Binary"
    FILETYPE_PE = "Portable"
    FILETYPE_ELF = "Elf"
    FILETYPE_MACH_O = "Mach-O"

    _BADADDR: int
    _idaapi: idaapi
    _idc: idc
    _idautils: idautils
    _ida_auto: ida_auto
    _ida_bitrange: ida_bitrange
    _ida_bytes: ida_bytes
    _ida_funcs: ida_funcs
    _ida_gdl: ida_gdl
    _ida_name: ida_name
    _ida_xref: ida_xref
    _ida_ua: ida_ua
    _ida_idp: ida_idp
    _ida_ida: ida_ida
    _ida_lines: ida_lines
    _ida_nalt: ida_nalt
    _ida_hexrays: ida_hexrays
    _ida_segment: ida_segment
    _ida_loader: ida_loader
    _ida_typeinf: ida_typeinf
    _ida_entry: ida_entry
    _ida_struct: ida_struct
    _ida_frame: ida_frame
    _ida_search: ida_search
    _ida_arm: ida_arm
    _ida_intel: ida_intel
    _ida_helpers: ida_helpers

    def _delete_temp_files(self):
        """
        Remove the temporary files created by IDA when it fails to do so.
        """
        for ext in [".id0", ".id1", ".id2", ".nam", ".til"]:
            file = self.input_path.parent / (self.input_path.name + ext)
            if os.path.exists(file):
                logger.debug(f"Removing IDA temp file: {file}")
                os.remove(file)

    def force_bitness(self, bitness: int):
        """
        Forces the address size for all segments.
        """
        if bitness not in (16, 32, 64):
            raise ValueError(f"Invalid bitness {bitness}")
        if self._ida_ida.inf_get_app_bitness() == bitness:
            return

        flag = {16:0, 32:1, 64:2}[bitness]
        for n in range(self._ida_segment.get_segm_qty()):
            if seg := self._ida_segment.getnseg(n):
                self._ida_segment.set_segm_addressing(seg, flag)
        try:
            self._ida_ida.inf_set_app_bitness(bitness)
        except AttributeError:
            pass  # inf_set_app_bitness was introduced in IDA 8.5
        self._ida_auto.plan_and_wait(0, self._BADADDR)

    def _find_ida_exe(self, install_dir: str, is_64_bit: bool) -> str:
        """
        Finds the location of the IDA executable.
        """
        ida_exe_re64 = re.compile(r"idaq?64(\.exe)?$")
        ida_exe_re32 = re.compile(r"idaq?(\.exe)?$")
        if is_64_bit:
            ida_exe_re = ida_exe_re64
        else:
            ida_exe_re = ida_exe_re32
        for filename in os.listdir(install_dir):
            if ida_exe_re.match(filename):
                return os.path.abspath(os.path.join(install_dir, filename))
        else:
            # IDA 8.5 + No longer has ida64.exe. Search for ida.exe if ida64 isn't present on a 64 bit file.
            # May be useful to eventually do a version check,
            # but I don't think there's a scenario where ida64 is missing and ida.exe is only 32 bit.
            if is_64_bit:
                for filename in os.listdir(install_dir):
                    if ida_exe_re32.match(filename):
                        return os.path.abspath(os.path.join(install_dir, filename))

        raise NotInstalledError(f"Unable to find ida executable within: {self._ida_path}")  # noqa


class IDALocalDisassembler(IDADisassembler):
    """
    Backend used when we are natively in the IDA interpreter or using idalib.
    """
    is_local = True

    def __init__(self, input_path=None, processor=None, filetype=None, bitness=None, **settings):
        """
        Initializes IDA disassembler.

        :param input_path: Path of binary to process.
        :param processor: Processor type (defaults to auto-detected)
            (https://hex-rays.com/products/ida/support/idadoc/618.shtml)
        :param filetype: File type (defaults to auto-detected)
            (https://docs.hex-rays.com/user-guide/disassembler/supported-file-formats)
        :param bitness: Sets the address size for all segments.
            If left as None, this will be determined by analyzing the input file.
        :param settings: Additional IDA specific settings that are also configurable in `settings.toml`.
        """
        if not (utils.in_ida() or idapro):
            raise RuntimeError("Missing IDA engine.")

        self._bitness = bitness

        # First check if a file is already loaded in IDA.
        import idc
        if loaded_file_path := idc.get_input_file_path():
            # Input path is not required when inside IDA, but if provided
            # let's use it to validate we are looking at the right file.
            if input_path and pathlib.Path(input_path).resolve() != loaded_file_path:
                raise ValueError(
                    f"Expected input path isn't the same as the file loaded in IDA: {input_path} != {loaded_file_path}")
            super().__init__(loaded_file_path, **settings)
            self._preloaded = True
            self.start()
        else:
            if not input_path:
                raise ValueError("Missing input path.")
            super().__init__(input_path, processor=processor, filetype=filetype, **settings)
            self._preloaded = False

    def _initialize_bridge(self):
        import idc
        self._BADADDR = idc.BADADDR
        self._idc = idc
        import idaapi
        self._idaapi = idaapi
        import idautils
        self._idautils = idautils
        import ida_auto
        self._ida_auto = ida_auto
        import ida_bitrange
        self._ida_bitrange = ida_bitrange
        import ida_bytes
        self._ida_bytes = ida_bytes
        import ida_funcs
        self._ida_funcs = ida_funcs
        import ida_gdl
        self._ida_gdl = ida_gdl
        import ida_name
        self._ida_name = ida_name
        import ida_xref
        self._ida_xref = ida_xref
        import ida_ua
        self._ida_ua = ida_ua
        import ida_idp
        self._ida_idp = ida_idp
        import ida_ida
        self._ida_ida = ida_ida
        import ida_lines
        self._ida_lines = ida_lines
        import ida_nalt
        self._ida_nalt = ida_nalt
        import ida_hexrays
        self._ida_hexrays = ida_hexrays
        import ida_segment
        self._ida_segment = ida_segment
        import ida_loader
        self._ida_loader = ida_loader
        import ida_typeinf
        self._ida_typeinf = ida_typeinf
        import ida_entry
        self._ida_entry = ida_entry
        try:
            #In IDA 8.5 and 9.0 API, ida_struct has been completely removed.
            import ida_struct
            self._ida_struct = ida_struct
        except ImportError:
            self._ida_struct = None
        import ida_frame
        self._ida_frame = ida_frame
        import ida_search
        self._ida_search = ida_search
        from .sdk import ida_arm
        self._ida_arm = ida_arm
        from .sdk import ida_intel
        self._ida_intel = ida_intel
        from .sdk import ida_helpers
        self._ida_helpers = ida_helpers

    def _disconnect_bridge(self):
        self._BADADDR = None
        self._idaapi = None
        self._idc = None
        self._idautils = None
        self._ida_auto = None
        self._ida_bitrange = None
        self._ida_bytes = None
        self._ida_funcs = None
        self._ida_gdl = None
        self._ida_name = None
        self._ida_xref = None
        self._ida_ua = None
        self._ida_idp = None
        self._ida_ida = None
        self._ida_lines = None
        self._ida_nalt = None
        self._ida_hexrays = None
        self._ida_segment = None
        self._ida_loader = None
        self._ida_typeinf = None
        self._ida_entry = None
        self._ida_struct = None
        self._ida_frame = None
        self._ida_search = None
        self._ida_arm = None
        self._ida_intel = None
        self._ida_helpers = None

    def start(self):
        if idapro and not self._preloaded:
            # Allow IDA to dump to stdout if debugging.
            # TODO: Redirect these to a logger. (Requires c-level stdout redirection)
            if logger.isEnabledFor(logging.DEBUG):
                idapro.enable_console_messages(True)

            args = []
            if self._processor:
                args.append(f"-p{self._processor}")
            if self._filetype:
                args.append(f"-T{self._filetype}")
            args.extend(self._settings.extra_args)
            args = " ".join(args)
            logger.debug(f"Running IDA with args: {args}")

            error_code = idapro.open_database(str(self.input_path), self._analyze, args=args or None)
            if error_code != 0:
                raise BackendError(f"IDA failed with error code: {error_code} (Please review debug logs for details)")
            if not self._analyze:
                logger.debug("Skipping autoanalysis.")

        self._initialize_bridge()
        self._idc.auto_wait()
        if self._bitness is not None:
            self.force_bitness(self._bitness)
        logger.debug("IDA Disassembler ready!")

    def stop(self, *exc_info):
        if idapro and not self._preloaded:
            logger.debug("Closing IDA database...")
            idapro.close_database()
            idapro.enable_console_messages(False)
            self._delete_temp_files()
            logger.debug("IDA database closed.")
        self._disconnect_bridge()

    def analyze(self):
        """
        Instruct IDA to initiate and wait for auto analysis completion.
        """
        if not self._idc:
            logger.error("Cannot run analyze() without connection to IDA database.")
            return
        logger.debug("Running autoanalysis.")
        self._idc.set_flag(self._idc.INF_GENFLAGS, self._idc.INFFL_AUTO, 1)
        self._idc.auto_wait()


class IDARemoteDisassembler(IDADisassembler):
    """
    Backend disassembler when we are remotely accessing IDA through rpyc.
    """
    is_local = False

    _rpyc_config = {}

    def __init__(
            self, input_path, ida_path=None, processor=None, filetype=None, detach=False,
            bitness: int = None, **settings
    ):
        """
        Initializes IDA disassembler.

        :param input_path: Path of binary to process.
        :param ida_path: Path to IDA directory.
            This may also be set using the environment variable IDADIR
        :param processor: Processor type (defaults to auto-detected)
            (https://hex-rays.com/products/ida/support/idadoc/618.shtml)
        :param filetype: File type (defaults to auto-detected)
            (https://docs.hex-rays.com/user-guide/disassembler/supported-file-formats)
        :param detach: Detach the IDA subprocess from the parent process group.
            This will cause signals to no longer propagate.
            (Linux only)
        :param bitness: Sets the address size for all segments.
            If left as None, this will be determined by analyzing the input file.
        :param settings: Additional IDA specific settings that are also configurable in `settings.toml`.
        """
        super().__init__(input_path, processor=processor, filetype=filetype, **settings)
        self._ida_path = ida_path or self._settings.install_dir
        if not self._ida_path:
            # Allow deprecated IDA_INSTALL_DIR.
            self._ida_path = os.environ.get("IDA_INSTALL_DIR")
            if self._ida_path:
                warnings.warn("Usage of 'IDA_INSTALL_DIR' is deprecated. Please change to 'IDADIR'.", DeprecationWarning)
            else:
                raise NotInstalledError(
                    f"Failed to get IDA install directory. "
                    "Please provide it in settings.toml or set the IDADIR environment variable."
                )
        self._script_path = ida_server.__file__
        self._rpyc_config = dict(self._rpyc_config)
        timeout = self._settings.timeout
        self._rpyc_config["sync_request_timeout"] = timeout if timeout > 0 else None

        # Determine if 64 bit.
        if "is_64_bit" in self._settings:
            warnings.warn(f"'is_64_bit' is no longer used. Please set 'bitness' instead.", DeprecationWarning)
            self._bitness = 64 if self._settings.is_64_bit else 32
        else:
            self._bitness = bitness

        if self._bitness is None:
            input_path = str(input_path)
            # First check if input file is a .idb or .i64
            if input_path.endswith(".i64"):
                is_64_bit = True
            elif input_path.endswith(".idb"):
                is_64_bit = False
            elif processor in (ProcessorType.ARM64, ProcessorType.x64):
                is_64_bit = True
            elif processor in (ProcessorType.ARM, ProcessorType.x86):
                is_64_bit = False
            else:
                is_64_bit = utils.is_64_bit(input_path)
        else:
            is_64_bit = False

        # Find ida executable within ida_dir.
        self._ida_exe = self._find_ida_exe(self._ida_path, is_64_bit)

        self._running = False

        self._detach = detach and sys.platform != "win32"
        self._socket_path = None
        self._process = None
        self._bridge = None
        self._root = None

        self._BADADDR = None
        self._idaapi = None
        self._idc = None
        self._idautils = None
        self._ida_auto = None
        self._ida_bitrange = None
        self._ida_bytes = None
        self._ida_funcs = None
        self._ida_gdl = None
        self._ida_name = None
        self._ida_xref = None
        self._ida_ua = None
        self._ida_idp = None
        self._ida_ida = None
        self._ida_lines = None
        self._ida_nalt = None
        self._ida_hexrays = None
        self._ida_segment = None
        self._ida_loader = None
        self._ida_typeinf = None
        self._ida_entry = None
        self._ida_struct = None
        self._ida_frame = None
        self._ida_search = None
        self._ida_arm = None
        self._ida_intel = None
        self._ida_helpers = None

    def _initialize_bridge(self):
        """
        Initialize components on bridge.
        """
        # Redirect output.
        self._bridge.modules.sys.stderr = sys.stderr
        self._bridge.modules.sys.stdout = sys.stdout
        remote_logger = self._bridge.modules.logging.getLogger()
        remote_logger.parent = logger
        remote_logger.setLevel(logger.getEffectiveLevel())

        # Import IDA modules.
        self._idaapi: idaapi = self._bridge.root.getmodule("idaapi")
        self._idc: idc = self._bridge.root.getmodule("idc")
        self._BADADDR: int = self._idc.BADADDR
        self._idautils: idautils = self._bridge.root.getmodule("idautils")
        self._ida_auto: ida_auto = self._bridge.root.getmodule("ida_auto")
        self._ida_bitrange: ida_bitrange = self._bridge.root.getmodule("ida_bitrange")
        self._ida_bytes: ida_bytes = self._bridge.root.getmodule("ida_bytes")
        self._ida_funcs: ida_funcs = self._bridge.root.getmodule("ida_funcs")
        self._ida_gdl: ida_gdl = self._bridge.root.getmodule("ida_gdl")
        self._ida_name: ida_name = self._bridge.root.getmodule("ida_name")
        self._ida_xref: ida_xref = self._bridge.root.getmodule("ida_xref")
        self._ida_ua: ida_ua = self._bridge.root.getmodule("ida_ua")
        self._ida_idp: ida_idp = self._bridge.root.getmodule("ida_idp")
        self._ida_ida: ida_ida = self._bridge.root.getmodule("ida_ida")
        self._ida_lines: ida_lines = self._bridge.root.getmodule("ida_lines")
        self._ida_nalt: ida_nalt = self._bridge.root.getmodule("ida_nalt")
        self._ida_hexrays: ida_hexrays = self._bridge.root.getmodule("ida_hexrays")
        self._ida_segment: ida_segment = self._bridge.root.getmodule("ida_segment")
        self._ida_loader: ida_loader = self._bridge.root.getmodule("ida_loader")
        self._ida_typeinf: ida_typeinf = self._bridge.root.getmodule("ida_typeinf")
        self._ida_entry: ida_entry = self._bridge.root.getmodule("ida_entry")
        try:
            #IDA 8.5 + no longer has ida_struct.
            self._ida_struct: ida_struct = self._bridge.root.getmodule("ida_struct")
        except ImportError:
            self._ida_struct = None
        self._ida_frame: ida_frame = self._bridge.root.getmodule("ida_frame")
        self._ida_search: ida_search = self._bridge.root.getmodule("ida_search")

        # Need to first add our custom sdk package to the path to import custom modules.
        from . import sdk
        self._bridge.modules.sys.path.extend(sdk.__path__)

        self._ida_arm: ida_arm = self._bridge.root.getmodule("ida_arm")
        self._ida_intel: ida_intel = self._bridge.root.getmodule("ida_intel")
        self._ida_helpers: ida_helpers = self._bridge.root.getmodule("ida_helpers")

    def _get_recent_ida_logs(self):
        """
        Retrieves the last few lines of the IDA logs for the current input file.
        """
        log_path = self.input_path.parent / (self.input_path.name + "_ida.log")
        logger.debug(f"Searching for the IDA log file at {log_path}.")
        if os.path.exists(log_path):
            with (open(log_path, "r") as f):
                return ("***************** Recent IDA Logs Below *****************\n"
                        f'{"".join(f.readlines()[-30:])}\n'
                        "******************** End of IDA Logs ********************\n"
                        f'Open the file at "{log_path}" to view all of the logs.')
        else:
            return "Could not find the IDA log file."

    def unix_connect(self, socket_path) -> rpyc.Connection:
        """
        Connects to bridge using unix socket.
        """
        retry = self._settings.retry_count
        for i in range(retry):
            try:
                logger.debug(f"Connecting to socket path: {socket_path}, try {i + 1}")
                stream = SocketStream.unix_connect(socket_path)
                link = factory.connect_stream(stream, rpyc.classic.SlaveService, config=self._rpyc_config)
                link.ping()
                logger.debug(f"Connected to {socket_path}")
                return link
            except socket.error:
                time.sleep(self._settings.retry_wait)
                continue

        raise DragodisError(f"Could not connect to {socket_path} after {retry} tries.\n{self._get_recent_ida_logs()}")

    def win_connect(self, pipe_name) -> rpyc.Connection:
        """
        Connects to bridge using Windows named pipe.
        """
        retry = self._settings.retry_count
        pipe_name = NamedPipeStream.NAMED_PIPE_PREFIX + pipe_name
        import pywintypes  # noqa
        for i in range(retry):
            try:
                logger.debug(f"Connecting to pipe: {pipe_name}, try {i + 1}")
                stream = NamedPipeStream.create_client(pipe_name)
                link = factory.connect_stream(stream, rpyc.classic.SlaveService, config=self._rpyc_config)
                link.ping()
                logger.debug(f"Connected to {pipe_name}")
                return link
            except pywintypes.error:
                time.sleep(self._settings.retry_wait)
                continue

        raise DragodisError(f"Could not connect to {pipe_name} after {retry} tries.\n{self._get_recent_ida_logs()}")

    def start(self):
        if self._running:
            raise ValueError(f"IDA disassembler already running.")

        # Create unique named pipe or socket path, depending on OS.
        socket_path = None
        pipe_name = None
        if sys.platform == "win32":
            pipe_name = str(uuid.uuid4())
        else:
            socket_path = tempfile.mktemp(prefix="dragodis_")

        # We need to temporarily change the current directory to be within the ida path so we don't
        # have spaces in script file path.
        # For an unknown reason, IDA hates spaces in its script path.
        orig_cwd = os.getcwd()
        try:
            os.chdir(self._ida_path)
            script_path = os.path.relpath(self._script_path, self._ida_path)
            # Create the command to start IDA with the bridge_server script
            command = [
                self._ida_exe,
                "-P",
                "-a",
                "-A",
                f'-S""{script_path}" "{pipe_name or socket_path}""',
            ]
            if self._settings.create_log:
                command.append(f'-L"{self.input_path}_ida.log"')
            if self._processor:
                command.append(f"-p{self._processor}")
            if self._filetype:
                command.append(f"-T{self._filetype}")
            command.extend(self._settings.extra_args)
            command.append(f'"{self.input_path}"')  # Input file MUST be last!

            command = " ".join(command)
            logger.debug(f"Running IDA with command: {command}")

            self._process = subprocess.Popen(
                command,
                shell=sys.platform != "win32",
                preexec_fn=os.setpgrp if self._detach else None
            )
            atexit.register(self._process.kill)
        finally:
            os.chdir(orig_cwd)

        logger.debug(f"Initializing IDA Bridge connection...")
        if socket_path:
            self._bridge = self.unix_connect(socket_path)
            # Remember socket path so we can close it later.
            self._socket_path = socket_path
        elif pipe_name:
            self._bridge = self.win_connect(pipe_name)
        else:
            raise RuntimeError("Unexpected error. Failed to setup socket or pipe.")

        self._initialize_bridge()
        # Keep a hold of the root remote object to prevent rpyc from prematurely closing on us.
        self._root = self._bridge.root
        self._running = True
        if self._bitness is not None:
            self.force_bitness(self._bitness)
        if self._analyze:
            self.analyze()
        else:
            logger.debug("Skipping autoanalysis.")
        logger.debug("IDA Disassembler ready!")

    def stop(self, *exc_info):
        if not self._running:
            return

        logger.debug("Shutting down IDA Bridge server...")

        # Before we close the bridge, remove connection to local logger to prevent logs being sent out afterwards.
        self._bridge.modules.logging.getLogger().parent = None

        self._bridge.close()
        self._root = None
        self._bridge = None
        self._BADADDR = None
        self._idaapi = None
        self._idc = None
        self._idautils = None
        self._ida_auto = None
        self._ida_bitrange = None
        self._ida_bytes = None
        self._ida_funcs = None
        self._ida_gdl = None
        self._ida_name = None
        self._ida_xref = None
        self._ida_ua = None
        self._ida_idp = None
        self._ida_ida = None
        self._ida_lines = None
        self._ida_nalt = None
        self._ida_hexrays = None
        self._ida_segment = None
        self._ida_loader = None
        self._ida_typeinf = None
        self._ida_entry = None
        self._ida_struct = None
        self._ida_frame = None
        self._ida_search = None
        self._ida_arm = None
        self._ida_intel = None
        self._ida_helpers = None

        # Wait for server to shutdown completely.
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.error("Failed to properly close IDA process.")
            self._process.kill()

        if self._socket_path:
            os.remove(self._socket_path)
            self._socket_path = None

        self._running = False
        logger.debug("IDA Bridge server closed.")
        self._delete_temp_files()

    def _async(self, proxy_func) -> Callable[..., rpyc.AsyncResult]:
        """
        Runs the given proxied function asynchronously.
        Good for functions that we don't care to get results back from.
        """
        return rpyc.async_(proxy_func)

    def analyze(self) -> None:
        """
        Instruct IDA to initiate and wait for auto analysis completion.
        """
        if not self._running:
            logger.error("Cannot run IDARemoteDisassembler.analyze() without a connected IDA instance.")
            return
        logger.debug("Running autoanalysis.")
        self._idc.set_flag(self._idc.INF_GENFLAGS, self._idc.INFFL_AUTO, 1)
        #To avoid timeouts, run it as async but block until complete here.
        self._async(self._idc.auto_wait)().wait()

    def teleport(self, func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Look for any arguments that pass along the disassembler object itself
            # and replace them with a local instance in IDA.
            # This helps to greatly improve performance.
            new_args = []
            for arg in args:
                if arg is self:
                    self._bridge.execute("import dragodis")
                    arg = self._bridge.eval("dragodis.IDA()")
                new_args.append(arg)
            args = tuple(new_args)

            return self._bridge.teleport(func)(*args, **kwargs)

        return wrapper
