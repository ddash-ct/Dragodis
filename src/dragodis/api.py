"""
Base interface for dragodis
"""
from __future__ import annotations

# Import available disassemblers so they get registered.
import os
import pathlib
from typing import Union, Type, TYPE_CHECKING

from dragodis import utils
from dragodis.constants import BACKEND_IDA, BACKEND_GHIDRA
from dragodis.ghidra import GhidraLocal, GhidraRemote
from dragodis.ida import IDALocal, IDARemote
from dragodis.vivisect import Vivisect
from dragodis.interface import FlatAPI, BackendDisassembler
from dragodis.interface.types import ProcessorType, FileType
from dragodis.config import settings


Vivisect = Vivisect


def IDA(*args, use_idalib: bool = None, **kwargs):
    if use_idalib is None:
        use_idalib = settings.ida.use_idalib
    if utils.in_ida() or (use_idalib and utils.have_idalib()):
        return IDALocal(*args, **kwargs)
    else:
        return IDARemote(*args, **kwargs)
IDA.name = BACKEND_IDA


def Ghidra(*args, **kwargs):
    # Need to dynamically provide Ghidra disassembler since detection can be wrong if
    # this module gets imported prematurely by a plugin before pyhidra sets up the interpreter.
    if utils.in_ghidra():
        return GhidraLocal(*args, **kwargs)
    else:
        return GhidraRemote(*args, **kwargs)
Ghidra.name = BACKEND_GHIDRA


if TYPE_CHECKING:
    Ghidra = GhidraLocal if utils.in_ghidra() else GhidraRemote
    IDA = IDALocal if (utils.in_ida() or utils.have_idalib()) else IDARemote


# Expose flat api when user wants to do typing.
class Disassembler(FlatAPI, BackendDisassembler):
    ...


def _get_class(name: str = None) -> Type[Disassembler]:
    # If name not provided, see if we can detect we are inside a disassembler. If so, use that.
    if not name:
        if utils.in_ida():
            return IDA
        if utils.in_ghidra():
            return Ghidra

    name = name or settings.disassembler
    if not name:
        raise ValueError(
            "No disassembler provided. "
            "Please provide disassembler name as an argument or by setting "
            "the environment variable 'DRAGODIS_DISASSEMBLER'."
        )
    if name.lower() == "ida":
        return IDA
    elif name.lower() == "ghidra":
        return Ghidra
    elif name.lower() == "vivisect":
        return Vivisect
    else:
        raise ValueError(f"Not a valid disassembler: {name}")


def open_program(
        file_path: Union[str, pathlib.Path],
        disassembler: str = None,
        processor: Union[ProcessorType, str] = None,
        filetype: Union[FileType, str] = None,
        analyze: bool = True,
        use_idalib: bool = None,
        **config
) -> Disassembler:
    """
    Opens given file in the given disassembler.

    :param file_path: Path to binary file to disassemble.
    :param disassembler: Name of disassembler to use.
        (Defaults to disassembler provided in DRAGODIS_DISASSEMBLER environment variable.)
    :param processor: Processor spec to use.
        (Defaults to auto-detection by underlying disassembler)
    :param filetype: Type of file to use.
        (Defaults to auto-detection by underlying disassembler)
    :param analyze: Determines whether autoanalysis should be conducted on the input file at startup.
    :param use_idalib: (IDA only) Determines whether to use the idalib library (if available).

    :param config: Arguments to pass to disassembler during instantiation.
        These arguments override the configuration defined in the `settings.toml` file.
        Non-applicable arguments will be ignored.

    :raises NotInstalledError: If the specified disassembler has not been installed.
    :raises ValueError: If the specified disassembler is not supported.
    """
    klass = _get_class(disassembler)
    file_path = pathlib.Path(file_path)
    if use_idalib is None:
        use_idalib = settings.ida.use_idalib
    args = {
        "processor": processor,
        "filetype": filetype,
        "analyze": analyze,
        "use_idalib": use_idalib,
        **config,
    }
    # Override args with backend prefixed keywords for chosen disassembler.
    prefix = f"{klass.name.lower()}_"
    for key, value in config.items():
        if key.startswith(prefix):
            args[key[len(prefix):]] = value

    return klass(file_path, **args)
