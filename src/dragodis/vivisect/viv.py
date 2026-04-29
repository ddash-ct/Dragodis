"""
Stores typed structureds for returned Vivisect objects.
"""
from __future__ import annotations
from typing import NamedTuple, Optional, Union, Any
from typing_extensions import TypedDict, NotRequired


class Symbol(NamedTuple):
    """Vivisect function symbol within function api or locals."""
    typename: str
    symname: str


class FunctionApi(NamedTuple):
    """Vivisect function api metadata."""
    rettype: str
    retname: Optional[str]
    callconv: str
    funcname: Optional[str]
    args: list[Symbol]


# Need to subclass namedtuple instance to allow overriding __new__
class FunctionApi(FunctionApi):
    def __new__(cls, *args):
        # Automatically converts the .args to Symbol
        *args, symbols = args
        symbols = [Symbol(*syminfo) for syminfo in symbols]
        return super().__new__(cls, *args, symbols)

    def __iter__(self):
        # Convert symbols back to tuples if iterating.
        items = list(super().__iter__())
        items[-1] = tuple(items[-1])
        yield from items


class FunctionLocal(NamedTuple):
    """Vivisect function local tuple."""
    fva: int
    spdelta: int
    symtype: int
    syminfo: Union[int, Symbol]  # arg idx or symbol definition


class FunctionLocal(FunctionLocal):
    def __new__(cls, *args):
        # Automatically converts the .syminfo to Symbol
        *args, syminfo = args
        if not isinstance(syminfo, int):
            syminfo = Symbol(*syminfo)
        return super().__new__(cls, *args, syminfo)

    def __iter__(self):
        # Convert syminfo back to a tuple if iterating.
        items = list(super().__iter__())
        if isinstance(items[-1], Symbol):
            items[-1] = tuple(items[-1])
        yield from items


class Location(NamedTuple):
    """Vivisect location tuple"""
    va: int
    size: int
    ltype: int
    tinfo: Any


class Export(NamedTuple):
    """Vivisect export tuple"""
    va: int
    etype: int
    name: str
    filename: str


class XRef(NamedTuple):
    """Vivisect xref tuple"""
    fromva: int
    tova: int
    rtype: int
    rflags: int


class Segment(NamedTuple):
    """Vivisect segment tuple"""
    va: int
    size: int
    name: str
    filename: str


class MemoryMap(NamedTuple):
    """Vivisect memory map info"""
    va: int
    size: int
    flags: int
    filename: str


class CodeBlock(NamedTuple):
    """Vivisect code block tuple"""
    va: int
    size: int
    funcva: int


class GraphNodeProperties(TypedDict):
    cbva: int
    cbsize: int
    color: str
    rootnode: NotRequired[bool]


class GraphNode(NamedTuple):
    """Vivisect graph node tuple"""
    nid: int
    props: GraphNodeProperties


class GraphEdge(NamedTuple):
    """Vivisect graph edge tuple"""
    eid: int
    node1: int
    node2: int
    props: dict


class MemoryMapDef(NamedTuple):
    """Vivisect memory map."""
    mva: int
    mmaxva: int
    mmap: MemoryMap
    mbytes: bytes


class MemoryMapDef(MemoryMapDef):
    def __new__(cls, *args):
        # Automatically converts the .mmap to MemoryMap
        args = list(args)
        args[2] = MemoryMap(*args[2])
        return super().__new__(cls, *args)

    def __iter__(self):
        # Convert mmap back to a tuple if iterating.
        items = list(super().__iter__())
        if isinstance(items[2], MemoryMap):
            items[2] = tuple(items[2])
        yield from items
