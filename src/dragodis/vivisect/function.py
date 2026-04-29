from __future__ import annotations
from typing import Optional, TYPE_CHECKING

from dragodis.vivisect.viv import Location
from vivisect import LOC_IMPORT
from vivisect.tools import graphutil

from dragodis.exceptions import UnsupportedError
from dragodis.interface import Function, CommentType
from dragodis.vivisect.flowchart import VivisectFlowchart
from dragodis.vivisect.stack import VivisectStackFrame

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectFunction(Function):
    def __init__(self, vivisect: VivisectFlatAPI, addr: int):
        super().__init__(vivisect)
        self._vivisect = vivisect
        self._addr = addr

    def __contains__(self, addr: int) -> bool:
        return self._vivisect._workspace.getFunction(addr) == self.start

    @property
    def start(self) -> int:
        return self._addr

    @property
    def end(self) -> int:
        # This may be incorrect in some cases
        # Currently not aware of a way to directly get the end address of a function
        if func_size := self._vivisect._workspace.getFunctionMeta(self.start, "Size"):
            return self.start + func_size
        raise ValueError(f"End of function starting at {hex(self.start)} is unknown")

    @property
    def flowchart(self) -> VivisectFlowchart:
        # Vivisect's getFunctionGraph() doesn't actually provide the complete graph for the function.
        # Need to use their graphutil.buildFunctionGraph instead. (This is used within the UI)
        graph = graphutil.buildFunctionGraph(self._vivisect._workspace, self._addr)
        return VivisectFlowchart(self._vivisect, graph)

    @property
    def name(self) -> str:
        # Return the signature's name because that doesn't have the address appended
        # to matched functions.
        *_, name = self.signature.name.rpartition(".")
        return name

    @name.setter
    def name(self, new_name: Optional[str]):
        self.signature.name = new_name

    def get_comment(self, comment_type=CommentType.anterior) -> Optional[str]:
        return self._vivisect.get_comment(self.start)

    def set_comment(self, comment: str, comment_type=CommentType.anterior):
        # While we technically ignore the comment_type for this disasembler.
        # We should only support the types that make sense.
        if comment_type in (CommentType.anterior, CommentType.plate, CommentType.repeatable):
            self._vivisect.set_comment(self.start, comment)
        else:
            raise ValueError(f"Invalid comment type for function: {repr(comment_type)}")

    @property
    def stack_frame(self) -> VivisectStackFrame:
        return VivisectStackFrame(self._vivisect, self.start)

    @property
    def is_library(self) -> bool:
        # Vivisect has limited ability to detect library functions.
        # Therefore, we can only test if it's a thunk for an import.
        if import_name := self._vivisect._workspace.getFunctionMeta(self.start, "Thunk"):
            # NOTE: We can't use getLocationByName() because Vivisect includes the address within the name,
            # which is less than helpful...
            for *_, name in self._vivisect._workspace.getImports():
                if name == import_name:
                    return True
        return False

    def undefine(self, clear_instructions: bool = False):
        start, end = self.start, self.end
        self._vivisect._workspace.delFunction(start)
        if clear_instructions:
            self._vivisect.undefine(start, end)
