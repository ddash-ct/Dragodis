from __future__ import annotations
from typing import TYPE_CHECKING, NamedTuple

import envi
from vivisect.const import *

from dragodis.interface import Reference, ReferenceType
from dragodis.vivisect.viv import XRef

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectReference(Reference):

    def __init__(self, vivisect: VivisectFlatAPI, xref: XRef):
        self._vivisect = vivisect
        self._xref = XRef(*xref)

    @property
    def from_address(self) -> int:
        return self._xref.fromva

    @property
    def to_address(self) -> int:
        return self._xref.tova

    @property
    def is_code(self) -> bool:
        return self._xref.rtype == REF_CODE

    @property
    def is_data(self) -> bool:
        return self._xref.rtype in (REF_DATA, REF_PTR)

    @property
    def type(self) -> ReferenceType:
        if self.is_code:
            if self._xref.rflags & (envi.BR_PROC | envi.BR_DEREF | envi.BR_TABLE):
                return ReferenceType.code_call
            elif self._xref.rflags & envi.BR_COND:
                return ReferenceType.code_jump
            elif self._xref.rflags & (envi.BR_FALL | envi.BR_ARCH):
                return ReferenceType.ordinary_flow
        elif self.is_data:
            # TODO: Determine if there is a way to distinguish read/write.
            return ReferenceType.data
        else:
            return ReferenceType.unknown
