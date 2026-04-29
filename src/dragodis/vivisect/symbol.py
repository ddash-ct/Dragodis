from __future__ import annotations
from typing import Optional, Iterable, TYPE_CHECKING

from dragodis.utils import genproperty
from dragodis.vivisect.reference import VivisectReference
from dragodis.interface.symbol import Symbol, Import, Export
from dragodis.vivisect.viv import Location, Export as vExport
from vivisect import InvalidFunction

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectSymbol(Symbol):

    def __init__(self, vivisect: VivisectFlatAPI):
        self._vivisect = vivisect

    @genproperty
    def references_to(self) -> Iterable[VivisectReference]:
        yield from self._vivisect.references_to(self.address)


class VivisectImport(Import, VivisectSymbol):

    def __init__(self, vivisect: VivisectFlatAPI, location: Location):
        super().__init__(vivisect)
        self._location = Location(*location)

    @property
    def address(self) -> int:
        return self._location.va

    @property
    def name(self) -> str:
        lib_name, _, name = self._location.tinfo.rpartition(".")
        return name

    @property
    def namespace(self) -> Optional[str]:
        lib_name, _, name = self._location.tinfo.rpartition(".")
        return lib_name

    @property
    def thunk_address(self) -> Optional[int]:
        fullname = self._location.tinfo
        for ref in self.references_to():
            if ref.is_call:
                try:
                    if self._vivisect._workspace.getFunctionMeta(ref.from_address, "Thunk") == fullname:
                        return ref.from_address
                except InvalidFunction:
                    continue


class VivisectExport(Export, VivisectSymbol):

    def __init__(self, vivisect: VivisectFlatAPI, export: vExport):
        super().__init__(vivisect)
        self._export = vExport(*export)

    @property
    def address(self) -> int:
        return self._export.va

    @property
    def name(self) -> str:
        return self._export.name
