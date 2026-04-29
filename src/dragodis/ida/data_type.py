
from __future__ import annotations
from typing import TYPE_CHECKING, Optional

from dragodis.interface.data_type import DataType

if TYPE_CHECKING:
    from dragodis import IDA
    import ida_typeinf


class IDADataType(DataType):

    def __init__(
            self,
            ida: IDA,
            tinfo: "ida_typeinf.tinfo_t" = None,
            address: int = None
    ):
        if not (tinfo or address):
            raise ValueError(f"Must provide a tinfo object or address.")
        self._ida = ida
        self._tinfo = tinfo
        self._address = address

    @classmethod
    def _create_tinfo(cls, ida: IDA, name: str) -> Optional["ida_typeinf.tinfo_t"]:
        """
        Attempts to create a tinfo_t object from given type name.
        """
        if ida.ida_version >= 850:
            # Newer version of tinfo_t() constructor can accept name directly for simple types.
            try:
                return ida._ida_typeinf.tinfo_t(name.lower())
            except ValueError:
                # Try again but with _UPPERCASE format.
                try:
                    return ida._ida_typeinf.tinfo_t(f"_{name.upper()}")
                except ValueError:
                    pass

        # Pull from simple types.
        _type_map = {
            "void": ida._ida_typeinf.BT_VOID,
            "byte": ida._ida_typeinf.BTF_BYTE,
            "char": ida._ida_typeinf.BTF_CHAR,
            "short": ida._ida_typeinf.BT_INT16,
            "word": ida._ida_typeinf.BT_INT16,
            "int": ida._ida_typeinf.BTF_INT,
            "dword": ida._ida_typeinf.BT_INT32,
            "long": ida._ida_typeinf.BT_INT64,
            "qword": ida._ida_typeinf.BT_INT64,
            "float": ida._ida_typeinf.BTF_FLOAT,
            "double": ida._ida_typeinf.BTF_DOUBLE,
        }
        if name.lower() in _type_map:
            return ida._ida_typeinf.tinfo_t(_type_map[name.lower()])

        # If a pointer, create another tinfo object that is the pointer of the first.
        if name.endswith("*"):
            if ref_tif := cls._create_tinfo(ida, name[:-1].strip()):
                tif = ida._ida_typeinf.tinfo_t()
                tif.create_ptr(ref_tif)
                return tif
            else:
                return None

        # Create named type.
        # Name has to be uppercase for get_named_type() to work.
        tif = ida._ida_typeinf.tinfo_t()
        if tif.get_named_type(None, name.upper()):
            return tif

        return None

    @property
    def name(self) -> str:
        if self._tinfo:
            return str(self._tinfo).lower().strip("_")
        else:
            TYPE_MAP = {
                self._ida._idc.FF_BYTE: "byte",
                self._ida._idc.FF_WORD: "word",
                self._ida._idc.FF_DWORD: "dword",
                self._ida._idc.FF_QWORD: "qword",
                self._ida._idc.FF_OWORD: "oword",
                self._ida._idc.FF_TBYTE: "tbyte",
                self._ida._idc.FF_STRLIT: "char",
                self._ida._idc.FF_STRUCT: "struct",
                self._ida._idc.FF_FLOAT: "float",
                self._ida._idc.FF_DOUBLE: "double",
                self._ida._idc.FF_PACKREAL: "packed decimal real",
                self._ida._idc.FF_ALIGN: "alignment directive",
            }
            flags = self._ida._ida_bytes.get_flags(self._address)
            flags &= self._ida._ida_bytes.DT_TYPE
            return TYPE_MAP[flags]

    @property
    def size(self) -> int:
        if self._tinfo:
            return self._tinfo.get_size()
        else:
            flags = self._ida._ida_bytes.get_flags(self._address)
            flags &= self._ida._ida_bytes.DT_TYPE
            return self._ida._ida_bytes.get_data_elsize(self._address, flags)

    @property
    def base(self) -> IDADataType:
        if self._tinfo and self._tinfo.is_decl_array():
            return IDADataType(self._ida, self._tinfo.get_array_element())
        return self

    @property
    def count(self) -> int:
        if self._tinfo.is_decl_array():
            return self._tinfo.get_array_nelems()
        return 1
