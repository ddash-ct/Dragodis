
from __future__ import annotations

import functools
from typing import Union, List, TYPE_CHECKING, NamedTuple, Optional

import envi
from vivisect import LOC_IMPORT
from vivisect.exc import InvalidFunction

from dragodis.exceptions import NotExistError
from dragodis.vivisect.data_type import VivisectDataType
from dragodis.vivisect.function_argument_location import VivisectArgumentLocation, VivisectRegisterLocation, \
    VivisectStackLocation
from dragodis.interface.function_signature import FunctionSignature, FunctionParameter
from .viv import FunctionApi, Symbol, Location

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


@functools.cache
def _get_emulator(vw) -> envi.Emulator:
    # Caching call to get emulator because obtaining the emulator is heavy
    # and we only need it for statically obtaining calling conventions.
    return vw.getEmulator()


class VivisectFunctionParameter(FunctionParameter):

    def __init__(self, vivisect: VivisectFlatAPI, signature: VivisectFunctionSignature, ordinal: int):
        super().__init__(signature)
        self._vivisect = vivisect
        self._ordinal = ordinal

    @property
    def _api(self) -> FunctionApi:
        return self.signature._api

    @_api.setter
    def _api(self, value: FunctionApi):
        self.signature._api = value

    @property
    def _symbol(self) -> Symbol:
        return self._api.args[self._ordinal]

    @_symbol.setter
    def _symbol(self, symbol: Symbol):
        api = self._api
        api.args[self._ordinal] = symbol
        self._api = api

    @property
    def name(self) -> str:
        return self._symbol.symname or f"arg{self._ordinal}"

    @name.setter
    def name(self, new_name: str):
        self._symbol = self._symbol._replace(symname=new_name)

    @property
    def ordinal(self) -> int:
        return self._ordinal

    @property
    def data_type(self) -> VivisectDataType:
        return VivisectDataType(self._vivisect, self._symbol.typename)

    @data_type.setter
    def data_type(self, new_type: Union[str, VivisectDataType]):
        self._symbol = self._symbol._replace(typename=str(new_type))

    @property
    def location(self) -> VivisectArgumentLocation:
        emu = _get_emulator(self._vivisect._workspace)
        cc = emu.getCallingConvention(self.signature.calling_convention.strip("_"))
        if not cc:
            raise ValueError(f"Invalid calling convention: {self.signature.calling_convention}")

        # Account for return address if placed on stack.
        # Vivisect's stack offset is post-call, but we are pre-call.
        retaddr_align = 0
        ret_type, _ = cc.retaddr_def
        if ret_type in (envi.CC_STACK, envi.CC_STACK_INF):
            retaddr_align = cc.align

        # If ordinal is beyond arg_def, then check if arguments are to be stored in
        # the stack.
        if self._ordinal >= len(cc.arg_def):
            arg_type, arg_val = cc.arg_def[-1]
            if arg_type == envi.CC_STACK_INF:
                stack_offset = arg_val + (self._ordinal - len(cc.arg_def) + 1) * cc.align - retaddr_align
                return VivisectStackLocation(stack_offset=stack_offset)
            else:
                raise ValueError(
                    f"Invalid number of arguments for calling convention: {self.signature.calling_convention}"
                )

        # Determine location based on calling convention.
        arg_type, arg_val = cc.arg_def[self._ordinal]
        if arg_type == envi.CC_REG:
            return VivisectRegisterLocation(self._vivisect, idx=arg_val)
        elif arg_type in (envi.CC_STACK, envi.CC_STACK_INF):
            return VivisectStackLocation(stack_offset=arg_val - retaddr_align)

        raise ValueError(f"Invalid argument type: {arg_type}")


class VivisectFunctionSignature(FunctionSignature):

    def __init__(self, vivisect: VivisectFlatAPI, addr: int):
        if addr < 0:
            raise NotExistError(f"Address cannot be negative: {addr}")
        self._vivisect = vivisect
        self._addr = addr
        self._parameters = None
        _ = self._api  # Trigger pulling api to validate we have a function.

    @property
    def _location(self) -> Location:
        location = self._vivisect._workspace.getLocation(self._addr)
        if not location:
            raise NotExistError(f"Address cannot be located: {hex(self._addr)}")
        location = Location(*location)
        if location.va != self._addr:
            raise NotExistError(f"Got invalid start address {hex(location.va)}, expected {hex(self._addr)}")
        return location

    @_location.setter
    def _location(self, location: Location):
        self._vivisect._workspace.addLocation(*location)

    @property
    def _api(self) -> FunctionApi:
        """Obtains the 'Api' object for the Function or Import"""
        vw = self._vivisect._workspace
        location = self._location
        if location.ltype == LOC_IMPORT:
            import_name = location.tinfo
            api = vw.getImpApi(import_name)
            if not api:
                # Vivisect doesn't have a defined signature for the import. (see vivisect/impapi/)
                # Providing a default, just like it does in VivisectEmulator.getCallApi()
                api = ("int", None, vw.getMeta("DefaultCall"), "UnknownApi", ())
            return FunctionApi(*api)
        try:
            return FunctionApi(*vw.getFunctionApi(location.va))
        except InvalidFunction as e:
            raise NotExistError(f"Function at {hex(location.va)} does not exist: {e}")

    @_api.setter
    def _api(self, api: FunctionApi):
        """Updates the internal Function or Import Api"""
        location = self._location
        if location.ltype == LOC_IMPORT:
            import_name = location.tinfo
            self._vivisect._workspace.updateApiDef({import_name.lower(): tuple(api)})
        else:
            self._vivisect._workspace.setFunctionApi(location.va, tuple(api))

    @property
    def name(self) -> str:
        location = self._location
        if location.ltype == LOC_IMPORT:
            # NOTE: Not using funcname from Import Api because that name defines the internal ntdll import.
            *_, func_name = location.tinfo.rpartition(".")
            return func_name
        else:
            # funcname only provided if Vivisect was able to produce a non-generic name.
            return self._api.funcname or self._vivisect._workspace.getName(self._addr)

    @name.setter
    def name(self, new_name: Optional[str]):
        location = self._location
        if location.ltype == LOC_IMPORT:
            namespace, *_ = location.tinfo.rpartition(".")
            self._location = location._replace(tinfo=f"{namespace}.{new_name}")
        else:
            self._api = self._api._replace(funcname=new_name)

    @property
    def calling_convention(self) -> str:
        return "__" + self._api.callconv

    @calling_convention.setter
    def calling_convention(self, name: str):
        # Ensure this is a valid calling convention.
        name = name.strip("_")
        if name == "fastcall":
            # Assume they meant Microsoft's
            name = "msfastcall"
        emu = _get_emulator(self._vivisect._workspace)
        if not emu.hasCallingConvention(name):
            valid = [cc_name for cc_name, _ in emu.getCallingConventions()]
            raise ValueError(f"Invalid calling convention: {name}\nMust be one of: {', '.join(valid)}")
        self._api = self._api._replace(callconv=name)

    @property
    def return_type(self) -> VivisectDataType:
        return VivisectDataType(self._vivisect, self._api.rettype)

    @return_type.setter
    def return_type(self, data_type: Union[VivisectDataType, str]):
        self._api = self._api._replace(rettype=str(data_type))

    def _update_parameter_ordinals(self):
        """Updates the ordinals in the parameter cache."""
        if self._parameters:
            for ordinal, param in enumerate(self._parameters):
                param._ordinal = ordinal

    @property
    def parameters(self) -> List[VivisectFunctionParameter]:
        if self._parameters is None:
            self._parameters = [
                VivisectFunctionParameter(self._vivisect, self, ordinal)
                for ordinal in range(len(self._api.args))
            ]
        return self._parameters

    def replace_parameters(self, data_types: List[str]):
        api = self._api
        names = [symbol.symname for symbol in api.args] + [f"arg{i}" for i in range(len(api.args), len(data_types))]
        self._api = api._replace(args=list(zip(data_types, names)))

        # Reset cache
        self._parameters = None

    def add_parameter(self, data_type: str) -> VivisectFunctionParameter:
        api = self._api
        idx = len(api.args)
        self._api = api._replace(args=api.args + [(data_type, f"arg{idx}")])

        # Update _parameters cache.
        if self._parameters is not None:
            new_param = VivisectFunctionParameter(self._vivisect, self, len(self._parameters))
            self._parameters.append(new_param)
            return new_param
        else:
            return self.parameters[-1]

    def remove_parameter(self, ordinal: int):
        api = self._api

        num_parameters = len(api.args)
        if ordinal < 0:
            ordinal += num_parameters
        if ordinal not in range(num_parameters):
            raise NotExistError(f"Parameter doesn't exist at ordinal: {ordinal}")

        new_args = []
        for idx, (typename, name) in enumerate(api.args):
            if idx == ordinal:
                continue
            # Fix argument name if default name was set.
            if idx > ordinal and name == f"arg{idx}":
                name = f"arg{idx - 1}"
            new_args.append((typename, name))
        self._api = api._replace(args=new_args)

        # Update parameters cache.
        if self._parameters is not None:
            del self._parameters[ordinal]
            self._update_parameter_ordinals()

    def insert_parameter(self, ordinal: int, data_type: str) -> VivisectFunctionParameter:
        api = self._api
        num_parameters = len(api.args)
        if ordinal < 0:
            ordinal += num_parameters
        if ordinal not in range(num_parameters):
            raise ValueError(f"Invalid ordinal for parameter insertion: {ordinal}")

        new_args = []
        for idx, (typename, name) in enumerate(api.args):
            if idx == ordinal:
                new_args.append((data_type, f"arg{idx}"))
            # Fix argument name if default name was set.
            if idx >= ordinal and name == f"arg{idx}":
                name = f"arg{idx + 1}"
            new_args.append((typename, name))
        self._api = api._replace(args=new_args)

        # Update parameters cache.
        if self._parameters is not None:
            new_param = VivisectFunctionParameter(self._vivisect, self, ordinal)
            self._parameters.insert(ordinal, new_param)
            self._update_parameter_ordinals()
            return new_param
        else:
            return self.parameters[ordinal]
