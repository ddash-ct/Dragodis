
import pytest

import dragodis
from dragodis.ida import IDARemote, IDALocal


def test_teleport_ida(disassembler):
    # Test basic
    @disassembler.teleport
    def teleported(addr):
        import idc
        return idc.get_strlit_contents(addr)
    assert teleported(0x40C000) == b"Idmmn!Vnsme "

    # Test disassembler gets converted to local version.
    @disassembler.teleport
    def teleported(dis):
        from dragodis.ida.disassembler import IDALocalDisassembler
        return isinstance(dis, IDALocalDisassembler)
    assert teleported(disassembler)


def test_shellcode_x86(shared_datadir, disassembler_params):
    params = {
        **disassembler_params,
        "file_path": str(shared_datadir / "strings_x86 .text[00401000,0040102a].bin"),
        "processor": dragodis.PROCESSOR_X86,
    }
    if params["use_idalib"]:
        pytest.skip("FIXME: idalib crashes with arguments.")

    try:
        with dragodis.open_program(**params) as dis:
            assert dis.is_x86
            insn = dis.get_instruction(0x0d)
            assert insn.mnemonic == "movsx"
    except dragodis.NotInstalledError as e:
        pytest.skip(str(e))


def test_shellcode_arm(shared_datadir, disassembler_params):
    params = {
        **disassembler_params,
        "file_path": str(shared_datadir / "strings_arm .text[000103fc,0001045b].bin"),
        "processor": dragodis.PROCESSOR_ARM,
        "bitness": 32,
    }
    if params["use_idalib"]:
        pytest.skip("FIXME: idalib crashes with arguments.")

    try:
        with dragodis.open_program(**params) as dis:
            assert dis.is_arm
            assert dis.bit_size == 32
            if dis.name == dragodis.BACKEND_IDA:
                assert dis._ida_ua.create_insn(0x14)
            insn = dis.get_instruction(0x14)
            assert insn.mnemonic == "strb"
    except dragodis.NotInstalledError as e:
        pytest.skip(str(e))


@pytest.mark.idalib
@pytest.mark.x86
def test_ida_with_idalib(shared_datadir):
    """
    Tests IDA backend disassembler using idalib library.
    """
    pytest.importorskip("idapro", reason="idalib not installed")

    input_path = shared_datadir / "strings_x86"
    try:
        with dragodis.open_program(str(input_path), "ida", use_idalib=True) as dis:
            assert isinstance(dis, IDALocal)
            insn = dis.get_instruction(0x401000)
            assert insn.mnemonic == "push"
    except dragodis.NotInstalledError as e:
        pytest.skip(str(e))


@pytest.mark.ida
@pytest.mark.x86
def test_ida_with_rpyc(shared_datadir):
    """
    Tests IDA backend disassembler using rpyc library.
    """
    input_path = shared_datadir / "strings_x86"
    try:
        with dragodis.open_program(str(input_path), "ida", use_idalib=False) as dis:
            assert isinstance(dis, IDARemote)
            insn = dis.get_instruction(0x401000)
            assert insn.mnemonic == "push"
    except dragodis.NotInstalledError as e:
        pytest.skip(str(e))
