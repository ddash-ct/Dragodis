
import pytest
from dragodis import BACKEND_VIVISECT


# TODO: Better support pointers
@pytest.mark.parametrize("name,size", [
    ("char", 1),
    ("byte", 1),
    ("int", 4),
    ("dword", 4),
    ("word", 2),
    ("char *", 4),
    ("float", 4),
    ("double", 8),
])
def test_get_data_type_all(disassembler, name, size):
    if disassembler.name == BACKEND_VIVISECT and name in ("float", "double"):
        pytest.skip("Vivisect doesn't support float/double")
    data_type = disassembler.get_data_type(name)
    assert data_type
    assert data_type.name == name
    assert data_type.size == size


def test_array_data_types_all(disassembler):
    if disassembler.name == BACKEND_VIVISECT:
        pytest.skip("Vivisect doesn't support arrays")
    data_type = disassembler.get_data_type("byte[10]")
    assert data_type
    assert data_type.count == 10
    assert data_type.base.name == "byte"
