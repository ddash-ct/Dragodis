
def test_basic(disassembler):
    strings = list(disassembler.strings())
    assert set((entry.address, str(entry)) for entry in strings) >= {
        # A handful of the expected strings we should see.
        # (0x40b208, "MM/dd/yy"),  # vivisect fails to find this
        (0x40a96c, "GetProcessWindowStation"),
        # (0x40ca56, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),  # vivisect fails to find this
        (0x40c000, "Idmmn!Vnsme "),
        (0x40a748, "Microsoft Visual C++ Runtime Library"),
        (0x40a778, "<program name unknown>"),
    }

    for string in strings:
        if string.address == 0x40c000:
            assert bytes(string) == b"Idmmn!Vnsme "
