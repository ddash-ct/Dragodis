"""
Stores global constants used in dragodis
"""

# backend disassembler names
BACKEND_GHIDRA = "Ghidra"
BACKEND_IDA = "IDA"
BACKEND_VIVISECT = "Vivisect"

# Here for backwards compatibility.
from dragodis.config import settings
BACKEND_DEFAULT = settings.disassembler
