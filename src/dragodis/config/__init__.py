
import os
from pathlib import Path

import platformdirs
from dynaconf import Dynaconf, Validator

default_config = Path(__file__).parent / "settings.toml"
user_config = platformdirs.user_config_path("dragodis", appauthor="dc3") / "settings.toml"
local_config = Path("dragodis.toml")


DISASSEMBLERS = ["ida", "ghidra", "vivisect"]

settings = Dynaconf(
    envvar_prefix="DRAGODIS",
    load_dotenv=True,
    merge_enabled=True,
    settings_files=[
        default_config,
        user_config,
        local_config,
    ],
    validators=[
        Validator(
            "DISASSEMBLER",
            cast=lambda v: v.lower(),
            is_in=DISASSEMBLERS,
            messages={
                "operations": "'{value}' for {name} is invalid. Must be one of: {op_value}",
            }
        ),
    ],
)

# For disassemblers, provide empty environment variables if not setup.
if "IDADIR" not in os.environ:
    os.environ["IDADIR"] = ""
    settings.ida.install_dir = None
if "GHIDRA_INSTALL_DIR" not in os.environ:
    os.environ["GHIDRA_INSTALL_DIR"] = ""
    settings.ghidra.install_dir = None
