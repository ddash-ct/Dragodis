# Installation

Getting Dragodis set up is simple, but varies slightly depending on which
disassembler(s) you plan to use.

First install dragodis like normal:

```bash
pip install dragodis
```

Then follow one or more of the following instructions to setup your favorite disassembler.

## IDA

1. Download and install [IDA Pro](https://www.hex-rays.com) with Python 3 mode. (Tested on version 8.1, 8.5, and 9.1) Make sure to run IDA at least once to accept the EULA.
2. Set the `IDADIR` environment variable to point to the directory where IDA is installed. (e.g. `C:\Program Files\IDA Pro 9.1`)
3. Dragodis uses [rpyc](https://rpyc.readthedocs.io/en/latest) to communicate with IDA.
   This is installed automatically when you install Dragodis. However, if you are using a different python
   environment than IDA, you can manually install the library in the IDA environment using the `--target` flag.

   ```bash
   py -3.11 -m pip install rpyc --target="%IDADIR%\python\3"
   ```

4. **WINDOWS**: If you are on Windows, you'll also need to install `pywin32` in the IDA interpreter.

   ```bash
   py -3.11 -m pip install pywin32 --target="%IDADIR%\python\3"
   ```

5. If using IDA 9.0+, we recommend installing the [idalib](https://docs.hex-rays.com/user-guide/idalib) library to improve performance.


## Ghidra

1. Download and install [Ghidra](https://ghidra-sre.org) to a desired location.
2. Set the `GHIDRA_INSTALL_DIR` environment variable to point to the directory where Ghidra is installed.
   (e.g. `C:\Tools\ghidra_9.1.2_PUBLIC`)


## Vivisect

Nothing needs to be done. Vivisect is included as a dependency when installing Dragodis.


## Set Preferred Disassembler

To set a preferred disassembler for when a script does not explicitly define one, set the `DRAGODIS_DISASSEMBLER` environment
variable to either `ida`, `ghidra`, or `vivisect`. The Vivisect disassembler will be chosen if this is not setup.
