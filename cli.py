from enum import Enum
from dataclasses import dataclass
import sys
from typing import Union
from constants import VALID_KEY_LENGTHS

# Minimal number of command line arguments required by the program
MIN_NUM_ARGS = 5

class Function(Enum):
    ENCRYPT = '--encrypt'
    DECRYPT = '--decrypt'

class Mode(Enum):
    ECB = '--ecb'
    CBC = '--cbc'

@dataclass
class Parameters:
    function: Function
    mode: Mode
    key: str
    text: Union[str, None] = None
    bytes: Union[bytes, None] = None
    iv: Union[str, None] = None


def usage() -> None:
    """Print usage of the command line interface to the terminal window"""
    script_name = sys.argv[0]
    msg = f"""
    Usage:
    {script_name} --encrypt|--decrypt --ecb|--cbc [--file] <message/cryptogram/path to file> <key> [iv]

    Examples:
    {script_name} --encrypt --ecb "Hello, World!" "abcdefghijklmnop"
    {script_name} --decrypt --ecb "qazwsxedcrfvt" "abcdefghijklmnop"

    {script_name} --encrypt --cbc "Hello, World!" "abcdefghijklmnop" "qwertyuiopasdfgh"
    {script_name} --decrypt --cbc "qazwsxedcrfvt" "abcdefghijklmnop" "qwertyuiopasdfgh"

    {script_name} --encrypt --ecb --file "test-files/abc.txt" abcdefghijklmnop
    {script_name} --decrypt --cbc --file "output" abcdefghijklmnop ponmlkjihgfedcba

    Remarks:
    - the key needs to be either 16,24, or 32-byte long, provided in plaintext (16 ASCII characters, 1 byte each)
    - the iv (initialization vector) parameter is only needed for CBC mode. It is also required to be 16 characters long
    - the result of encryption is always saved into file called "output". This file can be later decrypted using our tool
    """
    print(msg)


def error(msg: Union[str, None]) -> None:
    """Print error message to the terminal window"""
    if msg:
        print(msg, file=sys.stderr)

def parse_cli() -> Parameters:
    """Parse command line parameters and return them inside of an object"""

    if len(sys.argv) < MIN_NUM_ARGS:
        msg = "Insufficient amount of arguments"
        error(msg)
        usage()
        exit(1)
    
    arg_pos = 1
    function: Function = None
    functions = [member.value for member in Function]
    if sys.argv[arg_pos] in functions:
        function = Function(sys.argv[arg_pos])
    else:
        msg = f"{sys.argv[arg_pos]} is not a valid option. Choose either --encrypt or --decrypt"
        error(msg)
        usage()
        exit()
    arg_pos += 1

    mode: Mode = None
    modes = [member.value for member in Mode]
    if sys.argv[arg_pos] in modes:
        mode = Mode(sys.argv[arg_pos])
    else:
        msg = f"{sys.argv[arg_pos]} is not a valid mode. Choose either --ecb or --cbc"
        error(msg)
        usage()
        exit()
    arg_pos += 1

    text = None
    loaded_bytes = None
    if sys.argv[arg_pos] == '--file':
        arg_pos += 1
        filename = sys.argv[arg_pos]
        with open(filename, 'rb') as file:
            loaded_bytes = file.read()

    else:
        text = ''
        if len(sys.argv[arg_pos]) > 0:
            text: str = sys.argv[arg_pos]
        else:
            msg = f"The message cannot be empty"
            error(msg)
            usage()
            exit()
    arg_pos += 1

    key: str = ''
    key_len = len(sys.argv[arg_pos])
    if key_len in VALID_KEY_LENGTHS:
        key: str = sys.argv[arg_pos]
    else:
        msg = f"The key needs to be 16, 24 or 32 characters long"
        error(msg)
        usage()
        exit()
    arg_pos += 1

    # We have all needed parameters for ECB
    if mode == Mode.ECB:
        return Parameters(
            function=function,
            mode=mode,
            text=text,
            key=key,
            bytes=loaded_bytes,
        )

    iv: Union[str, None] = None
    if len(sys.argv) < MIN_NUM_ARGS + 1:
        msg = "Missing initialization vector for CBC mode"
        error(msg)
        usage()
        exit()

    if len(sys.argv[arg_pos]) == 16:
        iv: str = sys.argv[arg_pos]
    else:
        msg = f"The initialization vector needs to be exactly 128 bits long (16 characters)"
        error(msg)
        usage()
        exit()

    return Parameters(
        function=function,
        mode=mode,
        text=text,
        key=key,
        iv=iv,
        bytes=loaded_bytes,
    )