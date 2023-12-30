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
    text: str
    key: str
    iv: Union[str, None] = None

def usage() -> None:
    """Print usage of the command line interface to the terminal window"""
    script_name = sys.argv[0]
    msg = f"""
    Usage:
    {script_name} --encrypt|--decrypt --ecb|--cbc <message/cryptogram> <key> [iv]

    Examples:
    {script_name} --encrypt --ecb "Hello, World!" "abcdefghijklmnop"
    {script_name} --decrypt --ecb "qazwsxedcrfvt" "abcdefghijklmnop"

    {script_name} --encrypt --cbc "Hello, World!" "abcdefghijklmnop" "qwertyuiopasdfgh"
    {script_name} --decrypt --cbc "qazwsxedcrfvt" "abcdefghijklmnop" "qwertyuiopasdfgh"

    Remarks:
    - the key needs to be either 128 bits long, provided in plaintext (16 ASCII characters, 1 byte each)
    - the iv (initialization vector) parameter is only needed for CBC mode. It is also required to be 16 characters long
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
    
    function: Function = None
    functions = [member.value for member in Function]
    if sys.argv[1] in functions:
        function = Function(sys.argv[1])
    else:
        msg = f"{sys.argv[1]} is not a valid option. Choose either --encrypt or --decrypt"
        error(msg)
        usage()
        exit()

    mode: Mode = None
    modes = [member.value for member in Mode]
    if sys.argv[2] in modes:
        mode = Mode(sys.argv[2])
    else:
        msg = f"{sys.argv[2]} is not a valid mode. Choose either --ecb or --cbc"
        error(msg)
        usage()
        exit()

    text: str = ''
    if len(sys.argv[3]) > 0:
        text: str = sys.argv[3]
    else:
        msg = f"The message cannot be empty"
        error(msg)
        usage()
        exit()

    key: str = ''
    key_len = len(sys.argv[4])
    if key_len in VALID_KEY_LENGTHS:
        key: str = sys.argv[4]
    else:
        msg = f"The key needs to be 16, 24 or 32 characters long"
        error(msg)
        usage()
        exit()

    # We have all needed parameters for ECB
    if mode == Mode.ECB:
        return Parameters(function, mode, text, key)

    iv: Union[str, None] = None
    if len(sys.argv) < MIN_NUM_ARGS + 1:
        msg = "Missing initialization vector for CBC mode"
        error(msg)
        usage()
        exit()

    if len(sys.argv[5]) == 16:
        iv: str = sys.argv[4]
    else:
        msg = f"The initialization vector needs to be exactly 128 bits long (16 characters)"
        error(msg)
        usage()
        exit()

    return Parameters(function, mode, text, key, iv)