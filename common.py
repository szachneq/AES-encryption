from constants import *
from typing import List
import array

def padding(message: List[int]) -> List[int]:
    """
    Ensure that the message length is a multiple o 16 characters (128 bits).
    This is a requirement for AES block cipher.
    It is performed using ISO padding (ISO/IEC 9797-1 Padding Method 2).

    Parameters:
        message (List[int]): arbitrary message as a list of integers

    Returns:
        message (List[int]): message with length adequate for encryption
    """
    if len(message) % 16 != 0:
        message.append(0x80)

    while len(message) % 16 != 0:
        message.append(0x00)

    return message

def block_to_matrix(block: List[int]) -> List[List[int]]:
    """
    Turn list of 16 integers into a 4x4 matrix

    Parameters:
        block (List[int]): list representing message block

    Returns:
        message (List[int]): matrix representing part of the message
    """
    matrix = [
        [ block[0], block[4], block[8],  block[12] ],
        [ block[1], block[5], block[9],  block[13] ],
        [ block[2], block[6], block[10], block[14] ],
        [ block[3], block[7], block[11], block[15] ],
    ]

    return matrix

def prepare_message_str(msg_str: str) -> List[List[List[int]]]:
    """
    Prepare the message string for encryption

    Parameters:
        msg_str (str): arbitrary message string

    Returns:
        matrices (List[List[List[int]]]): list of 4x4 matrices, each representing block of message
    """
    # turn the string into list of integers
    msg = [ ord(list(msg_str)[i]) for i in range(len(msg_str)) ]
    # ensure proper length
    msg = padding(msg)
    # split the message into blocks, each 16 digits long
    blocks = [ msg[i:i+16] for i in range(0, len(msg), 16) ]
    # turn each block into a matrix
    matrices = [ block_to_matrix(blocks[i]) for i in range(len(blocks)) ]

    return matrices

def prepare_message_bytes(msg_bytes: bytes) -> List[List[List[int]]]:
    """
    Prepare the message bytes for encryption

    Parameters:
        msg_str (str): arbitrary bytes representing message

    Returns:
        matrices (List[List[List[int]]]): list of 4x4 matrices, each representing block of message
    """
    # turn the bytes into list of integers
    msg = list(array.array('B', msg_bytes))
    # ensure proper length
    msg = padding(msg)
    # split the message into blocks, each 16 digits long
    blocks = [ msg[i:i+16] for i in range(0, len(msg), 16) ]
    # turn each block into a matrix
    matrices = [ block_to_matrix(blocks[i]) for i in range(len(blocks)) ]

    return matrices

def hex_str_to_list(cryptogram_str: str) -> List[int]:
    """
    Turn string containing 2 letter (8-bit) hex codes into integer list

    Parameters:
        cryptogram_str (str): cryptogram string

    Returns:
        list (List[List[int]]): list of 8-bit integers
    """
    l = []

    for n in range(len(cryptogram_str)):
        start = 2 * n
        end = start + 2
        hex = cryptogram_str[start:end]
        num = int(hex, 16)
        l.append(num)

    return l

def prepare_cryptogram_str(cryptogram_str: str) -> List[List[List[int]]]:
    """
    Prepare the cryptogram string for decryption.
    It needs to be treated differently than the message string because it contains
    hex numbers instead of simple characters.

    Parameters:
        cryptogram_str (str): cryptogram string

    Returns:
        matrices (List[List[List[int]]]): list of 4x4 matrices, each representing block of message
    """
    if len(cryptogram_str) % 16 != 0:
        print("Invalid cryptogram length, cannot proceed")
        exit()

    # because each blocks has 16 integers. Each integer is saved in hex as 2 letters.
    CHARS_PER_BLOCK = 32
    NUM_BLOCKS = len(cryptogram_str) // CHARS_PER_BLOCK

    matrices = []

    for n in range(NUM_BLOCKS):
        matrix = [ [0] * 4 for i in range(4) ] # initialize empty matrix

        for i in range(16):
            start = n * CHARS_PER_BLOCK + 2 * i
            end = start + 2
            hex = cryptogram_str[start:end]
            num = int(hex, 16)
            matrix[i%4][i//4] = num

        matrices.append(matrix)

    return matrices

def prepare_key(key_str: str) -> List[int]:
    """
    Prepare the key string for encryption

    Parameters:
        key_str (str): string representing encryption key. Should be 16, 24 or 32 characters long

    Returns:
        message (List[int]): message as list of numbers prepared for encryption
    """
    if len(key_str) not in VALID_KEY_LENGTHS:
        print("Invalid key length")
        exit()

    return [ ord(list(key_str)[i]) for i in range(len(key_str)) ]

def round_key_to_matrix(words: List[List[int]]) -> List[List[int]]:
    """
    Create a 4x4 int matrix based on list of 8-bit words

    Parameters:
        words: List[List[int]]

    Returns:
        matrix (List[List[int]]): 4x4 integer matrix
    """
    matrix = [
        [ words[0][0], words[1][0], words[2][0], words[3][0] ],
        [ words[0][1], words[1][1], words[2][1], words[3][1] ],
        [ words[0][2], words[1][2], words[2][2], words[3][2] ],
        [ words[0][3], words[1][3], words[2][3], words[3][3] ],
    ]

    return matrix

def xor_matrices(a: List[List[int]], b: List[List[int]]) -> List[List[int]]:
    """
    Perform XOR operation on individual items of two 4x4 matrices

    Parameters:
        a (List[List[int]]): 4x4 integer matrix
        b (List[List[int]]): 4x4 integer matrix

    Returns:
        matrix (List[List[int]]): 4x4 integer matrix
    """
    for n in range(16):
        a[n%4][n//4] = a[n%4][n//4] ^ b[n%4][n//4]
    return a

def substitute_bytes(matrix: List[List[int]]) -> List[List[int]]:
    """
    Substitute bytes inside the matrix based on the values from the lookup table
    This function is used during encryption

    Parameters:
        matrix (List[List[int]]): 4x4 integer matrix on which we want to perform the substitution

    Returns:
        matrix (List[List[int]]): 4x4 integer matrix after the substitution
    """
    for n in range(16):
        matrix[n%4][n//4] = SUBSTITUTION_BOX[matrix[n%4][n//4]]

    return matrix

def inv_substitute_bytes(matrix: List[List[int]]) -> List[List[int]]:
    """
    Substitute bytes inside the matrix based on the values from the inverse lookup table
    This function is used during decryption

    Parameters:
        matrix (List[List[int]]): 4x4 integer matrix on which we want to perform the substitution

    Returns:
        matrix (List[List[int]]): 4x4 integer matrix after the substitution
    """
    for n in range(16):
        matrix[n%4][n//4] = INVERSE_SUBSTITUTION_BOX[matrix[n%4][n//4]]

    return matrix

def shift_rows(matrix: List[List[int]]) -> List[List[int]]:
    """
    Shift rows in AES encryption algorithm performs left circular shift on each row.
    The magnitude of the shift is equal to the 0 based row index.
    This function is used during encryption

    Parameters:
        matrix (List[List[int]]): 4x4 integer matrix on which we want to perform the shift

    Returns:
        matrix (List[List[int]]): shifted 4x4 integer matrix
    """
    return [ matrix[n][n:] + matrix[n][:n] for n in range(4) ]

def inv_shift_rows(matrix: List[List[int]]) -> List[List[int]]:
    """
    Inverse shift rows in AES encryption algorithm performs right circular shift on each row.
    The magnitude of the shift is equal to the 0 based row index.
    This function is used during decryption

    Parameters:
        matrix (List[List[int]]): 4x4 integer matrix on which we want to perform the shift

    Returns:
        matrix (List[List[int]]): shifted 4x4 integer matrix
    """
    return [ matrix[n][-n:] + matrix[n][:-n] for n in range(4) ]

def mul(a: int, b: int) -> int:
    """
    Perform Galois multiplication of two given integers in a finite field GF(2^8)
    Note: this operation is NOT commutative, order of parameters matters

    Parameters:
        a (int): first 8 bit integer
        b (int): second 8 bit integer

    Returns:
        result: (int): result of the Galois multiplication
    """
    p = 0b100011011 # "irreducible polynomial" of the finite field GF(2^8) = x^8+x^4+x^3+x+1
    result = 0
    for _ in range(8):
        result = result << 1
        if result & 0b100000000: # if MSB of result == 1
            result = result ^ p
        if b & 0b010000000: # if MSB of b == 1
            result = result ^ a
        b = b << 1
    
    return result

def mix_columns(matrix: List[List[int]]) -> List[List[int]]:
    """
    Mix columns step in AES encryption is simply a matrix multiplication.
    We take the current status matrix and multiply it with a constant matrix.
    However, instead of normal multiplication, we perform Galois multiplication
    in a finite field GF(2^8).
    This function is used during encryption.

    Parameters:
        matrix (List[List[int]]): 4x4 matrix of integers

    Returns:
        matrix (List[List[int]]): 4x4 matrix of integers
    """
    M = MIX_COLUMN_MATRIX # rename for shorter code

    for i in range(4): # for each of the columns
        c = [ matrix[n][i] for n in range(4) ] # ith column

        t = [0] * 4 # empty list as result container
        # perform Galois multiplication of the columns with appropriate rows of the Mix Columns Transformation Matrix
        for n in range(4):
            t[n] = mul(c[0], M[4*n]) ^ mul(c[1], M[4*n+1]) ^ mul(c[2], M[4*n+2]) ^ mul(c[3], M[4*n+3])

        # store results
        for n in range(4):
            matrix[n][i] = t[n]

    return matrix

def inv_mix_columns(matrix: List[List[int]]) -> List[List[int]]:
    """
    Mix columns step in AES encryption is simply a matrix multiplication.
    We take the current status matrix and multiply it with a constant matrix.
    However, instead of normal multiplication, we perform Galois multiplication
    in a finite field GF(2^8).
    This function is used during encryption.

    Parameters:
        matrix (List[List[int]]): 4x4 matrix of integers

    Returns:
        matrix (List[List[int]]): 4x4 matrix of integers
    """
    M = INVERSE_MIX_COLUMN_MATRIX # rename for shorter code

    for i in range(4): # for each of the columns
        c = [ matrix[n][i] for n in range(4) ] # ith column

        t = [0] * 4 # empty list as result container
        # perform Galois multiplication of the columns with appropriate rows of the Mix Columns Transformation Matrix
        for n in range(4):
            t[n] = mul(c[0], M[4*n]) ^ mul(c[1], M[4*n+1]) ^ mul(c[2], M[4*n+2]) ^ mul(c[3], M[4*n+3])

        # store results
        for n in range(4):
            matrix[n][i] = t[n]

    return matrix

def matrix_to_list(matrix: List[List[int]]) -> List[int]:
    """
    Turn 4x4 matrix into a list of 16 integers

    Parameters:
        matrix (List[List[int]]): 4x4 matrix of integers

    Returns:
        message (List[int]): list of integers
    """
    return [ matrix[n%4][n//4] for n in range(16) ]

def list_to_hex_str(l: List[int]) -> str:
    """
    Turn a list of integers into a string of hex numbers, without 0x prefix

    Parameters:
        l (List[int]): list of integers

    Returns:
        string (str): hex string
    """
    return ''.join([ '{:02x}'.format(l[i]) for i in range(len(l)) ])

def list_to_str(l: List[int]) -> str:
    """
    Turn a list of integers into a string of letters

    Parameters:
        l (List[int]): list of integers

    Returns:
        string (str): string of letters
    """
    return ''.join([ chr(num) for num in l ])
