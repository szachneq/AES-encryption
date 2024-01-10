from common import *
from key_expansion import expand_key
from typing import List
from copy import deepcopy

def aes_cbc_decrypt(key_str: str, iv_str: str, cryptogram_str: str = None, cryptogram_bytes: bytes = None) -> str:
    """
    Decrypt given cryptogram with a given key using AES CBC algorithm

    Parameters:
        message (str): arbitrary non-empty string to be decrypted
        key (str): 16, 24 or 32 characters long ASCII character string
        iv (str): initialization vector, 16 ASCII character string. Needs to be the same as one used for encryption

    Returns:
        message (str): message extracted from the cryptogram
    """
    # check if key length is valid
    if len(key_str) not in VALID_KEY_LENGTHS:
        print("Key length invalid. Cannot perform encryption")
        exit()

    # check if initialization vector length is valid
    if len(iv_str) != 16:
        print("Initialization vector length invalid. Cannot perform encryption")
        exit()
    
    # find values of constants used during the encryption
    NUM_ROUNDS = NUM_ROUNDS_FOR_KEY_LENGTH[len(key_str)]

    matrices = None
    if cryptogram_str is not None:
        matrices = prepare_cryptogram_str(cryptogram_str)
    elif cryptogram_bytes is not None:
        matrices = prepare_message_bytes(cryptogram_bytes)
    else:
        print("No message provided, cannot proceed")
        exit()

    key = prepare_key(key_str)
    iv = prepare_key(iv_str)
    iv = block_to_matrix(iv)

    round_keys = expand_key(key)
    msg: List[int] = []

    for matrix in matrices:
        next_iv = deepcopy(matrix)
        # 0th round
        # In case of decryption, we get round keys in the opposite order (from the back)
        round_key = round_key_to_matrix(round_keys[-4:]) # get round key and turn it into 4x4 matrix
        matrix = xor_matrices(matrix, round_key) # add round key

        # rounds 1 to N-1
        for n in range(1, NUM_ROUNDS):
            round_key = round_key_to_matrix(round_keys[-(4*n+4):-(4*n)]) # get round key and turn it into 4x4 matrix
            matrix = inv_shift_rows(matrix) # shift rows
            matrix = inv_substitute_bytes(matrix) # substitute bytes
            matrix = xor_matrices(matrix, round_key) # add round key
            matrix = inv_mix_columns(matrix) # mix columns

        # N-th (last) round
        round_key = round_key_to_matrix(round_keys[0:4]) # get round key and turn it into 4x4 matrix
        matrix = inv_shift_rows(matrix) # shift rows
        matrix = inv_substitute_bytes(matrix) # substitute bytes
        matrix = xor_matrices(matrix, round_key) # add round key

        matrix = xor_matrices(matrix, iv) # XOR matrix with initialization vector
        iv = next_iv

        msg.extend(matrix_to_list(matrix))

    with open('output', 'wb') as file:
        file.write(bytes(msg))

    s = list_to_str(msg)

    return s
