from common import *
from key_expansion import expand_key
from typing import List

def aes_cbc_encrypt(key_str: str, iv_str: str, msg_str: str = None, msg_bytes: bytes = None) -> str:
    """
    Encrypt given message with a given key using AES CBC algorithm
    
    Parameters:
        message (str): arbitrary non-empty string to be encrypted
        key (str): 16, 24 or 32 characters long ASCII character string
        iv (str): initialization vector, 16 ASCII character string. To later decrypt the message, the same iv value needs to be used

    Returns:
        cryptogram (str): encrypted message
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
    if msg_str is not None:
        matrices = prepare_message_str(msg_str)
    elif msg_bytes is not None:
        matrices = prepare_message_bytes(msg_bytes)
    else:
        print("No message provided, cannot proceed")
        exit()

    key = prepare_key(key_str)
    iv = prepare_key(iv_str)
    iv = block_to_matrix(iv)

    round_keys = expand_key(key)

    cryptogram: List[int] = []

    for matrix in matrices:
        # 0th round
        round_key = round_key_to_matrix(round_keys[0:4]) # get round key and turn it into 4x4 matrix
        matrix = xor_matrices(matrix, iv) # XOR original matrix with the initialization vector
        matrix = xor_matrices(matrix, round_key) # add round key

        # rounds 1 to N-1
        for n in range(1, NUM_ROUNDS):
            round_key = round_key_to_matrix(round_keys[4 * n:4 * n + 4]) # get round key and turn it into 4x4 matrix
            matrix = substitute_bytes(matrix)  # substitute bytes
            matrix = shift_rows(matrix)  # shift rows
            matrix = mix_columns(matrix)  # mix columns
            matrix = xor_matrices(matrix, round_key) # add round key

        # N-th (last) round
        round_key = round_key_to_matrix(round_keys[-4:])  # get round key and turn it into 4x4 matrix
        matrix = substitute_bytes(matrix)  # substitute bytes
        matrix = shift_rows(matrix)  # shift rows
        matrix = xor_matrices(matrix, round_key) # add round key
        iv = matrix # end result of encryption becomes initialization matrix for next block

        cryptogram.extend(matrix_to_list(matrix)) # append to the result

    with open('output', 'wb') as file:
        file.write(bytes(cryptogram))

    s = list_to_hex_str(cryptogram)

    return s
