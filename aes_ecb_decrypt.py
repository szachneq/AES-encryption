from constants import *
from common import *
from key_expansion import expand_key

def aes_ecb_decrypt(cryptogram_str: str, key_str: str) -> str:
    """
    Decrypt given cryptogram with a given key using AES ECB algorithm
    
    Parameters:
        message (str): arbitrary non-empty string to be decrypted
        key (str): 16, 24 or 32 characters long ASCII character string

    Returns:
        message (str): message extracted from the cryptogram
    """
    # check if key length is valid
    if len(key_str) not in VALID_KEY_LENGTHS:
        print("Key length invalid. Cannot perform key expansion")
        exit()

    # check if cryptogram length is valid
    if (len(cryptogram_str)) % 16 != 0:
        print("Invalid cryptogram length, cannot proceed")
        exit()

    # find values of constants used during the encryption
    NUM_ROUNDS = NUM_ROUNDS_FOR_KEY_LENGTH[len(key_str)]

    matrices = prepare_cryptogram(cryptogram_str)
    key = prepare_key(key_str)

    round_keys = expand_key(key)
    msg: List[int] = []

    for matrix in matrices:
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

        msg.extend(matrix_to_list(matrix)) # append to the result

    s = list_to_str(msg)
    
    return s
