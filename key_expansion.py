from constants import *
from common import *
from typing import List

def g(word: List[int], round: int) -> List[int]:
    """
    In AES encryption, every nth word of round key (where n depends on key length)
    is transformed a differently from others.

    Parameters:
        word (List[int]): List of 4 8-bit integers representing a binary word
        round (int): 0 based index of the round to which the word belongs

    Returns:
        word (List[int]): Binary word after the modification
    """
    # perform left circular shift on the word (1234 -> 2341)
    w = word[1:] + word[:1]

    # substitute the values based on the substitution lookup table
    # SBOX = INVERSE_SUBSTITUTION_BOX if decrypt else SUBSTITUTION_BOX
    w = [ SUBSTITUTION_BOX[w[i]] for i in range(4) ]

    # perform XOR operation on the first byte
    round_constant = ROUND_CONSTANTS[round]
    w[0] = w[0] ^ round_constant

    return w


def expand_key(key: List[int]) -> List[List[int]]:
    """
    Perform expansion of given key.
    Parameters:
        key (List[int]): List of integers representing the key. It should be 16, 24 or 36 items long
    Returns:
        words (List[List[int]]): List of 4 item long lists.
            Each short list represents a 32 bit word used as a part of round key
    """
    # check if key length is valid
    if len(key) not in VALID_KEY_LENGTHS:
        print("Key length invalid. Cannot perform key expansion")
        exit()

    # find values of constants used during key expansion
    NUM_ROUNDS = NUM_ROUNDS_FOR_KEY_LENGTH[len(key)]
    WORDS_PER_ROUND = WORDS_PER_ROUND_FOR_KEY_LENGTH[len(key)]
    NUM_WORDS = ((NUM_ROUNDS + 1) * 4)
    KEY256 = len(key) == 32 # tells if we are dealing with 256 bit key

    # initialize the result with zeroes
    w = [[0] * 4] * NUM_WORDS
    # first n words are taken directly from the key
    for n in range(WORDS_PER_ROUND):
        i = n * 4
        w[n] = key[i : i + 4]

    for n in range(WORDS_PER_ROUND, NUM_WORDS):
        t = list(w[n-1]) # copy of previous word

        if n % WORDS_PER_ROUND == 0:
            r = int(n / WORDS_PER_ROUND) - 1 # round index, 0 based
            t = g(t, r)

        # special case for 256 bit key
        if KEY256 and n % 8 == 4:
            # SBOX = INVERSE_SUBSTITUTION_BOX if decrypt else SUBSTITUTION_BOX
            t = [ SUBSTITUTION_BOX[word] for word in t ]
        # store in the result list
        w[n] = [ w[n-WORDS_PER_ROUND][i] ^ t[i] for i in range(4) ]
    return w
