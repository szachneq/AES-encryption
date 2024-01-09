#!/usr/bin/env python
from cli import parse_cli, Function, Mode
from aes_ecb_encrypt import aes_ecb_encrypt
from aes_cbc_encrypt import aes_cbc_encrypt
from aes_ecb_decrypt import aes_ecb_decrypt
from aes_cbc_decrypt import aes_cbc_decrypt

if __name__ == "__main__":
    parameters = parse_cli()
    # print(parameters)
    # exit()

    if parameters.function == Function.ENCRYPT:

        if parameters.mode == Mode.ECB:
            r = aes_ecb_encrypt(
                msg_str=parameters.text,
                msg_bytes=parameters.bytes,
                key_str=parameters.key,
            )
            print(r)

        elif parameters.mode == Mode.CBC:
            r = aes_cbc_encrypt(
                msg_str=parameters.text,
                msg_bytes=parameters.bytes,
                key_str=parameters.key,
                iv_str=parameters.iv,
            )
            print(r)

    elif parameters.function == Function.DECRYPT:

        if parameters.mode == Mode.ECB:
            r = aes_ecb_decrypt(
                cryptogram_str=parameters.text,
                cryptogram_bytes=parameters.bytes,
                key_str=parameters.key,
            )
            print(r)

        elif parameters.mode == Mode.CBC:
            r = aes_cbc_decrypt(
                cryptogram_str=parameters.text,
                cryptogram_bytes=parameters.bytes,
                key_str=parameters.key,
                iv_str=parameters.iv,
            )
            print(r)
