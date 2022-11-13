#!/usr/bin/env python3
#coding:utf-8

# Coded by Sud0ck3rs

from Crypto.PublicKey import RSA

# permet de generer une paire de clée RSA (privée, publique)
def generate_RSA_private_key(size):
    private_key = RSA.generate(size)
    public_key = private_key.public_key()

    return (private_key, public_key)


def main():
    private_key, public_key = generate_RSA_private_key(2048)

    print(private_key.export_key("PEM").decode())
    print(public_key.export_key("PEM").decode())

    file_private = open("./private.pem", "wb")
    file_public = open("./public.pem", "wb")

    if(not file_private.closed and not file_public.closed):
        file_private.write(private_key.export_key("PEM"))
        file_public.write(public_key.export_key("PEM"))

        file_private.close()
        file_public.close()


if __name__ == '__main__':
    main()