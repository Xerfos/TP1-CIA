#!/usr/bin/env python3
#coding:utf-8

# Coded by Sud0ck3rs

from termcolor import colored
from Crypto.PublicKey import RSA
from binascii import hexlify
import argparse
import time

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


# fonction pour chiffrer une donnée avec une clée privée
def RSA_encryption(data: bytes, publicKey: RSA) -> bytes:
    n = publicKey.n
    e = publicKey.e
    m = int(hexlify(data).decode(), 16)
        
    c = pow(m, e, n) # donnée chiffrée = m^e % n
    cipher_data = int_to_bytes(c)
    return cipher_data


def RSA_decryption(data: bytes, privateKey: RSA) -> bytes:
    n = privateKey.n
    d = privateKey.d
    c = int(hexlify(data).decode(), 16)
        
    m = pow(c, d, n) # donnée déchiffrée = c^d % n
    decipher_data = int_to_bytes(m)
    return decipher_data


# Programme principal
def main():
    #args parser
    parser = argparse.ArgumentParser(description="RSA encryption, decryption")
    parser.add_argument("--input", help="chemin du fichier à chiffrer ou déchiffrer", required=False)
    parser.add_argument("--output", help="chemin du fichier de sortie", required=False)
    parser.add_argument("--encrypt", help="permet de chifrer in fichier", action="store_true", required=False)
    parser.add_argument("--decrypt", help="permet de déchiffrer un fichier", action="store_true", required=False)
    parser.add_argument("--privateKey", help="chemin de la clée privée pour le déchiffrement du fichier", required=False)
    parser.add_argument("--publicKey", help="chemin de la clée publique pour le chiffrement du fichier", required=False)

    args = parser.parse_args()

    if args.encrypt:
        try:
            public_pem = open(str(args.publicKey), "rb")
            if not public_pem.closed:
                publicKey = RSA.import_key(public_pem.read())
                input_file = open(str(args.input), "rb")
                if not input_file.closed:
                    file_encrypted = open(str(args.output), "wb")
                    if not file_encrypted.closed:
                        start_encryption = time.time()
                        while True:
                            data = input_file.readline()
                            if not data:
                                break

                            cipher_data = RSA_encryption(data, publicKey)
                            file_encrypted.write(cipher_data)
                        end_encryption = time.time()
                        print(colored("chiffrement du fichier reussi...", "yellow"))
                        print(colored("temps du chiffrement: {} seconde".format(end_encryption - start_encryption), "yellow"))

            file_encrypted.close()  
            input_file.close()
            public_pem.close()

        except:
            print(colored("une erreur dans l'algorithme du chiffrement est survenue...", "red"))


    elif args.decrypt:
        try:
            private_pem = open(str(args.privateKey), "rb")
            if not private_pem.closed:
                privateKey = RSA.import_key(private_pem.read())
                input_file = open(str(args.input), "rb")
                if not input_file.closed:
                    file_decrypted = open(str(args.output), "wb")
                    if not file_decrypted.closed:
                        start_encryption = time.time()
                        while True:
                            data = input_file.readline()
                            if not data:
                                break
                            decipher_data = RSA_decryption(data, privateKey)
                            file_decrypted.write(decipher_data)
                        end_encryption = time.time()
                        print(colored("déchiffrement du fichier reussi...", "yellow"))
                        print(colored("temps du déchiffrement: {} seconde".format(end_encryption - start_encryption), "yellow"))

                file_decrypted.close()
                input_file.close()
                private_pem.close()
        except:
            print(colored("une erreur dans l'algorithme du déchiffrement est survenue...", "red"))





if __name__ == '__main__':
    main()