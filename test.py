#!/usr/bin/python3

import math
from interface import Address_book, RC5_decrypt, RC5_encrypt, RC5_setup, Receiver, Header, Sender, id_generator
import gc
from rsa import common

def main():
    #R = Receiver()
    #print(R.Address)
    #R.Address['192.168.7.2'] = ('3','Random','key')
    #print(R.Address)
    #R.Address.write_book()
    #A = Address_book('addressbook.txt')
    #print(A)

    #H = Header(1234,0,3,32456,32457,64,2)

    #E = H.encrypt(R.Address.public)

    #print(E)

    #U = H.decrypt(E,R.Address.private)

    #print(U)

    #print(H)

    S = Sender('192.168.1.1')

    S.read_file('README')

    print("Encrpted header")
    print(S.header_e[20])

    S.decrypt_header(20)

    print("SELF ENCRYPTED HEADER")
    print(S.received)

    S.decrypt_data(20)

    print("SELF DECODED PACKETS")
    print(S.packets[20].decode('utf8'))

    print("SELF DECRYPRED PACKETS")
    print(S.decrypted_packet.decode('utf8'))

    print("Length of frames")
    print(len(S.frames[20]))

if __name__ == "__main__":
    main()