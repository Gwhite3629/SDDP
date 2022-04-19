#!/usr/bin/python3

import math
from interface import Address_book, RC5_decrypt, RC5_encrypt, RC5_setup, Receiver, Header, Sender, id_generator
import gc
from rsa import common

def main():
    R = Receiver()
    #print(R.Address)
    R.Address['192.168.7.2'] = ('3','Random','key')
    #print(R.Address)
    R.Address.write_book()
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

    #print(S.header_e[20])

    S.decrypt_header(20)

    print(S.received)

    k = id_generator()
    k = k.encode('utf8')
    S = RC5_setup(k)

    (A, B) = RC5_encrypt(S, 3, 3)
    print(RC5_decrypt(S, A, B))

    #S.decrypt_data(20)

    #print(S.packets[20])

    #print(S.decrypted_packet)

if __name__ == "__main__":
    main()