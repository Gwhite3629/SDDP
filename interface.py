#!/usr/bin/python3

import rsa

class Sender(object):
    def __init__():

        return

    def create_header():
        return

    def encrypt_header(self, num):
        return

    def checksum():
        return

    def read_file():
        return

    def gen_cipher():
        return

    def cipher():
        return

class Address_book(object):
    def __init__(self, file): #Get addressbook function
        self.Book = dict()
        return

    def __str__(self):
        return self.Book.items()

    def __getitem__(self,key):
        return self.Book[key]

    def __setitem__(self,key,trust,hostname,address):
        self.Book[key] = (trust,hostname,address)
        return

    def write_book():
        return

class State(object):
    def __init__(self):
        self.State = 0

    def __getitem__(self, State):
        return self.State

    def __setitem__(self, State):
        self.State = State

class Header(object):
    def __init__(self, size, size_ext, data_type, cipher_key, checksum, total_packets, packet_number):
        self.Field_1 = size
        self.Field_2 = ((size_ext & 255) << 24) + ((data_type & 255) << 16) + (cipher_key & 65535)
        self.Field_3 = ((checksum & 65535) << 24) + ((total_packets & 255) << 16) + ((packet_number & 255) << 8)

    def __str__(self):
        return f'{hex(self.Field_1)}\n{hex(self.Field_2)}\n{hex(self.Field_3)}\n'

    def encrypt():
        return

    def decrypt():
        return

class Receiver(object):
    def __init__():
        return

    def reject():
        return

    def block():
        return

    def unblock():
        return

    def decrypt_header(self, num):
        return

    def decrypt_data():
        return