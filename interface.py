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
        self.file = file
        f = open(self.file,'r')
        L = f.read().splitlines()
        for l in L:
            line = l.split(',')
            self.Book[line[0]] = (line[1],line[2],line[3]) #(address,trust,hostname)
        f.close()

    def __str__(self):
        s = ""
        for x in self.Book:
            s = s+f'{x}: '
            for y in self.Book[x]:
                y = y.split(',')
                for z in y:
                    s = s+f'{z}, '
            s = s[:len(s)-2]
            s = s+'\n'
        return s

    def __getitem__(self,key):
        return self.Book[key]

    def __setitem__(self,key,value):
        self.Book[key] = value

    def write_book(self):
        s = ""
        f = open(self.file,'w')
        for x in self.Book:
            s = s+f'{x},'
            for y in self.Book[x]:
                y = y.split(',')
                for z in y:
                    s = s+f'{z},'
            s = s[:len(s)-1]
            s = s+'\n'
        s = s[:len(s)-1]
        f.write(s)
        f.close()

class State(object):
    def __init__(self):
        self.State = 0

    def __getitem__(self, State):
        return self.State

    def __setitem__(self, State):
        self.State = State

class Header(object):
    def __init__(self, size, size_ext, data_type, cipher_key, checksum, total_packets, packet_number):
        self.size = size
        self.size_ext = size_ext
        self.data_type = data_type
        self.cipher_key = cipher_key
        self.checksum = checksum
        self.total_packets = total_packets
        self.packet_number = packet_number
        self.Field_1 = size
        self.Field_2 = ((size_ext & 255) << 24) + ((data_type & 255) << 16) + (cipher_key & 65535)
        self.Field_3 = ((checksum & 65535) << 24) + ((total_packets & 255) << 16) + ((packet_number & 255) << 8)

    def __str__(self):
        string = f'{self.size}\n{self.size_ext},{self.data_type},{self.cipher_key}\n{self.checksum},{self.total_packets},{self.packet_number}\n'
        return f'{string}\n{hex(self.Field_1)}\n{hex(self.Field_2)}\n{hex(self.Field_3)}\n'

    def encrypt():
        return

    def decrypt():
        return

class Receiver(object):
    def __init__(self):
        self.Address = Address_book('addressbook.txt')
        return
    
    def connect(self):
        return

    def close(self):
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

    def resolve_trust():
        return
    
    def set_trust(self):
        return