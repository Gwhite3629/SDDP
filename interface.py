#!/usr/bin/python3

from genericpath import exists
from operator import mod
import pathlib
from pkg_resources import ResolutionError
import rsa
import os

class Sender(object):
    def __init__(self,current_address):
        self.Address = Address_book('addressbook.txt')
        self.headers = list()
        self.header_e = list()
        self.packets = list()
        self.checksums = list()
        self.cipher_keys = list()
        self.frames = list()
        self.current_address = current_address
        return

    def create_frames(self):
        for i in range(0,self.total_packets):
            self.frames.append(b''.join([self.header_e[i],self.packets[i]]))

    def create_headers(self):
        for i in range(0,self.total_packets):
            self.headers.append(Header(
                self.header_t.size,
                self.header_t.size_ext,
                self.header_t.misc,
                self.cipher_keys[i],
                self.checksums[i],
                self.total_packets,
                i))
            self.encrypt_header(i)
        return

    def create_packets(self):
        for i in range(0,self.total_packets):
            if i == (self.total_packets-1):
                self.packets.append(self.data[i*476:-1])
                padding_length = 476-len(self.packets[i])
                for j in range(0,padding_length):
                    self.packets[i] = b''.join([self.packets[i],b'\0'])
            else:
                self.packets.append(self.data[i*476:(i+1)*476])
        return

    def encrypt_header(self, num):
        self.header_e.append(
            self.headers[num].encrypt(
                self.Address.getkey(
                    self.Address[self.current_address][2]
                )))

    def decrypt_header(self, num):
        received = Header.decrypt(self.headers[0],self.header_e[num],self.Address.private)
        self.received = Header(
            (received >> 64) & (pow(2,32) - 1),
            (received >> 56) & 255,
            (received >> 48) & 255,
            (received >> 32) & 65525,
            (received >> 16) & 65535,
            (received >> 8) & 255,
            received & 255)

    def create_checksums(self):
        for i in range(0,self.total_packets):
            self.checksums.append(self.checksum(i))

    def create_ciphers(self):
        for i in range(0,self.total_packets):
            self.cipher_keys.append(self.gen_cipher())

    def checksum(self,num):
        sum = 0
        for i in range(0,len(self.packets[num])):
            sum = sum + ~self.packets[num][i]
        return ~(sum & 65535)

    def resolve_packets(self):
        # Number of packets is equal to file_size(bytes)/(508-header_size)+1
        # This is because the max safe UDP payload is 508 bytes and the header is 
        # 32 bytes long due to encryption. The end expression is to get any trail data.
        self.total_packets = int(self.size/476)+(mod(self.size,476)>0 if 1 else 0)

    def read_file(self, target):
        self.target = open(target,'rb') # Open file in binary mode
        self.data = self.target.read() # Read data
        self.size = os.path.getsize(target) # Get file size
        self.resolve_packets() # Get number of packets
        self.header_t = Header(self.size,0,0,0,0,self.total_packets,0)
        self.create_packets()
        self.create_checksums()
        self.create_ciphers()
        self.create_headers()

        return

    def gen_cipher(self):
        return 1

    def cipher():
        return

class Address_book(object):
    def __init__(self, file): #Get addressbook function
        self.get_my_keys()
        self.Book = dict()
        self.file = file
        f = open(self.file,'r')
        L = f.read().splitlines()
        for l in L:
            line = l.split(',')
            self.Book[line[0]] = (line[1],line[2],line[3]) #(address,trust,hostname,keyfile)
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

    def getkey(self, keyfile):
        f = open(f'keys/{keyfile}','rb')
        k = f.read()
        key = rsa.PublicKey._load_pkcs1_pem(k)
        f.close()
        return key

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

    def get_my_keys(self):
        if (exists('private.pem') | exists('public.pem')):
            fpriv = open('private.pem','rb')
            fpub = open('public.pem','rb')
            kpriv = fpriv.read()
            kpub = fpub.read()
            print('Loading keys')
            self.private = rsa.PrivateKey._load_pkcs1_pem(kpriv)
            self.public = rsa.PublicKey._load_pkcs1_pem(kpub)
            fpriv.close()
            fpub.close()
        else:
            fpriv = open('private.pem','wb')
            fpub = open('public.pem','wb')
            print('Generating keys')
            (self.public, self.private) = rsa.newkeys(256, accurate=1)
            fpub.write(self.public._save_pkcs1_pem())
            fpriv.write(self.private._save_pkcs1_pem())
            fpub.close()
            fpriv.close()

class State(object):
    def __init__(self):
        self.State = 0

    def __getitem__(self, State):
        return self.State

    def __setitem__(self, State):
        self.State = State

class Header(object):
    def __init__(self, size, size_ext, misc, cipher_key, checksum, total_packets, packet_number):
        self.size = size
        self.size_ext = size_ext
        self.misc = misc
        self.cipher_key = cipher_key
        self.checksum = checksum
        self.total_packets = total_packets
        self.packet_number = packet_number
        self.Field_1 = size & (pow(2,32)-1)
        self.Field_2 = ((size_ext & 255) << 24) + ((misc & 255) << 16) + (cipher_key & 65535)
        self.Field_3 = ((checksum & 65535) << 16) + ((total_packets & 255) << 8) + (packet_number & 255)
        self.header = (self.Field_1 << 64) + (self.Field_2 << 32) + (self.Field_3)

    def __str__(self):
        string = f'{self.size}\n{self.size_ext},{self.misc},{self.cipher_key}\n{self.checksum},{self.total_packets},{self.packet_number}\n'
        return f'{string}\n{hex(self.Field_1)}\n{hex(self.Field_2)}\n{hex(self.Field_3)}\n{hex(self.header)}\n'

    def __getitem__(self):
        return self.header

    def encrypt(self,Key):
        return rsa.encrypt(self.header.to_bytes(12,'little'),Key)

    def decrypt(self,header_e,Key):
        return int.from_bytes(rsa.decrypt(header_e,Key),'little')

class Receiver(object):
    def __init__(self):
        self.Address = Address_book('addressbook.txt')
        self.headers = list()
        return
    
    def checksum(self,packet):
        sum = 0
        for i in range(0,len(packet)):
            sum = sum + ~packet[i]
        return ~(sum & 15)

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