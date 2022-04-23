#!/usr/bin/python3

from genericpath import exists
from operator import mod
import pathlib
from tkinter import FALSE, TRUE
from pkg_resources import ResolutionError
import rsa
import os
import math as m
import string
import random
import socket

port = 8333
size = 488

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

class Sender(object):
    def __init__(self):
        self.Address = Address_book('addressbook.txt')
        self.headers = list()
        self.header_e = list()
        self.packets = list()
        self.checksums = list()
        self.cipher_keys = list()
        self.frames = list()
        self.packets_e = list()
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.state = State()
        return

    def connect(self, address):
        self.current_address = address
        self.sock.sendto(self.header_t,self.current_address)
        (ret, addr) = self.sock.recvfrom(32)
        if (addr != address):
            return "Failed"
        received = Header.decrypt(self.header_t,ret,self.Address.private)
        self.received = Header(
            (received >> 112) & (pow(2,32) - 1),
            (received >> 104) & 255,
            (received >> 96) & 255,
            (received >> 48) & (pow(2,48) - 1),
            (received >> 32) & 65535,
            (received >> 16) & 65535,
            received & 65535)
        if (self.received != self.header_t):
            return "Failed"
        self.State = "Connected"
        return

    def send_frame(self, num):
        self.sock.sendto(self.frames[num], (self.current_address, port))

    def done(self, address):
        d = Header(self.size,0,0,0,0,0,0)
        h = Header.encrypt(d, 
                self.Address.getkey(
                    self.Address[self.current_address][2]
                ))
        self.sock.sendto(h, self.current_address)
        self.state = "Waiting"

    def create_frames(self):
        for i in range(0,self.total_packets):
            print(len(self.header_e[i]),len(self.packets_e[i]))
            self.frames.append(b''.join([self.header_e[i],self.packets_e[i]]))

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
                self.packets.append(self.data[i*448:-1])
                padding_length = 448-len(self.packets[i])
                for j in range(0,padding_length):
                    self.packets[i] = b''.join([self.packets[i],b'\0'])
            else:
                self.packets.append(self.data[i*448:(i+1)*448])
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
            (received >> 112) & (pow(2,32) - 1),
            (received >> 104) & 255,
            (received >> 96) & 255,
            (received >> 48) & (pow(2,48) - 1),
            (received >> 32) & 65535,
            (received >> 16) & 65535,
            received & 65535)

    def decrypt_data(self, num):
        self.decrypt_header(num)
        k = self.received.cipher_key.to_bytes(6,'little')
        S = RC5_setup(k)
        k = 0
        P = list()
        for j in range(0,448//8+1):
            A = int.from_bytes(self.packets_e[num][(4*k):(4*(k+1))],'little')
            B = int.from_bytes(self.packets_e[num][(4*(k+1)):(4*(k+2))],'little')
            (A, B) = RC5_decrypt(S, A, B)
            p = b''.join([A.to_bytes(4,'little'),B.to_bytes(4,'little')])
            P.append(p)
            k = k + 2
        self.decrypted_packet = b''.join(P)

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
        # Number of packets is equal to file_size(bytes)/(508-header_size)
        # This is because the max safe UDP payload is 508 bytes and the header is 
        # 32 bytes long due to encryption. The end expression is to get any trail data.
        self.total_packets = int(self.size/448)+(mod(self.size,448)>0 if 1 else 0)

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
        self.cipher_packets()
        self.create_frames()
        return

    def gen_cipher(self):
        k = id_generator()
        k = k.encode('utf8')
        return k

    def cipher_packets(self):
        for i in range(0,self.total_packets):
            S = RC5_setup(self.cipher_keys[i])
            k = 0
            P = list()
            for j in range(0,448//8+1):
                A = int.from_bytes(self.packets[i][(4*k):(4*(k+1))],'little')
                B = int.from_bytes(self.packets[i][(4*(k+1)):(4*(k+2))],'little')
                (A, B) = RC5_encrypt(S, A, B)
                p = b''.join([A.to_bytes(4,'little'),B.to_bytes(4,'little')])
                P.append(p)
                k = k + 2
            self.packets_e.append(b''.join(P))
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
        self.State = "Not connected"

    def __getitem__(self, State):
        return self.State

    def __setitem__(self, State):
        self.State = State

class Header(object):
    def __init__(self, size, size_ext, misc, cipher_key, checksum, total_packets, packet_number):
        if (type(cipher_key) == bytes):
            cipher_key = int.from_bytes(cipher_key,'little')
        self.size = size
        self.size_ext = size_ext
        self.misc = misc
        self.cipher_key = cipher_key
        self.checksum = checksum
        self.total_packets = total_packets
        self.packet_number = packet_number
        self.Field_1 = size & (2**32 - 1)
        self.Field_2 = ((size_ext & 255) << 24) + ((misc & 255) << 16) + ((cipher_key >> 32) & 65535)
        self.Field_3 = cipher_key & (2**32 - 1)
        self.Field_4 = ((checksum & 65535) << 16) + (total_packets & 65535)
        self.Field_5 = packet_number & 65525
        self.header = (self.Field_1 << 112) + (self.Field_2 << 80) + (self.Field_3 << 48) + (self.Field_4 << 16) + self.Field_5

    def __str__(self):
        string = f'{self.size}\n{self.size_ext},{self.misc},{self.cipher_key}\n{self.checksum},{self.total_packets},{self.packet_number}\n'
        return f'{string}\n{hex(self.Field_1)}\n{hex(self.Field_2)}\n{hex(self.Field_3)}\n{hex(self.Field_4)}\n{hex(self.Field_5)}\n{hex(self.header)}\n'

    def __getitem__(self):
        return self.header

    def __eq__(self, other):
        return ((self.header) == (other.header))

    def encrypt(self,Key):
        return rsa.encrypt(self.header.to_bytes(16,'little'),Key)

    def decrypt(self,header_e,Key):
        return int.from_bytes(rsa.decrypt(header_e,Key),'little')

class Receiver(object):
    def __init__(self):
        self.Address = Address_book('addressbook.txt')
        self.headers = dict()
        self.header_e = list()
        self.frames = list()
        self.packets_e = list()
        self.packets = dict()
        self.received = 0
        self.client = ""
        self.sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.state = State()
        return
    
    def checksum(self,packet):
        sum = 0
        for i in range(0,len(packet)):
            sum = sum + ~packet[i]
        return ~(sum & 15)

    def verify_checksum(self, num):
        r = self.checksum(self.packets[num])
        if (r == self.headers[num].checksum):
            b = TRUE
        else:
            b = FALSE
        return b

    def connect(self):
        h = Header(0,0,0,0,0,0,0)
        # Template header
        (m, addr1) = self.sock.recvfrom(32)
        self.header_t = Header.decrypt(h, m, self.Address.private)
        self.total_packets = self.header_t.total_packets
        r = Header.encrypt(self.header_t, 
                self.Address.getkey(
                    self.Address[addr1][2]
                ))
        self.sock.sendto(r, (addr1, port))
        # Filename
        (m, addr2) = self.sock.recvfrom(32+self.header_t.size_ext)
        if (addr1 != addr2):
            return "Failed"
        self.current_addr = addr2
        h = Header.decrypt(h, m[0:32], self.Address.private)
        self.filename = self.decrypt_frame(h.cipher_key, m[32:-1])
        self.state = "Receiving"

    def receive_packet(self):
        (m, addr) = self.sock.recvfrom(size)
        if (addr != self.current_addr):
            return "Failed"
        self.frames.append(m)
        self.split_frame(-1)
        num = self.decrypt_header(-1)
        self.decrypt_data(-1, num)

    def get_lost(self, num):
        H = Header(
            self.header_t.size,
            self.header_t.size_ext,
            self.header_t.misc,
            self.header_t.cipher_key,
            self.header_t.checksum,
            self.header_t.total_packets,
            num)
        m = H.encrypt(
                self.Address.getkey(
                    self.Address[self.current_addr][2]
                ))
        self.sock.sendto(m, self.current_addr)
        self.receive_packet()

    def write_data(self):

        return

    def close(self):
        return

    def reject():
        return

    def block(self):
        self.Address.Book[self.client] = (0, "Unknown", "nokey.txt")
        return

    def unblock(self):
        return

    def split_frame(self, num):
        self.header_e.append(self.frames[num][0:32])
        self.packets_e.append(self.frames[num][32:-1])

    def decrypt_header(self, num):
        received = Header.decrypt(self.header_t,self.header_e[num],self.Address.private)
        r = Header(
            (received >> 112) & (pow(2,32) - 1),
            (received >> 104) & 255,
            (received >> 96) & 255,
            (received >> 48) & (pow(2,48) - 1),
            (received >> 32) & 65535,
            (received >> 16) & 65535,
            received & 65535)
        self.headers[r.packet_number] = r
        return r.packet_number

    def decrypt_frame(self, key, data):
        k = key.to_bytes(6, 'little')
        S = RC5_setup(k)
        k = 0
        P = list()
        for j in range(0,size(data)//8+1):
            A = int.from_bytes(data[(4*k):(4*(k+1))],'little')
            B = int.from_bytes(data[(4*(k+1)):(4*(k+2))],'little')
            (A, B) = RC5_decrypt(S, A, B)
            p = b''.join([A.to_bytes(4,'little'),B.to_bytes(4,'little')])
            P.append(p)
            k = k + 2
        return b''.join(P)

    def decrypt_data(self, e_num, o_num):
        k = self.headers[o_num].cipher_key.to_bytes(6, 'little')
        S = RC5_setup(k)
        k = 0
        P = list()
        for j in range(0,448//8+1):
            A = int.from_bytes(self.packets_e[e_num][(4*k):(4*(k+1))],'little')
            B = int.from_bytes(self.packets_e[e_num][(4*(k+1)):(4*(k+2))],'little')
            (A, B) = RC5_decrypt(S, A, B)
            p = b''.join([A.to_bytes(4,'little'),B.to_bytes(4,'little')])
            P.append(p)
            k = k + 2
        self.packets[o_num] = b''.join(P)

    def resolve_trust():
        return
    
    def set_trust(self):
        return

def RC5_setup(k: bytes):
    c = 2
    L = [0, 0]
    for i in range(5,0,-1):
        L[i//4] = mod((rol(L[i//4], 8, 32) + k[i]),2**32)

    S = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    S[0] = mod(int.from_bytes(bytearray.fromhex('B7E15163'),'little'),2**32)
    for i in range(1,25):
        S[i] = mod(S[i - 1] + int.from_bytes(bytearray.fromhex('9E3779B9'),'little'),2**32)

    i = j = 0
    A = B = 0
    for r in range(0,3*26):
        A = S[i] = mod(rol((S[i] + A + B), 3, 32),2**32)
        B = L[j] = mod(rol((L[j] + A + B), (A + B), 32),2**32)
        i = mod((i + 1), 26)
        j = mod((j + 1), c)
    #for i in range(0,len(S)):
    #    S[i] = (S[i] + 2**32) & (2**32 - 1)
    return S

def RC5_decrypt(S, A, B):
    A = mod((A + S[0]),2**32)
    B = mod((B + S[1]),2**32)
    for i in range(1,13):
        A = mod((rol((A ^ B), B, 32) + S[2*i]),2**32)
        B = mod((rol((B ^ A), A, 32) + S[2*i+1]),2**32)
    return A, B

def RC5_encrypt(S, A, B):
    for i in range(12,0,-1):
        B = mod((ror((B - S[2*i+1]), A, 32) ^ A),2**32)
        A = mod((ror((A - S[2*i]), B, 32) ^ B),2**32)
    B = mod((B - S[1]),2**32)
    A = mod((A - S[0]),2**32)
    return A, B