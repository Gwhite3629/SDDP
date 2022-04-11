#!/usr/bin/python3

from interface import Address_book, Receiver
import gc

def main():
    R = Receiver()
    print(R.Address)
    R.Address['192.168.7.2'] = ('3','Random','key')
    print(R.Address)
    R.Address.write_book()
    A = Address_book('addressbook.txt')
    print(A)

if __name__ == "__main__":
    main()