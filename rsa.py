#!/usr/bin/env python3

import secrets
from Crypto.Util import number
import hashlib


# test comment
class RSA:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.e = 65537
        self.p = None
        self.q = None
        self.n = None
        self.euler_totient = None
        self.d = None
        self.public_key = None
        self.private_key = None
    
    # generate prime number of specified bit length
    def generate_prime(self, bits):
        return number.getPrime(bits)
    
    # find gcd and coefficients with extended euclidean algorithm
    def extended_gcd(self, a, b):
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    

    # multiplicative inverse of a mod m
    def mod_inverse(self, a, m):
        gcd, x, _ = self.extended_gcd(a, m)
        
        if gcd != 1:
            raise ValueError(f"multiplicative inverse does not exist for {a} mod {m}")
        
        return (x % m + m) % m
    
    def generate_keypair(self):
        # create two primes
        prime_bits = self.key_size // 2
        self.p = self.generate_prime(prime_bits)
        self.q = self.generate_prime(prime_bits)
                
        # n=p*q
        self.n = self.p * self.q
        
        # euler's totient -- (p-1)(q-1)
        self.euler_totient = (self.p - 1) * (self.q - 1)
                
        # private exponent -- d = e^(-1) mod totient
        self.d = self.mod_inverse(self.e, self.euler_totient)
        
        # public and private keys
        self.public_key = (self.n, self.e)
        self.private_key = (self.n, self.d)
        
        return self.public_key, self.private_key
    
    # encrypt using public key
    def encrypt(self, message, public_key=None):
        if public_key is None:
            if self.public_key is None:
                raise ValueError("no public key")
            n, e = self.public_key
        else:
            n, e = public_key
        
        # convert message to int if it's a string
        if isinstance(message, str):
            message_int = self.string_to_int(message)
        else:
            message_int = message
        
        # make sure message isn't too big
        if message_int >= n:
            raise ValueError(f"message {message_int} too large for key size, must be < {n}")
        
        # encrypt: c = m^e mod n
        ciphertext = pow(message_int, e, n)
        return ciphertext
    
    # decrypt ciphertext using private key
    def decrypt(self, ciphertext, private_key=None):
        if private_key is None:
            if self.private_key is None:
                raise ValueError("n private key available")
            n, d = self.private_key
        else:
            n, d = private_key
        
        # Decrypt: m = c^d mod n
        message_int = pow(ciphertext, d, n)
        return message_int
    
    # convert string to an int
    def string_to_int(self, message):
        message_bytes = message.encode('utf-8')
        message_hex = message_bytes.hex()
        message_int = int(message_hex, 16)
        return message_int
    
    # convert int back to string
    def int_to_string(self, message_int):
        # convert int to hex
        message_hex = hex(message_int)[2:] 
        
        # make sure even number of hex digits
        if len(message_hex) % 2:
            message_hex = '0' + message_hex
        
        message_bytes = bytes.fromhex(message_hex)
        message_str = message_bytes.decode('utf-8')
        return message_str
    
    # encrypt string and return ciphertext
    def encrypt_string(self, message):
        ciphertext = self.encrypt(message)
        return ciphertext
    
    # decrypt ciphertext and return string
    def decrypt_string(self, ciphertext):
        message_int = self.decrypt(ciphertext)
        message_str = self.int_to_string(message_int)
        return message_str
    
