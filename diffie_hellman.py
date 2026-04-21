#!/usr/bin/env python3
import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class DiffieHellman:
    def __init__(self, q, a):
        self.q = q
        self.a = a
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        
    def generate_private_key(self):
        self.private_key = secrets.randbelow(self.q - 1) + 1
        return self.private_key
    
    def compute_public_key(self):
        """(a^private_key) % q"""
        if self.private_key is None:
            raise ValueError("Private key not generated")
        self.public_key = pow(self.a, self.private_key, self.q)
        return self.public_key
    
    def compute_shared_secret(self, other_public_key):
        """(other_public_key^private_key) % q"""
        if self.private_key is None:
            raise ValueError("private key not generated")
        self.shared_secret = pow(other_public_key, self.private_key, self.q)
        return self.shared_secret
    
    # get aes key from shared secret -- SHA256
    def make_key(self):
        if self.shared_secret is None:
            raise ValueError("sharedd secret not computed")
        # convert shared secret to bytes and hash it
        secret_bytes = self.shared_secret.to_bytes((self.shared_secret.bit_length() + 7) // 8, 'big')
        hash_digest = hashlib.sha256(secret_bytes).digest()
        # truncate to 16 bytes for aes-128
        return hash_digest[:16]

# encrypt using cbc
def aes_encrypt(key, plaintext, iv=None):
    if iv is None:
        iv = b'\x00' * 16  # zero as iv
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext

# decrypt using CBC
def aes_decrypt(key, ciphertext, iv=None):
    if iv is None:
        iv = b'\x00' * 16  # using zero as iv
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_text, AES.block_size)
    return plaintext.decode('utf-8')
