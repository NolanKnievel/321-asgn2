#!/usr/bin/env python3

from rsa import RSA

def demo_rsa(rsa):    
    # string message
    message_str = "Hello World!"
    print(f"Original message (string): '{message_str}'")
    
    # Show conversion process
    message_as_int = rsa.string_to_int(message_str)
    print(f"String as bytes: {message_str.encode('utf-8')}")
    print(f"Bytes as hex: {message_str.encode('utf-8').hex()}")
    print(f"Hex as integer: {message_as_int}")
    print()
    
    ciphertext_str = rsa.encrypt_string(message_str)
    print(f"Encrypted ciphertext: {ciphertext_str}")
    
    decrypted_str = rsa.decrypt_string(ciphertext_str)
    print(f"Decrypted message: '{decrypted_str}'")
    print()
    


def task_three():
    rsa = RSA(2048)

    print('='*20 + 'RSA encryption-decryption demo' + '='*20)
    # generate key pair
    rsa.generate_keypair()

    # encrypt and decrypt
    demo_rsa(rsa)
        

if __name__ == "__main__":
    task_three()
