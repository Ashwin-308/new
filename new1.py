



'''import socket

# Function to encrypt text using Caesar Cipher
def caesar_cipher_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():  # Encrypt only letters
            shift_base = ord('A') if char.isupper() else ord('a')
            encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted_text += char  # Keep non-alphabet characters unchanged
    return encrypted_text

# Server Setup
HOST = '127.0.0.1'  # Localhost
PORT = 12345
SHIFT_KEY = 3  # Shift value for Caesar Cipher

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print(f"Server listening on {HOST}:{PORT}...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

while True:
    data = conn.recv(1024).decode()
    if not data:
        break
    print(f"Received: {data}")
    encrypted_text = caesar_cipher_encrypt(data, SHIFT_KEY)
    conn.sendall(encrypted_text.encode())

conn.close()

import socket

# Client Setup
HOST = '127.0.0.1'  # Localhost
PORT = 12345        # Must match the server port

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

while True:
    message = input("Enter message: ")
    if message.lower() == "exit":
        break
    client_socket.sendall(message.encode())
    encrypted_response = client_socket.recv(1024).decode()
    print(f"Encrypted Message: {encrypted_response}")

client_socket.close() '''

''' hill cipher import socket
import numpy as np

# Convert characters to numbers (A=0, B=1, ..., Z=25)
def char_to_num(char):
    return ord(char.upper()) - ord('A')

# Convert numbers back to characters
def num_to_char(num):
    return chr(num + ord('A'))

# Hill Cipher Encryption Function
def hill_cipher_encrypt(plaintext, key_matrix):
    # Remove spaces and convert to uppercase
    plaintext = plaintext.replace(" ", "").upper()

    # If odd length, add a padding character (e.g., 'X')
    if len(plaintext) % 2 != 0:
        plaintext += 'X'

    # Convert text to numerical form
    numbers = [char_to_num(c) for c in plaintext]

    # Encrypt in pairs
    encrypted_numbers = []
    for i in range(0, len(numbers), 2):
        vector = np.array([[numbers[i]], [numbers[i+1]]])  # Convert to column vector
        result = np.dot(key_matrix, vector) % 26  # Matrix multiplication (mod 26)
        encrypted_numbers.extend(result.flatten())

    # Convert back to characters
    encrypted_text = ''.join(num_to_char(num) for num in encrypted_numbers)
    return encrypted_text

# Server Setup
HOST = '127.0.0.1'  # Localhost
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print(f"Server listening on {HOST}:{PORT}...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Define a 2x2 Key Matrix (Must be invertible mod 26)
key_matrix = np.array([[3, 3], [2, 5]])

while True:
    data = conn.recv(1024).decode()
    if not data:
        break
    print(f"Received: {data}")
    encrypted_text = hill_cipher_encrypt(data, key_matrix)
    conn.sendall(encrypted_text.encode())

conn.close()

import socket

# Client Setup
HOST = '127.0.0.1'  # Localhost
PORT = 12345        # Must match the server port

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

while True:
    message = input("Enter message: ")
    if message.lower() == "exit":
        break
    client_socket.sendall(message.encode())
    encrypted_response = client_socket.recv(1024).decode()
    print(f"Encrypted Message: {encrypted_response}")

client_socket.close()'''
 
 






''' server import socket

import socket

# Vigenere Cipher Encryption Function
def vigenere_encrypt(plaintext, key):
    encrypted_text = []
    key = key.upper()
    key_length = len(key)
    
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            if char.isupper():
                encrypted_text.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            else:
                encrypted_text.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        else:
            encrypted_text.append(char)
    
    return ''.join(encrypted_text)

# Server Setup
HOST = '127.0.0.1'  # Localhost
PORT = 12345        # Port to listen on

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print(f"Server listening on {HOST}:{PORT}...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

key = "SECRET"  # Define the encryption key

while True:
    data = conn.recv(1024).decode()
    if not data:
        break
    print(f"Received: {data}")
    encrypted_text = vigenere_encrypt(data, key)
    conn.sendall(encrypted_text.encode())

conn.close()


client
import socket

# Client Setup
HOST = '127.0.0.1'  # Localhost
PORT = 12345        # Same port as server

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

while True:
    message = input("Enter message: ")
    if message.lower() == "exit":
        break
    client_socket.sendall(message.encode())
    encrypted_response = client_socket.recv(1024).decode()
    print(f"Encrypted Message: {encrypted_response}")

client_socket.close() '''



#df
'''
import socket import random

    p = 23
    g = 5

    private_key = random.randint(1, p-1) public_key = pow(g, private_key, p)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) server.bind(("127.0.0.1", 5555))
    server.listen(1)

    print("[SERVER] Waiting for client connection...") conn, addr = server.accept()
    print(f"[SERVER] Connected to {addr}")

    # Send public key to client conn.send(str(public_key).encode()) print(f"[SERVER] Sent public key: {public_key}")

    # Receive client's public key
    client_public_key = int(conn.recv(1024).decode()) print(f"[SERVER] Received client public key: {client_public_key}")

    # Compute shared secret
    shared_secret = pow(client_public_key, private_key, p) print(f"[SERVER] Shared Secret: {shared_secret}")

    conn.close() server.close()
    print("[SERVER] Connection closed.")

client
import socket import random

p = 23
g = 5

private_key = random.randint(1, p-1) public_key = pow(g, private_key, p)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print("[CLIENT] Connecting to server...") client.connect(("127.0.0.1", 5555))

# Receive server's public key
server_public_key = int(client.recv(1024).decode()) print(f"[CLIENT] Received server public key: {server_public_key}")

# Send client's public key client.send(str(public_key).encode()) print(f"[CLIENT] Sent public key: {public_key}")

# Compute shared secret
shared_secret = pow(server_public_key, private_key, p) print(f"[CLIENT] Shared Secret: {shared_secret}")
client.close()
print("[CLIENT] Connection closed.")

mim
import socket
import time # Added for delays

p = 23
g = 5

# MITM acts as a fake server to the client
mitm = socket.socket(socket.AF_INET, socket.SOCK_STREAM) mitm.bind(("127.0.0.1", 6666))
mitm.listen(1)

print("[MITM] Waiting for client to connect...") client_conn, client_addr = mitm.accept() print(f"[MITM] Client connected from {client_addr}")

# Small delay to ensure server is running before MITM connects time.sleep(1)

# MITM now connects to the real server
server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM) server_conn.connect(("127.0.0.1", 6666))
print("[MITM] Connected to the real server.")

# Small delay to ensure connections are stable time.sleep(1)

# Receive public key from server
server_public_key = int(server_conn.recv(1024).decode()) print(f"[MITM] Intercepted server's public key: {server_public_key}")

# Introduce a slight delay before sending fake key time.sleep(1)

# Replace server's public key with a fake key and send to client fake_key = 10
print(f"[MITM] Sent fake public key to client: {fake_key}")

# Receive public key from client
client_public_key = int(client_conn.recv(1024).decode()) print(f"[MITM] Intercepted client's public key: {client_public_key}")
# Delay before sending manipulated key to the server time.sleep(1)

# Replace client's public key with the fake key and send to server server_conn.send(str(fake_key).encode())
print(f"[MITM] Sent fake public key to server: {fake_key}")

# MITM calculates secrets with both parties attacker_secret_with_client = pow(client_public_key, 1, p) attacker_secret_with_server = pow(server_public_key, 1, p)

print(f"[MITM] Attacker's Secret with Client: {attacker_secret_with_client}") print(f"[MITM] Attacker's Secret with Server: {attacker_secret_with_server}")

# Close all connections client_conn.close() server_conn.close() mitm.close()
print("[MITM] Attack completed. Connections closed.") '''
















 #rsa

'''import socket 
 
def power(base, expo, m): 
    res = 1 
    base = base % m 
    while expo > 0: 
        if expo & 1: 
            res = (res * base) % m 
        base = (base * base) % m 
        expo //= 2 
    return res 
 
def mod_inverse(e, phi): 
    for d in range(2, phi): 
        if (e * d) % phi == 1: 
            return d 
    return -1   
 
def decrypt(c, d, n): 
    return power(c, d, n) 
 
client_socket = socket.socket() 
client_socket.connect(('127.0.0.1', 12355)) 
print("Connected to server.") 
 
e_n_data = client_socket.recv(1024).decode() 
e, n = map(int, e_n_data.split(',')) 
 
p = 17 
q = 11 
phi = (p - 1) * (q - 1) 
d = mod_inverse(e, phi) 
 
while True: 
    encrypted_msg = client_socket.recv(1024).decode() 
    if encrypted_msg.lower() == 'exit': 
        break 
     
    print(f"Received Cipher Text: {encrypted_msg}") 
 
    decrypted_msg = decrypt(int(encrypted_msg), d, n) 
    print(f"Decrypted Message: {decrypted_msg}") 
 
client_socket.close() 

import socket 
 
def power(base, expo, m): 
    res = 1 
    base = base % m 
    while expo > 0: 
        if expo & 1: 
            res = (res * base) % m 
        base = (base * base) % m 
        expo //= 2 
    return res 
 
def encrypt(m, e, n): 
    return power(m, e, n) 
 
p = 17 
q = 11 
n = p * q 
phi = (p - 1) * (q - 1) 
e = 7   
 
server_socket = socket.socket() 
server_socket.bind(('127.0.0.1', 12355)) 
server_socket.listen(1) 
 
conn, addr = server_socket.accept() 
print("Client connected.") 
 
conn.send(f"{e},{n}".encode()) 
 
while True: 
    msg = input("Enter a number to encrypt (or type 'exit' to quit): ") 
    if msg.lower() == 'exit': 
        conn.send("exit".encode()) 
        break 
 
    try: 
        msg_int = int(msg) 
        encrypted_msg = encrypt(msg_int, e, n) 
        print(f"Encrypted Message: {encrypted_msg}") 
        conn.send(str(encrypted_msg).encode()) 
    except ValueError: 
        print("Invalid input. Please enter a number.") 
 
conn.close() 
server_socket.close() '''


 #sdes key exchange
''' def keyGen(key):
    # P10 permutation
    p10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    p8 = [6, 3, 7, 4, 8, 5, 10, 9]
    
    # Apply P10
    p10k = [key[i-1] for i in p10]
    
    # Left shift by 1
    sp10k = p10k[1:5] + [p10k[0]] + p10k[6:10] + [p10k[5]]
    
    # Apply P8 to get K1
    k1 = [sp10k[i-1] for i in p8]
    
    # Left shift by 3
    s3p10k = sp10k[2:5] + sp10k[0:2] + sp10k[7:10] + sp10k[5:7]
    
    # Apply P8 to get K2
    k2 = [s3p10k[i-1] for i in p8]
    
    return "".join(k1), "".join(k2)

Example Usage
key = input("Enter 10-bit key: ")
k1, k2 = keyGen(key)
print(f"K1: {k1}, K2: {k2}") '''

#md5
'''import struct  
  
def left_rotate(n, b):  
    return ((n << b) | (n >> (32 - b))) & 0xffffffff  
  
def sha1(message):  
    h0 = 0x67452301  
    h1 = 0xEFCDAB89  
    h2 = 0x98BADCFE  
    h3 = 0x10325476  
    h4 = 0xC3D2E1F0  
      
    message_byte_array = bytearray(message, 'ascii')  
    original_length_bits = (8 * len(message_byte_array)) & 0xffffffffffffffff  
    message_byte_array.append(0x80)  
      
    while (len(message_byte_array) * 8) % 512 != 448:  
        message_byte_array.append(0)  
      
    message_byte_array += struct.pack('>Q', original_length_bits)  
      
    for chunk_index in range(0, len(message_byte_array), 64):  
        chunk = message_byte_array[chunk_index:chunk_index + 64]  
        w = [0] * 80  
          
        for i in range(16):  
            w[i] = struct.unpack('>I', chunk[i * 4:(i + 1) * 4])[0]  
          
        for i in range(16, 80):  
            w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)  
          
        a = h0  
        b = h1  
        c = h2  
        d = h3  
        e = h4  
          
        for i in range(80):  
            if 0 <= i <= 19:  
                f = (b & c) | ((~b) & d)  
                k = 0x5A827999  
            elif 20 <= i <= 39:  
                f = b ^ c ^ d  
                k = 0x6ED9EBA1  
            elif 40 <= i <= 59:  
                f = (b & c) | (b & d) | (c & d)  
                k = 0x8F1BBCDC  
            else:  
                f = b ^ c ^ d  
                k = 0xCA62C1D6  
              
            temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff  
            e = d  
            d = c  
            c = left_rotate(b, 30)  
            b = a  
            a = temp  
          
        h0 = (h0 + a) & 0xffffffff  
        h1 = (h1 + b) & 0xffffffff  
        h2 = (h2 + c) & 0xffffffff  
        h3 = (h3 + d) & 0xffffffff  
        h4 = (h4 + e) & 0xffffffff  
      
    return '{:08x}{:08x}{:08x}{:08x}{:08x}'.format(h0, h1, h2, h3, h4)  
  
# Example here   
message = "ashwin"  
hash_value = sha1(message)  
print("SHA-1 Hash:", hash_value) '''
#sha
'''import struct  
  
def left_rotate(n, b):  
    return ((n << b) | (n >> (32 - b))) & 0xffffffff  
  
def sha1(message):  
    h0 = 0x67452301  
    h1 = 0xEFCDAB89  
    h2 = 0x98BADCFE  
    h3 = 0x10325476  
    h4 = 0xC3D2E1F0  
      
    message_byte_array = bytearray(message, 'ascii')  
    original_length_bits = (8 * len(message_byte_array)) & 0xffffffffffffffff  
    message_byte_array.append(0x80)  
      
    while (len(message_byte_array) * 8) % 512 != 448:  
        message_byte_array.append(0)  
      
    message_byte_array += struct.pack('>Q', original_length_bits)  
      
    for chunk_index in range(0, len(message_byte_array), 64):  
        chunk = message_byte_array[chunk_index:chunk_index + 64]  
        w = [0] * 80  
          
        for i in range(16):  
            w[i] = struct.unpack('>I', chunk[i * 4:(i + 1) * 4])[0]  
          
        for i in range(16, 80):  
            w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)  
          
        a = h0  
        b = h1  
        c = h2  
        d = h3  
        e = h4  
          
        for i in range(80):  
            if 0 <= i <= 19:  
                f = (b & c) | ((~b) & d)  
                k = 0x5A827999  
            elif 20 <= i <= 39:  
                f = b ^ c ^ d  
                k = 0x6ED9EBA1  
            elif 40 <= i <= 59:  
                f = (b & c) | (b & d) | (c & d)  
                k = 0x8F1BBCDC  
            else:  
                f = b ^ c ^ d  
                k = 0xCA62C1D6  
              
            temp = (left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff  
            e = d  
            d = c  
            c = left_rotate(b, 30)  
            b = a  
            a = temp  
          
        h0 = (h0 + a) & 0xffffffff  
        h1 = (h1 + b) & 0xffffffff  
        h2 = (h2 + c) & 0xffffffff  
        h3 = (h3 + d) & 0xffffffff  
        h4 = (h4 + e) & 0xffffffff  
      
    return '{:08x}{:08x}{:08x}{:08x}{:08x}'.format(h0, h1, h2, h3, h4)  
  
# Example here   
message = "ashwin"  
hash_value = sha1(message)  
print("SHA-1 Hash:", hash_value)'''
