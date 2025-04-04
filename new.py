 



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