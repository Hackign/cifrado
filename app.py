from flask import Flask, render_template, request
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

def generate_key(user_key):
    return hashlib.sha256(user_key.encode()).digest()

# Cifrado César
def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def caesar_decipher(text, shift):
    return caesar_cipher(text, -shift)

# Cifrado XOR
def xor_cipher(text, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

# Cifrado AES
def aes_encrypt(user_key, message):
    key = generate_key(user_key)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + encrypted_bytes).decode()

def aes_decrypt(user_key, encrypted_message):
    key = generate_key(user_key)
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:AES.block_size]
    encrypted_bytes = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_bytes), AES.block_size).decode()

@app.route('/', methods=['GET', 'POST'])
def index():
    encrypted_message = decrypted_message = ""
    if request.method == 'POST':
        message = request.form['message']
        key = request.form['key']
        method = request.form['method']

        if method == 'caesar':
            shift = int(request.form['shift'])
            encrypted_message = caesar_cipher(message, shift)
            decrypted_message = caesar_decipher(encrypted_message, shift)
        elif method == 'xor':
            encrypted_message = xor_cipher(message, key)
            decrypted_message = xor_cipher(encrypted_message, key)
        elif method == 'aes':
            encrypted_message = aes_encrypt(key, message)
            decrypted_message = aes_decrypt(key, encrypted_message)
    
    return render_template('index.html', encrypted_message=encrypted_message, decrypted_message=decrypted_message)

if __name__ == "__main__":
    app.run(debug=True)
