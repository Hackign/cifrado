import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

if __name__ == "__main__":
    print("Selecciona un método de cifrado:")
    print("1. César")
    print("2. XOR")
    print("3. AES")
    
    opcion = input("Opción: ")
    mensaje = input("Ingrese el mensaje a cifrar: ")
    
    if opcion == "1":
        shift = int(input("Ingrese el desplazamiento: "))
        mensaje_cifrado = caesar_cipher(mensaje, shift)
        print("Mensaje cifrado:", mensaje_cifrado)
        print("Mensaje descifrado:", caesar_decipher(mensaje_cifrado, shift))
    
    elif opcion == "2":
        clave = input("Ingrese la clave XOR: ")
        mensaje_cifrado = xor_cipher(mensaje, clave)
        print("Mensaje cifrado:", mensaje_cifrado)
        print("Mensaje descifrado:", xor_cipher(mensaje_cifrado, clave))
    
    elif opcion == "3":
        clave = input("Ingrese la clave AES: ")
        mensaje_cifrado = aes_encrypt(clave, mensaje)
        print("Mensaje cifrado:", mensaje_cifrado)
        print("Mensaje descifrado:", aes_decrypt(clave, mensaje_cifrado))
    else:
        print("Opción no válida.")
