from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def adjust_key(key, required_length):
    if len(key) < required_length:
        key += get_random_bytes(required_length - len(key))
    elif len(key) > required_length:
        key = key[:required_length]
    return key

def encrypt(algorithm, key, iv, plaintext):
    if algorithm == 'DES':
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif algorithm == '3DES':
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif algorithm == 'AES-256':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Unsupported algorithm")

    padded_text = pad(plaintext.encode(), cipher.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return base64.b64encode(ciphertext).decode()

def decrypt(algorithm, key, iv, ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    if algorithm == 'DES':
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif algorithm == '3DES':
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif algorithm == 'AES-256':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Unsupported algorithm")

    decrypted_data = unpad(cipher.decrypt(ciphertext), cipher.block_size)
    return decrypted_data.decode()

def main():
    algorithm = input("Seleccione el algoritmo (DES, 3DES, AES-256): ").strip()

    if algorithm == 'DES':
        key = input("Ingrese una clave para DES: ").encode()
        iv = input("Ingrese un IV de 8 bytes para DES: ").encode()
        key = adjust_key(key, 8)
        iv = adjust_key(iv, 8)
    
    elif algorithm == '3DES':
        key = input("Ingrese una clave para 3DES: ").encode()
        iv = input("Ingrese un IV de 8 bytes para 3DES: ").encode()
        key = adjust_key(key, 24)
        iv = adjust_key(iv, 8)

    elif algorithm == 'AES-256':
        key = input("Ingrese una clave para AES-256: ").encode()
        iv = input("Ingrese un IV de 16 bytes para AES-256: ").encode()
        key = adjust_key(key, 32)
        iv = adjust_key(iv, 16)
    else:
        print("Algoritmo no soportado.")
        return

    print(f"Clave ajustada utilizada: {key}")
    print(f"IV utilizado: {iv}")

    plaintext = input("Ingrese el texto a cifrar: ")
    ciphertext = encrypt(algorithm, key, iv, plaintext)
    print(f"Texto cifrado (base64): {ciphertext}")

    decrypted_text = decrypt(algorithm, key, iv, ciphertext)
    print(f"Texto descifrado: {decrypted_text}")

if __name__ == "__main__":
    main()
