import Crypto.Cipher.AES

def Encrypt(key, plaintext):
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext,tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, nonce, tag

def Decrypt(key, ciphertext, nonce,tag):
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('ascii')
    except ValueError:
        return False