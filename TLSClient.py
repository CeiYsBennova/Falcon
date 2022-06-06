import socket
import pyDH
import AES_EAX
import hashlib
client = pyDH.DiffieHellman()
client_pk = client.gen_public_key()
def CheckLogin(username, password,socket,key):
    SendEnc(key,username,socket)
    SendEnc(key,password,socket)
    data = ReceiveEnc(key,socket)
    if data == "True":
        return True
    else:
        return False

'''def SetRequest(socket, key, country, state,city, organization, email):
    SendEnc(key,country,socket)
    SendEnc(key,state,socket)
    SendEnc(key,city,socket)
    SendEnc(key,organization,socket)
    SendEnc(key,email,socket)
    return True'''

def UpLoadFile(filename,socket,key):
    with open(filename, 'rb') as f:
        for line in f:
            SendEnc(key,line,socket)

def SendEnc(key,plaintext,socket):
    plaintextEncode = plaintext.encode()
    ciphertext,nonce,tag = AES_EAX.Encrypt(key,plaintextEncode)
    ciphertextHex = ciphertext.hex()
    socket.send(PadSocket(ciphertextHex).encode())
    nonceHex = nonce.hex()
    socket.send(PadSocket(nonceHex).encode())
    tagHex = tag.hex()
    socket.send(PadSocket(tagHex).encode())
    return True
def ReceiveEnc(key,socket):
    ciphertextwithpad = socket.recv(2048).decode()
    cipher = bytes.fromhex(UnPadSocket(ciphertextwithpad))
    noncewithpad = socket.recv(2048).decode()
    nonce = bytes.fromhex(UnPadSocket(noncewithpad))
    tagwithpad = socket.recv(2048).decode()
    tag = bytes.fromhex(UnPadSocket(tagwithpad))
    plaintext = AES_EAX.Decrypt(key,cipher,nonce,tag)
    return plaintext

def PadSocket(message):
    if (len(message)<2048):
        message+='1'
    while (len(message)<2048):
        message+='0'
    return message
def UnPadSocket(message):
    message = message[:message.rfind("1")]
    return message

if __name__ == "__main__":
    ip = "127.0.0.1"
    port = 60000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    #gửi public key của diffie hellman
    s.send(str(client_pk).encode())
    #nhận public key của server
    server_pk = int(s.recv(1024).decode())
    #tạo shared key
    shared_key = client.gen_shared_key(server_pk)
    shared_key_bytes = hashlib.sha256(shared_key.encode()).digest()


    print("---------------Welcome to the our project!---------------")
    print("Pls choose:")
    print("1. Set Request To Sign Document")
    print("2. Verify Document")
    choice = input("Enter your choice: ")
    s.send(choice.encode())
    if choice == "1":
        flag = False
        while flag == False:

            check = False
            while check == False:
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                if CheckLogin(username, password, s, shared_key_bytes):
                    print("Login Successful")
                    check = True
                    SendEnc(shared_key_bytes, "Login Successful", s)
                    break
                else:
                    print("Login Failed. Retry")
                    SendEnc(shared_key_bytes, "Login Failed. Retry", s)

            print('Step 1: Upload your document:')
            filepath = input("Enter the filepath: ")
            # gửi file
            with open(filepath, 'rb') as f:
                send_data = f.read()
            hashdata = str(hashlib.sha256(send_data).hexdigest())
            SendEnc(shared_key_bytes, hashdata, s)
            print('------------------------------------------------------')
            print('Step 3: Wait for the server to send the signature')
            sig = s.recv(2048).decode()
            print("Signature: ", sig)
            print('Step 4: Enter filepath to save the signature')
            filesave = input("Enter the filepath: ")
            with open(filesave, "w") as f:
                f.write(sig)
            print('-------------------------End-----------------------------')
            flag = True
    elif choice == "2":
        flag = False
        while flag == False:
            print('Step 1: Upload your document:')
            filepath = input("Enter the filepath: ")
            # gửi file
            with open(filepath, 'rb') as f:
                send_data = f.read()
            hashdata = str(hashlib.sha256(send_data).hexdigest())
            SendEnc(shared_key_bytes, hashdata, s)
            print('------------------------------------------------------')
            print('Step 2: Upload your signature:')
            filepath = input("Enter the filepath: ")
            with open(filepath, "rb") as f:
                data = f.read()
            s.send(data)
            cert = s.recv(12000).decode()
            print(cert)
            #message = s.recv(2048).decode()
            #print("Verify Result: ", message)
            print('-------------------------End-----------------------------')
            flag = True
