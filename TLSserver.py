import socket
import pyodbc
import datetime
import pyDH
import AES_EAX
import hashlib
import pandas as pd

import falcon
import uuid

ip = "127.0.0.1"
port = 60000
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((ip, port))
s.listen(1)

server = pyDH.DiffieHellman()
server_pk = server.gen_public_key()

def CheckUser(username, password):
    conn = pyodbc.connect('Driver={SQL Server};'
                          'Server=CEIYSEKIRALOASB\CEIYSBENNOVA;'
                          'Database=DatabaseServer;'
                          'Trusted_Connection=yes;')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM UserInfo WHERE Username = ? AND Password = ?", username, password)
    row = cursor.fetchone()
    if row is None:
        return False
    else:
        return True
def SendEnc(key,plaintext,conn):
    plaintextEncode = plaintext.encode()
    ciphertext,nonce,tag = AES_EAX.Encrypt(key,plaintextEncode)
    ciphertextHex = ciphertext.hex()
    conn.send(PadSocket(ciphertextHex).encode())
    nonceHex = nonce.hex()
    conn.send(PadSocket(nonceHex).encode())
    tagHex = tag.hex()
    conn.send(PadSocket(tagHex).encode())
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

def UpdateToDB(Username,Sig, SerialNumber, NotValidBefore, NotValidAfter):
    conn = pyodbc.connect('Driver={SQL Server};'
                            'Server=CEIYSEKIRALOASB\CEIYSBENNOVA;'
                            'Database=DatabaseServer;'
                            'Trusted_Connection=yes;')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO SignInfo (Username, Sig, SerialNumber, NotValidBefore, NotValidAfter) VALUES (?,?,?,?,?)", Username, Sig, SerialNumber, NotValidBefore, NotValidAfter)
    conn.commit()
    return True

def GetSecretKeyFromDB(username):
    conn = pyodbc.connect('Driver={SQL Server};'
                          'Server=CEIYSEKIRALOASB\CEIYSBENNOVA;'
                          'Database=DatabaseServer;'
                          'Trusted_Connection=yes;')
    query = (f"select SecretKey from KeyInfo where Username = '{username}'")
    data = pd.read_sql_query(query, conn)
    print(data)
    return data.iloc[0][0]

def GetSecretKeyBySig(sig):
    conn = pyodbc.connect('Driver={SQL Server};'
                            'Server=CEIYSEKIRALOASB\CEIYSBENNOVA;'
                            'Database=DatabaseServer;'
                            'Trusted_Connection=yes;')
    query = (f"SELECT KeyInfo.SecretKey from KeyInfo,SignInfo where KeyInfo.Username = SignInfo.Username and SignInfo.Sig = '{sig}'")
    data = pd.read_sql_query(query, conn)
    return data.iloc[0][0]

def GetDataFromDB(sig):
    conn = pyodbc.connect('Driver={SQL Server};'
                          'Server=CEIYSEKIRALOASB\CEIYSBENNOVA;'
                          'Database=DatabaseServer;'
                          'Trusted_Connection=yes;')
    query = (f"SELECT UserInfo.OrgName, UserInfo.Province, UserInfo.City, UserInfo.District,UserInfo.Email,SignInfo.Sig, SignInfo.SerialNumber,SignInfo.NotValidBefore, SignInfo.NotValidAfter FROM UserInfo,SignInfo where UserInfo.Username = SignInfo.Username and Sig = '{sig}'")
    data = pd.read_sql_query(query, conn)
    return data.iloc[0][0],data.iloc[0][1],data.iloc[0][2],data.iloc[0][3],data.iloc[0][4],data.iloc[0][5],data.iloc[0][6],data.iloc[0][7],data.iloc[0][8]
def CertFormat(sig,publickey,hashdata,sigoriginal):
    orgname,province,city,district,email,sig,serialnumber,notvalidbefore,notvalidafter = GetDataFromDB(sig)
    if pk.verify(hashdata.encode(), sigoriginal):
        flag = 'Signature verified'
    else:
        flag = 'Signature not verified'
    s = "-------------------------Begin Certificate-------------------------\n"
    s+= "CA: Group 5\n"
    s+= "Signature Algorithm: Falcon512\n"
    s+= "Public Key: " + str(publickey) + "\n"
    s+= "Organization Name: " + orgname + "\n"
    s+= "Province: " + province + "\n"
    s+= "City: " + city + "\n"
    s+= "District: " + district + "\n"
    s+= "Email: " + email + "\n"
    s+= "Sig: " + sig + "\n"
    s+= "Serial Number: " + serialnumber + "\n"
    s+= "Not Valid Before: " + notvalidbefore + "\n"
    s+= "Not Valid After: " + notvalidafter + "\n"
    s+="Status: " + flag + "\n"
    s+= "-------------------------End Certificate-------------------------\n"
    return s

if __name__ == "__main__":

    print("Server is running...")
    print("Waiting for connection...")
    while True:
        conn, addr = s.accept()
        #nhan public key của client
        client_pk = int(conn.recv(1024).decode())
        #tao shared key
        shared_key = server.gen_shared_key(client_pk)
        shared_key_bytes = hashlib.sha256(shared_key.encode()).digest()
        #gửi public key của server
        conn.send(str(server_pk).encode())

        # nhận thong tin ve lua chon
        choice = conn.recv(1024).decode()
        print("Choice: ", choice)
        if choice == "1":

            check = False
            while check == False:
                username = ReceiveEnc(shared_key_bytes, conn)
                password = ReceiveEnc(shared_key_bytes, conn)
                passwordHash = hashlib.sha512(password.encode()).hexdigest()
                print(passwordHash)
                if CheckUser(username, passwordHash):
                    SendEnc(shared_key_bytes, "True", conn)
                else:
                    SendEnc(shared_key_bytes, "False", conn)
                data = ReceiveEnc(shared_key_bytes, conn)
                if data == "Login Successful":
                    check = True
                    print("Connection from: ", addr, "Username: ", username)
            flag = False
            while flag == False:
                print("Waiting for request...")
                # nhận file
                hashdata = ReceiveEnc(shared_key_bytes, conn)
                # hash file
                #hashdata = hashlib.sha256(alldata).hexdigest()
                skfromdb = GetSecretKeyFromDB(username)
                polys = []
                sklist = bytes.fromhex(skfromdb).decode().split("\n")
                for i in range(4):
                    string = sklist[i][sklist[i].find("[") + 1:sklist[i].find("]")].split(",")
                    for j in range(len(string)):
                        string[j] = int(string[j])
                    polys.append(string)
                sk = falcon.SecretKey(512,polys)
                skhex = str(sk).encode().hex()
                pk = falcon.PublicKey(sk)
                pkhex = str(pk).encode().hex()

                signature = sk.sign(hashdata.encode())
                signaturehex = signature.hex()
                serialID = str(uuid.uuid4())
                NotValidBefore = str(datetime.datetime.now().date())
                NotValidAfter = str(datetime.datetime.now().date() + datetime.timedelta(days=365))
                # gửi thông tin về database
                UpdateToDB(username, signaturehex, serialID, NotValidBefore, NotValidAfter)
                print("Sig: Done")
                #gửi chữ ký về client
                conn.send(signaturehex.encode())
                flag = True
        elif choice == '2':
            flag = False
            while flag == False:
                hashdata = ReceiveEnc(shared_key_bytes, conn)
                sighex = conn.recv(2048).decode()
                sig = bytes.fromhex(sighex)
                skhex = GetSecretKeyBySig(sighex)
                print("Secret Key: ", skhex)
                polys = []
                sklist = bytes.fromhex(skhex).decode().split("\n")
                for i in range(4):
                    string = sklist[i][sklist[i].find("[") + 1:sklist[i].find("]")].split(",")
                    for j in range(len(string)):
                        string[j] = int(string[j])
                    polys.append(string)
                print(polys)
                sk = falcon.SecretKey(512,polys)
                pk = falcon.PublicKey(sk)
                cert = CertFormat(sighex, pk, hashdata, sig)
                print("Certificate: ", cert)
                conn.sendall(cert.encode())
                flag = True



