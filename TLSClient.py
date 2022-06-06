import socket
def CheckLogin(username, password,socket):
    socket.send(username.encode())
    socket.send(password.encode())
    data = socket.recv(1024)
    if data.decode() == "True":
        return True
    else:
        return False
def CountLine(filename):
    with open(filename, 'rb') as f:
        count = 0
        for line in f:
            count += 1
    return count

def UpLoadFile(filename,socket):
    with open(filename, 'rb') as f:
        for line in f:
            socket.send(line)

if __name__ == "__main__":
    ip = "127.0.0.1"
    port = 60000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))

    flag = False
    while flag == False:
        username = input("Enter your username: ")
        password = input("Enter your password: ")
        if CheckLogin(username, password, s):
            print("Login Successful")
            flag = True
            data = s.send("Login Successful".encode())
            break
        else:
            print("Login Failed. Retry")
            data = s.send("Login Failed. Retry".encode())
    flag = False
    while flag == False:
        filepath = input("Enter the filepath: ")
        # gửi filename
        filename = filepath[filepath.rfind("\\")+1:filepath.rfind(".")]
        s.send(filename.encode())
        # gửi file extension
        extension = filepath[filepath.rfind("."):]
        s.send(extension.encode())
        # gửi linecounter
        linecounter = CountLine(filepath)
        s.send(str(linecounter).encode())
        UpLoadFile(filepath, s)
        data = s.recv(1024)
        if data.decode() == "File saved":
            print("Upload Successful")
            flag = True
            break
        else:
            print("Upload Failed. Retry")
            flag = False

