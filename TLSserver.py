import socket
import pyodbc
import datetime

ip = "127.0.0.1"
port = 60000
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((ip, port))
s.listen(1)


def CheckUser(username, password):
    conn = pyodbc.connect('Driver={SQL Server};'
                          'Server=CEIYSEKIRALOASB\CEIYSBENNOVA;'
                          'Database=test;'
                          'Trusted_Connection=yes;')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM [User] WHERE name = ? AND pass = ?", username, password)
    row = cursor.fetchone()
    if row is None:
        return False
    else:
        return True
def SaveFile(filename, socket, linecounter):
    with open(filename, 'wb') as f:
        for i in range(linecounter):
            data = socket.recv(1024)
            f.write(data)

if __name__ == "__main__":

    print("Server is running...")
    print("Waiting for connection...")
    while True:
        conn, addr = s.accept()
        flag = False
        while flag == False:
            username = conn.recv(1024)
            password = conn.recv(1024)
            if CheckUser(username.decode(), password.decode()):
                conn.send("True".encode())
            else :
                conn.send("False".encode())
            data = conn.recv(1024)
            if data.decode() == "Login Successful":
                flag = True
                print("Connection from: ", addr, "Username: ",username.decode())
        flag = False
        while flag == False:
            # nhận filename
            filename = conn.recv(1024).decode()
            # nhận file extension
            extension = conn.recv(1024).decode()
            namefiletosave = "File\\" + username.decode()  + filename +datetime.datetime.now().strftime("%d-%m-%y")+ extension
            # nhận linecounter
            linecounter = int(conn.recv(1024).decode())
            print(linecounter)
            SaveFile(namefiletosave, conn, linecounter)
            conn.send("File saved".encode())
            print("File saved")
            flag = True


