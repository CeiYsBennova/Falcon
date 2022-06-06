import falcon
import datetime
def savefile(inputfile, outputfile):
    with open(inputfile, 'rb') as f:
        with open(outputfile, 'wb') as f2:
            for line in f:
                f2.write(line)
def CountLine(filename):
    with open(filename, 'rb') as f:
        count = 0
        for line in f:
            count += 1
    return count

input1 = "testcert.txt"
input2 = "File\hacker-icon.png"
print(CountLine(input1))
print(CountLine(input2))

f2 = open(input2, 'rb')
with open("File\out2.png","wb") as f:
    for i in range(CountLine(input2)):
        f.write(f2.readline())
