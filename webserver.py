from socket import *
serverIP = "127.0.0.1"
serverPort = 11000
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind((serverIP, serverPort))
serverSocket.listen(1)
print("The server is ready to receive")
while (True):
    connectionSocket, addr = serverSocket.accept()
    sentence = connectionSocket.recv(2048).decode()
    print ("sentence received")
    capitalizedSentence = sentence.upper()
    connectionSocket.send(capitalizedSentence.encode())
    connectionSocket.close()