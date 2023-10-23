from socket import *
import os
serverIP = "127.0.0.1"
serverPort = 11000
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverIP, serverPort))


file_name = input("Introduce file:")

clientSocket.send(file_name.encode())
modifiedSentence = clientSocket.recv(2048)
print("From Server:", modifiedSentence.decode())
clientSocket.close()