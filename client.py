from socket import *
import os
serverIP = "127.0.0.1"
serverPort = 11000
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((serverIP, serverPort))

type_request = input("Introduce file:")
if type_request == "h":
    http_request_type="HEAD /prueba/HelloWorld.html\r\n"
elif type_request == "g":
    http_request_type="GET /prueba/HelloWorld.html\r\n"
else:
    http_request_type="PUT /prueba/HelloWorld.html\r\n"
    

clientSocket.send(http_request_type.encode())
modifiedSentence = clientSocket.recv(2048)
print("From Server:", modifiedSentence.decode())
clientSocket.close()