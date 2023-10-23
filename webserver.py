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
    list_sentence=sentence.split()
    # print(list_sentence)
    print(sentence)
    type_request=list_sentence[0]
    file_name=list_sentence[1][1:]

    
    if type_request=="GET":
        try:
            print(file_name)
            with open(file_name, "rb") as file:
                # FIXME: chat gpt
                file_content = file.read()
                response = "HTTP/1.1 200 OK\r\n"
                response += "Content-Length: " + str(len(file_content)) + "\r\n"
                response += "\r\n"
                response = response.encode() + file_content
        except FileNotFoundError:
            response = "HTTP/1.1 404 Not Found\r\n\r\nFile not found."
        connectionSocket.send(response)


    
    # capitalizedSentence = file_content.upper()

    # connectionSocket.send(capitalizedSentence.encode())
    connectionSocket.close()