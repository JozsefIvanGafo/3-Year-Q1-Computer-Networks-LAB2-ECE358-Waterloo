from socket import *
import datetime
import os
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
            print("THIS IS THE FILE NAME"+file_name)
            with open(file_name, "rb") as file:
                # FIXME: chat gpt
                file_content = file.read()
                # Generate the current date and time
                date = datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')
                last_modification = datetime.datetime.fromtimestamp(os.path.getmtime(file_name)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                # file_type = os.get_file_type(file_name)

                response = "HTTP/1.1 200 OK\r\n"
                response += "Connection: Keep-Alive\r\n"# FIXME: NO ESTOY SEGURA
                response += "Date: " + date +"\r\n"
                response += "Last-Modified: " + last_modification + "\r\n"
                response += "Server: \r\n" #FIXME: NOSE CUAL SERÍA EL SERVER
                response += "Content-Length: " + str(len(file_content)) + "\r\n"
                response += "Content-Type: text/html\r\n" #FIXME: PODEMOS PONER TEXT/HTML PORQUE SABEMOS QUE EN ESTE CASO SIEMPRE VA A SER ESO?
                response += "\r\n"
                final_response = response.encode() + file_content

        except FileNotFoundError:
            final_response = "HTTP/1.1 404 Not Found\r\n\r\nFile not found."
        connectionSocket.send(final_response)

    # elif type_request=="HEAD":
        
    connectionSocket.close()