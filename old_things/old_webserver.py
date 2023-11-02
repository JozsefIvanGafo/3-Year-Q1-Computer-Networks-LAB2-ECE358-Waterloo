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

    connectionSocket = serverSocket.accept()[0]
    sentence = connectionSocket.recv(2048).decode()

    # In case we receive an empty request we just ignore it -
    print("Sentence Received")
    if sentence == "":
        connectionSocket.close()
    list_sentence = sentence.split()
    type_request = list_sentence[0]
    file_name = list_sentence[1][1:]
    if type_request == "HEAD" or type_request == "GET":

        # Generate the current date and time
        date = "Date: " + datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT') + "\r\n"
        last_modification = "Last-Modified: " + datetime.datetime.fromtimestamp(
            os.path.getmtime(file_name)).strftime('%a, %d %b %Y %H:%M:%S GMT') + "\r\n"
        server = "Server: webserver\r\n"  # TODO: QUESTION ¿NAME?

        try:
            # We open the file name
            with open(file_name, "rb") as file:

                file_content = file.read()

                response = "HTTP/1.1 200 OK\r\n"
                response += "Connection: Keep-Alive\r\n"  # FIXME: miss time of keep alive
                response += date
                response += server
                response += last_modification
                response += "Content-Length: " + \
                    str(len(file_content)) + "\r\n"
                # FIXME: PODEMOS PONER TEXT/HTML PORQUE SABEMOS QUE EN ESTE CASO SIEMPRE VA A SER ESO?
                response += "Content-Type: text/html\r\n"
                response += "\r\n"

                if type_request == "GET":
                    final_response = response.encode() + file_content
                # type_request==Head
                else:
                    final_response = response.encode()

                print(final_response)  # TODO: ELIMINAR AL FIN

        except FileNotFoundError:
            # File not found send error code
            response = "404 Not Found\r\n"  # FIXME: QUESTION: ¿RIGHT FORMAT?
            response += date
            response += server
            final_response = response.encode()

        connectionSocket.send(final_response)
    connectionSocket.close()


# TODO: test other methods such as PUT
# TODO: check nested folders or directories
