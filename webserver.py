"""
University of Waterloo Fall 2023 ECE-358 LAB-2  Group 151
József IVÁN GAFO (21111635) jivangaf@uwaterloo.ca
Sonia NAVAS RUTETE (21111397) srutete@uwaterloo.ca
V 1:0
Description: In this module we will write the code for the webserver for the task 1 of lab 2
"""
#We define the imports
import datetime
import os
from socket import *


class WebServer:
    """
    This class is in charge of running a web server for the lab 2 task 1
    """

    def __init__(self,serverIP:str,serverPort:int) -> None:
        self._server_ip=serverIP
        self._server_port=serverPort
        self._server_socket=socket(AF_INET, SOCK_STREAM)
        self._server_socket.bind((self._server_ip,self._server_port))
        self._server_socket.listen(1)
        print("The server is ready to receive")

        #Here we have the content when we don't find the requested file
        self._error_file_path=os.getcwd()+"/404_not_found.html"
        try:
            with open(self._error_file_path, "rb") as file:
                    self._error_file_content = file.read()
        except FileNotFoundError as error:
            print(f"[ERROR] An exception occurred: {error}")


    def initialization(self):
        """
        This method is in charge of initializing the web server
        """
        while True:

            #We wait until we receive a request
            connectionSocket,client_address=self._server_socket.accept()
            sentence=connectionSocket.recv(2048).decode()
            print("sentence received")

            #We split the content to obtain the type of request and file path
            try:
                list_sentence = sentence.split()
                type_request = list_sentence[0]
                file_path =os.getcwd()+list_sentence[1]

                #If the type of request is not head or get we close the connection
                if type_request != "HEAD" and type_request !="GET":
                    raise ValueError("The type of request allowed is HEAD or GET")

            #In case of error we close the connection with client
            except Exception as error:
                print(f"[ERROR] An exception occurred: {error}")
                connectionSocket.close()
                continue
            
            #we open the path if error we return the error http response
            try:
                # We open the file name
                with open(file_path, "rb") as file:
                    file_content = file.read()
                    #We create the headers+data for the http response
                    response=self.__http_response(type_request,file_path,file_content,"200 OK")

            #If we didn't find the file we send http error response
            except FileNotFoundError:
                print("[ERROR] File not found")
                #response=self.__http_error_response()
                response=self.__http_response(type_request,self._error_file_path,self._error_file_content,"404 Not Found")

            #If we encounter another type of error
            except Exception as error:
                print(f"[ERROR] An exception occurred: {error}")
                connectionSocket.close()
                continue

            print("sending response")
            print(response)
            #We send the response
            connectionSocket.send(response.encode())
            #We close connection with client
            connectionSocket.close()


    
    #Methods to generate the response of the web server
    def __http_response(self,type_request:str,file_path:str,file_content:bytes,status_code:str)->str:
        """
        Description: This method is in charge of returning the response of the http request
        @type_request: The type of request the user is requesting (HEAD or GET)
        @file_path: The file path the client is requesting
        @file_content: The content of the file the user is requesting
        @status_code: is a string containing the status code of the response
        @return: It returns the response with all the headers and possible data
        """
        status="HTTP/1.1 "+status_code+"\r\n"
        connection=self.__get_connection_header()
        date=self.__get_date_header()
        server=self.__get_server_header()
        last_mod=self.__get_last_mod_date_header(file_path)
        content_length=self.__get_content_length_header(file_content)
        content_type=self.__get_content_type_header()

        #We create the structure of the response
        response=status+date+server+last_mod+content_length+content_type+connection

        #IF is type HEAD then we only return the headers
        if type_request=="HEAD":
            return response+"\r\n"
        #If is type get we return all headers + file content
        return response+"\r\n"+file_content.decode()
        

    #Static methods for obtaining headers
    @staticmethod
    def __get_date_header():
        """
        Description: Returns the actual date header
        """
        return "Date: " + datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT') + "\r\n"
    
    @staticmethod
    def __get_last_mod_date_header(file_path:str)->str:
        """
        Description: Return the header of the last time a file was modified
        @file_path:the file path of the file requested by client
        """
        return "Last-Modified: " + datetime.datetime.fromtimestamp(
                os.path.getmtime(file_path)).strftime('%a, %d %b %Y %H:%M:%S GMT') + "\r\n"
    
    @staticmethod
    def __get_content_length_header(file_content:bytes)->str:
        """
        Description: Returns the header of the content length
        @file_content: The content of the file requested by the client
        """
        return "Content-Length: " + str(len(file_content)) + "\r\n"
    
    @staticmethod
    def __get_server_header()->str:
        """
        Description: returns the web server software being used header
        """
        return "Server: Webserver\r\n"
    
    @staticmethod
    def __get_connection_header()->str:
        """
        Description: returns the connection header
        """
        return "Connection: Keep-Alive\r\n"
    
    @staticmethod
    def __get_content_type_header()->str:
        """
        Description: Returns the content type header of the file requested by client
        """
        return "Content-Type: text/html\r\n"



if __name__=="__main__":
    serverIP = "127.0.0.1"
    serverPort = 11000
    web_server=WebServer(serverIP,serverPort)
    web_server.initialization()
