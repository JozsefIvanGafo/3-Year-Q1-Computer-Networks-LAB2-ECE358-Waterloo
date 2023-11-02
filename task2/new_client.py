#imports
from socket import *
import random

#Create class

class Client:
    def __init__(self,server_ip:str,server_port:int) -> None:
        self.__server_ip=server_ip
        self.__server_port=server_port
        self.__socket=socket(AF_INET, SOCK_DGRAM)

    def initialize(self):
        while True:
            domain=input("Enter domain: ")

            #We finish connection if domain is end
            if domain=="end":
                break


            dns_header=self.__dns_header()
            dns_query=self.__dns_query()
            dns_request=dns_header+dns_header
    


    def __dns_header(self):
        return
    def __dns_query(self,domain):
        return