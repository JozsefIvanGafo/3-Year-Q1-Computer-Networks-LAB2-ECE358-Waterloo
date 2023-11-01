from socket import *

#Define functions
def generate_dns_response_header():
    name=""
    type_=""
    class_=""
    ttl=""
    rdlength=""
    rdata=""
    return
    

#Define main program
serverIP = "127.0.0.1"
serverPort = 12000
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind((serverIP, serverPort))
print ("The server is ready to receive")




while True:
    message, clientAddress = serverSocket.recvfrom(2048)




    dns_response=generate_dns_response_header
    print(dns_response)
    modifiedMessage = dns_response.decode().upper()
    serverSocket.sendto(modifiedMessage.encode(),clientAddress)
    


