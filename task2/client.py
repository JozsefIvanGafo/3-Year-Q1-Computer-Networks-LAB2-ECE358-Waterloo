from socket import *

#Define functions
def generate_dns_header(message):
    qname=""
    qtype=""
    qclass=""

    return ""





#Define main program of client
serverIP = "127.0.0.1"
serverPort = 12000
clientSocket = socket(AF_INET, SOCK_DGRAM)


while True:
    message = input("Enter Domain Name: ")

    #End communication if we detected end message
    if message=="end":
        break
    
    #Generate the request
    dns_request=generate_dns_header(message)
    print(dns_request)

    #Send request to DNS server
    clientSocket.sendto(message.encode(),(serverIP,serverPort))
    #Wait until we receive response
    modifiedMessage, serverAddress = clientSocket.recvfrom(2048)

    #Print responde of the server.py
    print (modifiedMessage.decode())



clientSocket.close()
print("Session ended")

