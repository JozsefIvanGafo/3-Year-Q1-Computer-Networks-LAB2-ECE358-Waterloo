from socket import *
import random

#Define functions
import random

def old_generate_dns_header():
    id = random.randint(0, 2**16 - 1)
    #qr + opcode + aa + tc + rd = 00000100
    total = b'8'
    
    # qr = 0b0  # 0 is query, 1 is response
    # opcode = 0b0000  # Standard query
    # aa = 0b1  # Authoritative answer
    # tc = 0b0
    # rd = 0b0
    # ra + z + rcode = 00000000
    total2 = b'0'
    # ra = 0b0
    # z = 0b000
    # rcode = 0b0000  # No error condition
    # qdcount = 0b0000000000000001
    qdcount = b'\x01'
    ancount = 0b0000000000000001  # Message type
    nscount = 0b0000000000000000
    arcount = 0b0000000000000000
    # print("Tipo de 'id':", type(id), "Número de bits:", id.bit_length())
    # print("Tipo de 'qr':", type(qr), "Número de bits:", qr.bit_length())
    # print("Tipo de 'opcode':", type(opcode), "Número de bits:", opcode.bit_length())
    # print("Tipo de 'aa':", type(aa), "Número de bits:", aa.bit_length())
    # print("Tipo de 'tc':", type(tc), "Número de bits:", tc.bit_length())
    # print("Tipo de 'rd':", type(rd), "Número de bits:", rd.bit_length())
    # print("Tipo de 'ra':", type(ra), "Número de bits:", ra.bit_length())
    # print("Tipo de 'z':", type(z), "Número de bits:", z.bit_length())
    # print("Tipo de 'rcode':", type(rcode), "Número de bits:", rcode.bit_length())

    print("Tipo de 'total':", type(total))
    print(int.from_bytes(total, byteorder="big"))
    print("Tipo de 'total2':", type(total2))
    print(total2)

    print("Tipo de 'qdcount':", type(qdcount))
    print("Tipo de 'ancount':", type(ancount))
    print("Tipo de 'nscount':", type(nscount))
    print("Tipo de 'arcount':", type(arcount))

    header = id + total + total + qdcount + ancount + nscount + arcount

    

    return header
def generate_dns_header():
    id = random.randint(0, 2**16 - 1)
    qr = 0  # 0 is query, 1 is response
    opcode = 0  # Standard query
    aa = 0  # Authoritative answer
    tc = 0
    rd = 1  # Request recursion
    ra = 0
    z = 0
    rcode = 0  # No error condition
    qdcount = 1  # Number of questions
    ancount = 0  # Number of answers (to be filled by the server)
    nscount = 0
    arcount = 0
    header = (
        (id << 112) + (qr << 15) + (opcode << 11) + (aa << 10) +
        (tc << 9) + (rd << 8) + (ra << 7) + (z << 4) + rcode +
        (qdcount << 32) + (ancount << 48) + (nscount << 64) + (arcount << 80)
    )
    return header.to_bytes(16, byteorder='big')




def old_generate_dns_query(domain):
    
    qname=domain.encode()
    qtype=b'\x01'
    qclass= b'\x01'

    return qname+qtype+qclass


#Define main program of client
serverIP = "127.0.0.1"
serverPort = 12000
clientSocket = socket(AF_INET, SOCK_DGRAM)


while True:
    domain = input("Enter Domain Name: ")

    #End communication if we detected end message
    if domain=="end":
        break
    # Example usage:
    dns_header = old_generate_dns_header()
    print(type(dns_header))
    #Generate the request
    dns_query=old_generate_dns_query(domain)
    # print(dns_query)

    
    # dns_request = dns_header.encode() + dns_query.encode()
    dns_request = dns_header
    
    print(dns_request.hex())
    #Send request to DNS server
    clientSocket.sendto(dns_request,(serverIP,serverPort))
    break
    #clientSocket.sendto(message.encode(),(serverIP,serverPort))
    #Wait until we receive response
    modifiedMessage, serverAddress = clientSocket.recvfrom(2048)

    #Print responde of the server.py
    print (modifiedMessage.decode())



clientSocket.close()
print("Session ended")

