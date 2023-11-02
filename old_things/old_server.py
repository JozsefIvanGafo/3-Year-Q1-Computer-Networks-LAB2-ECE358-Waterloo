from socket import *

DOMAIN_RECORDS = dns_records = {
    "google.com": {
        "Type": "A",
        "Class": "IN",
        "TTL": 260,
        "IP": ["192.165.1.1", "192.165.1.10"]
    },
    "youtube.com":{
        "Type": "A",
        "Class": "IN",
        "TTL": 160,
        "IP": ["192.165.1.2"]
    },
    "uwaterloo.ca": {
        "Type": "A",
        "Class": "IN",
        "TTL": 160,
        "IP": ["192.165.1.3"]
    },
    "wikipedia.org": {
        "Type": "A",
        "Class": "IN",
        "TTL": 160,
        "IP": ["192.165.1.4"]
    },
    "amazon.ca": {
        "Type": "A",
        "Class": "IN",
        "TTL": 160,
        "IP": ["192.165.1.5"]
    }
}


#Define functions
def generate_dns_response_header(domain):
    aux = find_domain(domain)
    
    if aux=="":
        return
    
    name = aux.get("Type").hex()
    type_= aux.get("Type").hex()
    class_= aux.get("Class").hex()
    ttl= aux.get("TTL").hex()
    rdata=aux.get("IP").hex()
    rdlength=str(len(rdata)).hex()
    return name+type_+class_+ttl+rdlength+rdata
    
def find_domain(domain):
    try:
        return DOMAIN_RECORDS[domain]
    except Exception as error:
        print(f"[ERROR]: domain not found {error}")
        return ""
    

#Define main program
serverIP = "127.0.0.1"
serverPort = 12000
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind((serverIP, serverPort))
print ("The server is ready to receive")




while True:
    message, clientAddress = serverSocket.recvfrom(2048)
    # hex_message=message.hex()
    message_hex=message.hex()
    #print(message_hex)
    groups = [message_hex[i:i+2] for i in range(0, len(message_hex), 2)]

    for pair in groups:
        print(pair, end=" ")




    dns_response=generate_dns_response_header
    # print(dns_response)
    # modifiedMessage = dns_response.decode().upper()
    #serverSocket.sendto(modifiedMessage.encode(),clientAddress)
    serverSocket.close()
    


