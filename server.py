#import
import random
import json
from socket import *

#Create class Server
class Server:

    def __init__(self,serverIP:str,serverPort:int,debug:bool=True) -> None:
        self.__server_ip=serverIP
        self.__server_port=serverPort
        self.__debug=debug
        #We load the domain records
        self.__domain_records={
            "google.com": {
                "Type": "A",
                "Class": "IN",
                "TTL": 260,
                "IP": ["192.165.1.1", "192.165.1.10"]
            },
            "youtube.com": {
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

        #We create the socket
        self.__server_socket=socket(AF_INET, SOCK_DGRAM)
        self.__server_socket.bind((self.__server_ip,self.__server_port))

        print("The server is ready to receive")
        

    #We initialize the server
    def initialize(self):
        while True:
            #Wait until we receive a request
            message, clientAddress = self.__server_socket.recvfrom(2048)

            # ! Extract data
            hex_message=message.hex()
            # ! We  extracted the data on a dictionary
            request=self.extract_data_of_request(hex_message)


            #We iterate all values of the hex and we print them with colours depending of the type of header
            print("Request:")
            self.print_hex(hex_message)
            print("")

            #Obtain the domain
            #Convert it from hex to bytes to then convert it to string

            domain=bytes.fromhex(request["qname"]).decode()
            transaction_id=bytes.fromhex(request["id_req"])
            #print(domain)

            #Create structure of the dns answer
            #TODO: Refactor
            domain = self._decode_domain(domain)
            dns_answer=self.__generate_answer_section(domain)
            if dns_answer!=None:
                dns_header=self.__dns_header(transaction_id,1)#already in bytes
                dns_response=dns_header+dns_answer
            else:
                dns_response=self.__dns_header(transaction_id,0)
            # print(dns_response)

            #TODO: print in hexadecimal with colours for the dns_response
            self.print_hex(dns_response.hex())

            #67 6f 6f 67 6c 65 2e 63 6f 6d
            #67 6f 6f 67 6c 65 03 63 6f 6d


            #Send answer
            # print(dns_response)
            # modifiedMessage = dns_response.decode().upper()
            self.__server_socket.sendto(dns_response,clientAddress)
            #self.__server_socket.close()



    def _decode_domain(self,domain:str)->str:
        """
        Method in charge of decoding the domain
        @domain: The domain we want to decode
        @return: The decoded domain
        """
        real_domain = ""
        domain_bytes = domain.encode()

        length_1 = domain_bytes[0]
        for i in range(1, length_1 + 1):
            real_domain += chr(domain_bytes[i])
        real_domain += "."

        i = length_1 + 1
        length_2 = domain_bytes[i]
        for j in range(1, length_2 + 1):
            real_domain += chr(domain_bytes[i + j])

        return real_domain
            

        
        

    #Methods to generate headers
    def __generate_answer_section(self,domain)->bytes:
        """
        Method is in charge of creating the answer header
        @return: Returns bytes if there is a domain found else it returns None
        """
        aux = self.find_domain(domain)
        if aux==None:
            return
        
        #TODO: Refactor
        name =self.int_to_bytes(204,4) #c0 0c (hex)=204 (dec)#aux.get("Type")


        type_= aux.get("Type")
        type_code=b""
        if type_=="A":
            type_code=self.int_to_bytes(1,2)#1=type A
        else:
            raise ValueError("[ERROR] we only accept type A for this lab")
        class_= aux.get("Class")
        if class_=="IN":
            class_=self.int_to_bytes(1,2)#1=class IN(internet)


        ttl= self.int_to_bytes(aux.get("TTL"),4)#Time to live


        list_ip=aux.get("IP")
        rdata=b""
        for ip in list_ip:
            rdata+=ip.encode()
        
        #TODO: the length must be in bytes
        rdlength=self.int_to_bytes(len(rdata),2)


        if self.__debug:
            print(type(name))
            print(type(type_code))
            print(type(class_))
            print(type(ttl))
            print(type(rdata))
            print(type(rdlength))

        return name+type_code+class_+ttl+rdlength+rdata
    

    def find_domain(self,domain)->dict:
        """
        This method is in charge of finding the domain and 
        returning the dictionary with the different values for that domain
        @domain: a string containing the domain we want to search
        @return: Returns a dictionary if it found the domain else it returns None
        """
        try:
            return self.__domain_records[domain]
        except Exception as error:
            print(f"[ERROR]: domain not found {error}")
            return 
    
    def __dns_header(self,transaction_id:bytes,found:bool)->bytes:
        """
        This method is in charge of generating the header of the dns
        @transaction_id: is the id of the request
        @found:it tells us if we found dns answer
        """
        #We generate the ID
        dns_id=transaction_id

        #We generate the flag header
        flags = self.generate_flags(found)

        #We generate the other headers
        qdcount=self.int_to_bytes(1,2)#number of entries in question section

        #Based on message type
        ancount=self.int_to_bytes(0,2)#number of resource records in answer section

        nscount=self.int_to_bytes(0,2)#number of name server resource records in authorative records
        arcount=self.int_to_bytes(0,2)#number of resource records additional record section

        return dns_id+flags+qdcount+ancount+nscount+arcount
 
    def generate_flags(self,found:bool)->bytes:
        """
        We generate the flag header
        """
        qr = "1"  # 0 is query, 1 is response
        opcode = "0000"  # Standard query
        aa = "1"    # Authoritative answer
        tc = "0"    #Message truncated
        rd = "0"    #recursion desired
        ra = "0"    #recursion avaible
        z = "000"   #for future use
        #If we found an ip address then is 0 (no error)
        if found:
            rcode ="0000"  #Response code
        #The name reference in the query does not exist( code 3)
        else:
            rcode="0011"

        flags=qr+opcode+aa+tc+rd+ra+z+rcode

        #We convert it to bytes and we return it
        return self.bits_to_bytes(flags)
    
    #Method to extract data of a request
    def extract_data_of_request(self,hex_data:hex)->dict:
        """
        This method is in charge of extracting all the 
        components of the request made by the client
        @hex_data: the request in hexadecimals numbers
        @return: a dictionary containing all components of the request
        """

        dictionary={
            "id_req":hex_data[:4],
            "flags_req":hex_data[4:8],
            "qdcount":hex_data[8:12],
            "ancount":hex_data[12:16],
            "nscount":hex_data[16:20],
            "arcount":hex_data[20:24],
            "qname":hex_data[24:-8],#We know it will always be -8
            "qtype":hex_data[-8:-4],
            "qclass":hex_data[-4:]
        }
        return dictionary


    #static methods
    @staticmethod
    def int_to_bytes(number:int,byte_size:int)->bytes:
        """
        Method to convert an integer to bytes
        @number: The number we want to convert into bytes
        @byte_size: How many bytes do we want to generate
        @return bytes: we return the conversion of number into bytes
        """
        #Byteorder big= most significant byte comes first
        return number.to_bytes(byte_size,byteorder="big")
    
    @staticmethod
    def bits_to_bytes(bits:str)->bytes:
        """
        Method in charge of translating bits into bytes
        @bits: A string containing bits
        @return bytes: We return the conversion of bits to bytes
        """
        if len(bits)%8!=0:
            raise ValueError("[Error] The bit length must be multiple of 8")
        
        #We divide the bits by chunks of 8
        byte_chunks=[bits[i:i+8] for i in range(0, len(bits), 8)]

        result_in_bytes = bytes([int(chunk, 2) for chunk in byte_chunks])
        return result_in_bytes

    @staticmethod
    def print_hex(hex_number:hex)->None:
        """
        Method in charge of printing hex numbers
        @hex_data: The data we want to print
        """
        print(' '.join(hex_number[i:i+2] for i in range(0, len(hex_number), 2)))


if __name__=="__main__":
    serverIP = "127.0.0.1"
    serverPort = 12000
    debug=False
    server=Server(serverIP,serverPort,debug)
    server.initialize()