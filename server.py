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
            dns_header=message

            # ! Extract data
            hex_message=message.hex()
            # ! We  extracted the data on a dictionary
            request=self.extract_data_of_request(hex_message)


            #We iterate all values of the hex and we print them with colours depending of the type of header
            print("Request:")
            self.print_hex(hex_message)

            #Obtain the domain
            #Convert it from hex to bytes to then convert it to string
            domain = self._decode_domain(bytes.fromhex(request["qname"]).decode())
            

            #Create structure of the dns answer
            #TODO: Refactor
            
            dns_answer=self.__generate_answer_section(domain)

            if dns_answer!=None:
                dns_response=dns_header+dns_answer
            print("Response:")
            self.print_hex(dns_response.hex())


            #Send answer
            self.__server_socket.sendto(dns_response,clientAddress)



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
        answer=b""
        list_ip=aux.get("IP")
        for ip in list_ip:
            name =self.int_to_bytes(192,1) + self.int_to_bytes(12,1) #c0 0c (hex)=204(dec)
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

            rdlength=self.int_to_bytes(4,2) # As ip always has 32 bits
            
            rdata=b""
            for i in ip.split("."):
                rdata+=self.int_to_bytes(int(i),1)
            answer += name+type_code+class_+ttl+rdlength+rdata
        return answer
    
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

        for i in range(0, len(hex_number), 32):  # Cada 16 números es 32 caracteres en formato hexadecimal
            group = hex_number[i:i + 32]  # Toma 32 caracteres
            formatted_group = ' '.join(group[i:i+2] for i in range(0, 32, 2))  # Divide en pares de 2 y une con espacios
            print(formatted_group)
        # print(' '.join(hex_number[i:i+2] for i in range(0, len(hex_number), 2)))


if __name__=="__main__":
    serverIP = "127.0.0.1"
    serverPort = 12000
    debug=False
    server=Server(serverIP,serverPort,debug)
    server.initialize()