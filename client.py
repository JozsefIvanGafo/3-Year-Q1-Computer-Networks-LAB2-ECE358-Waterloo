#imports
import random
from socket import *

#Create class
class Client:
    def __init__(self,server_ip:str,server_port:int) -> None:
        self.__server_ip=server_ip
        self.__server_port=server_port
        self.__client_socket=socket(AF_INET, SOCK_DGRAM)
        self.__debug=True

    def initialize(self):
        """
        We initialize the request to the dns server
        """
        while True:
            print("Input from the user:")
            domain=input("Enter Domain Name: ")
            domain=domain.lower()

            #We finish connection if domain is end
            if domain=="end":
                print("Session Ended")
                break

            #We create the structure of the dns request
            dns_header=self.__dns_header()
            dns_query=self.__dns_query(domain)
            dns_request=dns_header+dns_query

            #If we want to know what we are sending
            #TODO: DELETE AT THE END
            if self.__debug:
                message_hex=dns_request.hex()
                self.print_hex(message_hex)

            #Send request to the server
            self.__client_socket.sendto(dns_request,(self.__server_ip,self.__server_port))
            response, addr = self.__client_socket.recvfrom(2048)
            #TODO: HANDLE ERROR, NO EXISTE EL DOMINIO MIRA PIAZZA: https://piazza.com/class/llomgydu5c3tm/post/248
            print("Output:")
            # self.print_hex(response.hex())
            self.print_response(response)

    
    #Functions to create the request headers + data
    def __dns_header(self)->bytes:
        """
        This method is in charge of generating the header of the dns
        """
        #We generate the ID
        random_id=random.randint(0,(2**16)-1)
        dns_id=self.int_to_bytes(random_id,2)

        #We generate the flag header
        flags = self.generate_flags()

        #We generate the other headers
        qdcount=self.int_to_bytes(1,2)#number of entries in question section

        #Based on message type
        ancount=self.int_to_bytes(0,2)#number of resource records in answer section

        nscount=self.int_to_bytes(0,2)#number of name server resource records in authorative records
        arcount=self.int_to_bytes(0,2)#number of resource records additional record section

        return dns_id+flags+qdcount+ancount+nscount+arcount

    def __dns_query(self,domain:str)->bytes:
        """
        This method is in charge of generating the dns query
        """
        #Revise qname to bytes
        labels = domain.split(".")
        qname = b"" # Initialize
        for label in labels:
            qname += self.int_to_bytes(len(label),1)
            qname += label.encode()
        qname += self.int_to_bytes(0,1) # End of domain

        qtype=self.int_to_bytes(1,2)
        qclass=self.int_to_bytes(1,2)

        return qname+qtype+qclass
    
    def generate_flags(self):
        """
        We generate the flag header
        """
        qr = "0"  # 0 is query, 1 is response
        opcode = "0000"  # Standard query
        aa = "1"    # Authoritative answer
        tc = "0"    #Message truncated
        rd = "0"    #recursion desired
        ra = "0"    #recursion avaible
        z = "000"   #for future use
        rcode ="0000"  #Response code

        flags=qr+opcode+aa+tc+rd+ra+z+rcode

        #We convert it to bytes and we return it
        return self.bits_to_bytes(flags)

    def print_response(self,response:bytes)->None:
        """
        Method to print the response from the server
        @response: The response we want to print
        """
        # Domain name
        x = response[12]
        domain = response[13:13+x].decode()
        x2 = response[13+x]
        domain += "." + response[14+x:14+x+x2].decode() + ": "
        i = 14+x+x2
        
        while response[i:i+1] != b'\xc0':
            i += 1

        final_part = response[i:]
        line = ""
        for x in range(0, len(final_part), 16):
            line += domain
            line += "type "
            aux = 2

            if(int.from_bytes(final_part[x+aux:x+aux+2], byteorder="big") == 1):
                line += "A, "
            #TODO: ERROR que hacemos?
            line += "class "
            aux +=2
            if(int.from_bytes(final_part[x+aux:x+aux+2], byteorder="big")):
                line += "IN, "
            aux +=2

            line += "TTL "
            line += str(int.from_bytes(final_part[x+aux:x+aux+4],byteorder="big"))
            aux +=4


            line += ", addr ("
            line += str(int.from_bytes(final_part[x+aux:x+aux+2],byteorder="big"))
            line += ")"
            aux+=2

            for i in range(4):
                line += str(final_part[x+aux])
                if i != 3:
                    line += "."
                aux +=1
            line += "\n"
        print(line)

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

#TODO: Delete this method
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




if __name__=="__main__":
    serverIP="127.0.0.1"
    serverPort=12000
    client=Client(serverIP,serverPort)
    client.initialize()