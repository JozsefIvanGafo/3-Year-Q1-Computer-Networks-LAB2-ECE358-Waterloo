#import
import random
import json
from socket import *

#Create class Server
class Server:

    def __init__(self,serverIP:str,serverPort:int) -> None:
        self.__server_ip=serverIP
        self.__server_port=serverPort
        self.__debug=False
        #We load the domain records
        with open("domain_records.json","r") as json_file:
            self.__domain_records=json.load(json_file)

        #We create the socket
        self.__server_socket=socket(AF_INET, SOCK_DGRAM)
        self.__server_socket.bind((self.__server_ip,self.__server_port))


        #Coulours
        self.__colours= [
                        "\033[31m",  # Red
                        "\033[32m",  # Green
                        "\033[33m",  # Yellow
                        "\033[34m",  # Blue
                        "\033[35m",  # Magenta
                        "\033[36m",  # Cyan
                        "\033[91m",  # Light Red
                        "\033[92m",  # Light Green
                        "\033[93m",  # Light Yellow
                        "\033[94m",  # Light Blue
                        "\033[95m",  # Light Magenta
                        "\033[96m",  # Light Cyan
                        "\033[97m",  # Light Gray
                        "\033[90m",  # Dark Gray
                        "\033[37m",  # Default
                        ]
        self.__reset = "\033[0m"  # Reset text color to default

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


            #TODO: print in hexadecimal with colours for the message
            #We iterate all values of the hex
            self.__print_dict(request)


            #Convert the message to hexadecimal
            # # hex_message=message.hex()
            # message_hex=message.hex()
            # #print(message_hex)
            # groups = [message_hex[i:i+2] for i in range(0, len(message_hex), 2)]

            # for pair in groups:
            #     print(pair, end=" ")
            

            #TODO: generate header for answering the question
            #Obtain the domain
            #Convert it from hex to bytes to then convert it to string
            domain=bytes.fromhex(request["qname"]).decode()
            #print(domain)

            #Create structure of the dns answer
            dns_header=self.__dns_header()
            dns_answer=self.__generate_answer_header(domain)
            dns_response=dns_header+dns_answer
            
            print(dns_response)

            #TODO: print in hexadecimal with colours for the dns_response
            

            #67 6f 6f 67 6c 65 2e 63 6f 6d
            #67 6f 6f 67 6c 65 03 63 6f 6d


            #Send answer
            # print(dns_response)
            # modifiedMessage = dns_response.decode().upper()
            #serverSocket.sendto(modifiedMessage.encode(),clientAddress)
            self.__server_socket.close()

    



    #Methods to generate headers
    def __generate_answer_header(self,domain)->bytes|None:
        """
        Method is in charge of creating the answer header
        @return: Returns bytes if there is a domain found else it returns None
        """
        aux = self.find_domain(domain)
        if aux==None:
            return
        
        #TODO: convert it into bytes
        name = aux.get("Type")
        type_= aux.get("Type")
        class_= aux.get("Class")
        ttl= aux.get("TTL")
        rdata=aux.get("IP")
        rdlength=str(len(rdata))
        return name+type_+class_+ttl+rdlength+rdata
    
    def find_domain(self,domain)->dict|None:
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
    
    def __dns_header(self)->bytes:
        """
        This method is in charge of generating the header of the dns
        """
        #We generate the ID
        random_id=random.randint(0,2**16-1)
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
        qname=bytes(domain,"utf-8")
        qtype=self.int_to_bytes(1,2)
        qclass=self.int_to_bytes(1,2)

        return qname+qtype+qclass
 
    def generate_flags(self)->bytes:
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
        rcode ="0000"  #Response code

        flags=qr+opcode+aa+tc+rd+ra+z+rcode

        #We convert it to bytes and we return it
        return self.bits_to_bytes(flags)
    
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

    #coloured prints for a list
    def __print_dict(self, request:dict)->None:
        for i, (_,value) in enumerate(request.items()):
                #We group hexadecimals by 2 
            for j,hex_value in enumerate(value):
                    #Space between them every 2 hex numbers
                if j%2==0:
                    print(" ",end="")
                    #We add the colours formula = colour+ text + reset_colour
                print(self.__colours[i]+hex_value+self.__reset,end="")


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






if __name__=="__main__":
    serverIP = "127.0.0.1"
    serverPort = 12000
    server=Server(serverIP,serverPort)
    server.initialize()