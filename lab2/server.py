"""
University of Waterloo Fall 2023 ECE-358 LAB-2  Group 151
József IVÁN GAFO (21111635) jivangaf@uwaterloo.ca
Sonia NAVAS RUTETE (21111397) srutete@uwaterloo.ca
V 1:0
Description: In this module we will write the code for the server for the task 2 of lab 2
"""
#import
from socket import *

#Create class Server
class Server:
    #Setup
    def __init__(self,serverIP:str,serverPort:int,debug:bool=True) -> None:
        #Set properties for the server
        self.__server_ip=serverIP
        self.__server_port=serverPort

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
            

            # We extract the data and we convert it into message
            hex_message=message.hex()
            # We extract the data into a dictionary (it makes it easier to id and extract data)
            #request=self.extract_data_of_request(hex_message)
            request_dict=self.__extract_data(hex_message)


            print("Request:")
            #We print the request of the client
            self.__print_hex(hex_message)


            #We extract the relevant info from the request
            domain =request_dict["question"][0]["qname"]
            transaction_id=self.__hex_to_bytes(request_dict["id_req"])

            
            #We load the question section format (that is the query of the client)
            question_dict= request_dict["question"]
            dns_question=self.__generate_dns_question(question_dict)

            #Create structure of the dns answer
            dns_answer = self.__generate_answer_section(domain)
            
            
            #If is b""" it means we din't found the answer of the question asked to the client
            if dns_answer!=b"":
                #The number of ipv4 under a domain
                number_of_ipv4=len(self.__domain_records[domain]["IP"])
                dns_header=self.__generate_dns_header(transaction_id,found=True, ancount=number_of_ipv4)#already in bytes

            else:
                #In case of dns not found ancount is 0, and the rcode is "0011", meaning the query doesn't exist
                dns_header=self.__generate_dns_header(transaction_id,found=False,ancount=0)

            #We obtain the response in bytes to the client
            dns_response=dns_header+dns_question+dns_answer

            print("Response:")
            #We print the response
            self.__print_hex(dns_response.hex())


            #Send the answer to client
            self.__server_socket.sendto(dns_response,clientAddress)

    #Methods to generate headers
    def __generate_dns_header(self,transaction_id:bytes,found:bool, ancount: int)->bytes:
        """
        This method is in charge of generating the header of the dns
        @transaction_id: is the id of the request
        @found:it tells us if we found dns answer
        """
        #We generate the ID
        dns_id=transaction_id
            #We generate the flag header
        flags = self.__generate_flags(found)

        #We generate the other headers
        qdcount=self.__int_to_bytes(1,2)#number of entries in question section
        #Based on message type
        ancount=self.__int_to_bytes(ancount,2)#number of resource records in answer section

        nscount=self.__int_to_bytes(0,2)#number of name server resource records in authorative records
        
        arcount=self.__int_to_bytes(0,2)#number of resource records additional record section

        return dns_id+flags+qdcount+ancount+nscount+arcount

    def __generate_flags(self,found:bool)->bytes:
        """
        We generate the flag header
        """
        qr = "1"  # 0 is query, 1 is response
        opcode = "0000"  # Standard query
        aa = "1"    # Authoritative answer
        tc = "0"    #Message truncated
        rd = "0"    #recursion desired
        ra = "0"    #recursion available
        z = "000"   #for future use
        #If we found an ip address then is 0 (no error)
        if found:
            rcode ="0000"  #Response code
        #The name reference in the query does not exist( code 3)
        else:
            rcode="0011"

        flags=qr+opcode+aa+tc+rd+ra+z+rcode

        #We convert it to bytes and we return it
        return self.__bits_to_bytes(flags)
    
    def __generate_answer_section(self,domain)->bytes:
        """
        Method is in charge of creating the answer header
        @return: Returns bytes if there is a domain found else it returns None
        """

        #We first search if the domain asked exist in our database
        domain_record_dict = self.__find_domain_from_database(domain)

        #If is none it means we didn't find the question domain
        if domain_record_dict==None:
            return b""
        
        #We prepare the answer
        answer=b""
        #We get the list of ip
        ipv4_list=domain_record_dict.get("IP")


        #Now we will iterate the different ipv4 that are on domain_record_dict
        for ipv4 in ipv4_list:

            #name of the node (for this lab we have a fixed name of node=c0 0c)
            name =self.__int_to_bytes(192,1) + self.__int_to_bytes(12,1) #c0 0c (hex)=204(dec)

            #We obtain the conversion from 
            type_code = self.__str_type_code_to_bytes(domain_record_dict.get("Type"))

            #We obtain the class of the ipv4
            class_ = self.__str_class_to_bytes(domain_record_dict.get("Class"))

            #We obtain the ttl of the ipv4
            ttl= self.__int_to_bytes(domain_record_dict.get("TTL"),4)#Time to live

            #We obtain the rdlength (we allways now is 4, since is ipv4)
            rdlength=self.__int_to_bytes(4,2)
            
            #We obtain the ipv4
            rdata = self.__str_ipv4_to_bytes(ipv4)

            #we obtain the ith answer 
            answer += name+type_code+class_+ttl+rdlength+rdata

        return answer

    def __generate_dns_question(self, question_dict:list)->bytes:
        """
        Obtain the question section format into bytes
        @question_dict: Here we have a list of dictionaries containing the questiosn of the client
        @return: It returns the translation of the question into bytes
        """
        
        prev_question_query=b""
        for question in question_dict:
            
            #we obtain qname
            qname=self.__domain_to_bytes(question["qname"])

            #In this lab we know it has fixed values
            qtype=self.__int_to_bytes(1,2)
            qclass=self.__int_to_bytes(1,2)

            #We create a question query
            prev_question_query+=qname+qtype+qclass

        return prev_question_query

    
    #Method to extract data of a request or to find information
    def __extract_data(self,hex_data:hex)->dict:
        """
        Method of extracting the data from the server
        @hex_data: All the data of the response in hex
        @return dict: It return a dictionary with all the fields
        """
        #General data of the response
        data={
            "id_req":hex_data[:4],
            "flags_req":hex_data[4:8],
            "qdcount":hex_data[8:12],
            "ancount":hex_data[12:16],
            "nscount":hex_data[16:20],
            "arcount":hex_data[20:24],
            "question":[],
            "answers":[]
        }
        i=24
        #We extract the query data
        qdcount=int(data["qdcount"],16)
        for _ in range(qdcount):
            domain,qtype,qclass,i=self.__extract_query(hex_data,i)
            data["question"].append({
                "qname":domain,
                "qtype":qtype,
                "qclass":qclass
            })
        
        return data

    def __extract_query(self, hex_data: hex, i: int) -> [str, hex, hex, int]:
        """
        This method is in charge of finding the fields of the query
        @hex_data: the response in hex
        @i: integer that represents the position in hex_data
        @return: returns the domain, qtype, qclass, and the position in hex_data
        """

        #obtain the first part of the domain length (*2 because they are hex not bytes)
        length_first_part=self.__hex_to_int(hex_data[i:i+2])*2
        i+=2
        first_domain=self.__hex_to_str(hex_data[i:i+length_first_part])
        i+=length_first_part

        #We obtain the second part (*2 because they are hex not bytes)
        length_second_part=self.__hex_to_int(hex_data[i:i+2])*2
        i+=2
        second_domain=self.__hex_to_str(hex_data[i:i+length_second_part])
        i+=length_second_part
        
        #We create the domain
        domain=first_domain+"."+second_domain
                                      

        # Skip over the null terminator
        i += 2

        return domain, hex_data[i:i+2], hex_data[i+2:i+4],i

    def __find_domain_from_database(self,domain:str)->dict:
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


    #Methods to translate info of single headers
    def __str_ipv4_to_bytes(self, ipv4:str)->bytes:
        """
        This method is in charge of changing an ip string into bytes
        @ip: string containing an ip address
        @return: It returns the conversion of an ipv4 to bytes
        """
        rdata=b""
        #We iterate ipv4 without the "."
        for i in ipv4.split("."):
            rdata+=self.__int_to_bytes(int(i),1)
        return rdata
    
    def __str_class_to_bytes(self, class_str:str)->bytes:
        """
        Method in charge of translating an str class into its equivalent code in bytes
        @class_str: the class that we want to translate into bytes code
        @return: We return the class into bytes
        """
        if class_str=="IN":
            class_bytes=self.__int_to_bytes(1,2)#1=class IN(internet)
        else:
            raise ValueError("[ERROR] We only accept type IN for this lab")
        return class_bytes

    def __str_type_code_to_bytes(self, type_code_str:str)->bytes:
        """
        Method in charge of translating a string type code into bytes
        @type_code_str: A string containing the type code (e.g A)
        @return: It return the type code translated to bytes
        """
        type_code_bytes=b""
        if type_code_str=="A":
            type_code_bytes=self.__int_to_bytes(1,2)#1=type A
        else:
            raise ValueError("[ERROR] we only accept type A for this lab")
        return type_code_bytes

    def __domain_to_bytes(self,domain:str)->bytes:
        """
        Method to convert a string containing a domain into bytes
        @domain: string containing the domain
        @return: the domain converted into bytes
        """
        #Variables
        qname = b"" # Initialize
        domain_split = domain.split(".")

        #We transform the domain into bytes
        for part_domain in domain_split:
            #obtain the length
            qname_length=self.__int_to_bytes(len(part_domain),1)
            #Obtain the part of domain 
            part_domain_bytes=part_domain.encode()

            qname += qname_length+part_domain_bytes

        #End of domain
        qname += self.__int_to_bytes(0,1) # End of domain
        return qname


    #static methods to translate simple types into bytes or hex
    @staticmethod
    def __int_to_bytes(number:int,byte_size:int)->bytes:
        """
        Method to convert an integer to bytes
        @number: The number we want to convert into bytes
        @byte_size: How many bytes do we want to generate
        @return bytes: we return the conversion of number into bytes
        """
        #Byteorder big= most significant byte comes first
        return number.to_bytes(byte_size,byteorder="big")
    
    @staticmethod
    def __bits_to_bytes(bits:str)->bytes:
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
    def __hex_to_bytes(hex_data:hex)->bytes:
        """
        Method to translate hex into bytes
        @hex_data: data in hex to translate into bytes
        @return: The translation of hex into bytes
        """
        return bytes.fromhex(hex_data)
    
    @staticmethod
    def __hex_to_int(hex_data:hex)->int:
        """
        Convert a hexadecimal number to an integer
        @hex_data: hexadecimal numbers that contain an integer
        @return str: return te conversion from hex to in
        """
        return int(hex_data,16)

    @staticmethod
    def __hex_to_str(hex_data:hex)->str:
        """
        Method to convert a hexadecimal into a string
        @hex_data: hexadecimal numbers that contain a string
        @return str: return te conversion from hex to string
        """

        return bytes.fromhex(hex_data).decode('utf-8')

    @staticmethod
    def __print_hex(hex_number:hex)->None:
        """
        Method in charge of printing hex numbers
        @hex_data: The data we want to print
        """
        # 16 numbers are equivalent to 32 characters
        for i in range(0, len(hex_number), 32): 
            group = hex_number[i:i + 32]  
            
            # Join pairs of hex digits with a space for better readability
            formatted_group = ' '.join(group[i:i + 2] for i in range(0, 32, 2))  
            
            # Print the formatted group
            print(formatted_group)


if __name__=="__main__":
    serverIP = "127.0.0.1"
    serverPort = 12000
    debug=False
    server=Server(serverIP,serverPort,debug)
    server.initialize()