#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
//https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/UsingSocketsandSocketStreams.html#//apple_ref/doc/uid/CH73-SW12
//https://www.youtube.com/watch?v=F3iIGUiW27Q

// IMPORTANT -> REMOVE namespace std;

#include <string>
#include <map> // used to define the object tree
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "SnmpProtocol.h"

// SNMP
#define SNMP_MSG_MAX_LEN	2048

// Listening Port
#define PORT 161

// Define the SOCKET type
typedef int SOCKET;



void printAsHexa(char* byteArray, ssize_t lengthArray) {
	unsigned int value;
	for (int i = 0; i < lengthArray; i++)
	{	
		value = byte2int(byteArray[i]);
		std::cout << std::hex << std::uppercase << "0x" << std::setw(2) << std::setfill('0') << value << " "<<std::dec;
	}
    std::cout << std::endl;
}



int startSocket(SOCKET& sd, int puerto) {
	
	/* Open a datagram socket */
    // AF_INET=ipv4, AF_INET6=ipv6
    // SOCK_STREAM=TCP, SOCK_DGRAM=UDP
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == -1)
	{
        std::cerr<< "Could not create socket" << std::endl;
		return -1;
	}

	//Prepare the sockaddr_in structure
    struct sockaddr_in server;
    server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(puerto);

	//Bind
    bind(sd, (struct sockaddr*)&server, sizeof(server));
    std::cout << "Bind done to socket " << sd << std::endl;
    //std::cout << listen(sd, 1) << std::endl;
	return 0;
}

int receiveFromSocket(SOCKET sd, char* received, ssize_t& recv_len, struct sockaddr_in& infoIpCliente) {

    socklen_t clientLength = sizeof(infoIpCliente);

	std::cout << "Waiting for data..." << std::endl;
	//clear the buffer by filling null, it might have previously received data
	memset(received, '\0', SNMP_MSG_MAX_LEN);

	//try to receive some data, this is a blocking call
    recv_len = recvfrom(sd, received, SNMP_MSG_MAX_LEN, 0, (struct sockaddr*)&infoIpCliente, &clientLength);
    
	if (recv_len < 1)
	{
        std::cerr << "recvfrom() failed" << std::endl;
		exit(EXIT_FAILURE);
	}
	return 0;
}

int sendToSocket(SOCKET sd, const char* mensaje, ssize_t longMensaje, struct sockaddr_in& infoIpDestino) {
	int infoIpLength = sizeof(infoIpDestino);
    ssize_t sentBytes;
    sentBytes = sendto(sd, mensaje, longMensaje, 0, (struct sockaddr*)&infoIpDestino, infoIpLength);
    std::cout << sentBytes << std::endl;
    return 0;
}

///////////////////////////////77




int main(int argc, char* argv[])
{
	SOCKET sd;
	int myerror;
	myerror = startSocket(sd, PORT);
    int value = 235;

	ssize_t received_msg_length; // lreceived msg length
	char recv_msg_buffer[SNMP_MSG_MAX_LEN];

	struct sockaddr_in client_ip_info;

	SNMP_message *snmp_msg;
	TypeMyTree	management_db;
    
	TypeMyNode n;
	

	//keep listening for data
	while (1)
	{
        myerror = receiveFromSocket(sd, recv_msg_buffer, received_msg_length, client_ip_info);
        
		std::cout << "Received packet from " << inet_ntoa(client_ip_info.sin_addr) << ":" << ntohs(client_ip_info.sin_port) << std::endl;
		std::cout << "Number of bytes = " << received_msg_length << std::endl;
		std::cout << "Data in hexa:" << std::endl;
		printAsHexa(recv_msg_buffer, received_msg_length);


		char snmp_response_buffer[SNMP_MSG_MAX_LEN];
		ssize_t response_msg_length= received_msg_length;

		// TODO SNMP_message cosntrusctor method needs to be fully implemented
		snmp_msg=new SNMP_message (recv_msg_buffer);
 
        char aux [20];
	
        int tlvIntResponse = int_to_tlv(aux, value);
        
        tvalue intTValue;
        intTValue.integer_value = 16;
        
        n.object_type=scalar;
        n.max_access=read_only;
        n.data_type = INTEGER;
        n.value=intTValue;
        
        
        management_db[".1.3.6.1.3.10"]=n;
        
        
        
        
        
        
		// TODO: pdu_type is not properly filed
		switch (snmp_msg->pdu_type)
		{
		case SNMP_message::PduType::GET_REQUEST:
			
			// TODO
			// Add here code to handle get requests
			break;
		case SNMP_message::PduType::SET_REQUEST:
			// TODO
			// Add here code to handle set requests
			break;
		default:
			snmp_msg->error_status = genErr;

			std::cout << "Unknown Request Type :"<<std::hex<< (snmp_msg->pdu_type&0xFF)<<std::dec<<std::endl;
			break;

		}


		// TODO-

		response_msg_length=snmp_msg->to_tlv(snmp_response_buffer, SNMP_MSG_MAX_LEN);

		// DUMMY response answer with the received message
		response_msg_length = received_msg_length;
		memcpy(snmp_response_buffer, recv_msg_buffer,received_msg_length);


		std::cout << "Generated response:" << std::endl;
		std::cout << "Number of bytes = " << response_msg_length << std::endl;
		std::cout << "Data in hexa:" << std::endl;
		printAsHexa(snmp_response_buffer, response_msg_length);
        
        std::cout<<"Testing in2tlv"<<value<<std::endl;
        printAsHexa(aux, tlvIntResponse);
		myerror = sendToSocket(sd, ( char *)snmp_response_buffer, response_msg_length, client_ip_info);

        
        
	}



}
