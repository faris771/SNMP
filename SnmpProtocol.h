#pragma once
#include <string>
#include <stdio.h>
//#include <winsock2.h>
#include <string>
#include <map> // used to define the object tree
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>


#include <cstring>


#define BUFF_LEN 512



// We define enumerations as alias for relevant integer values
enum Asn1DataType
{
	INTEGER				= 0x02,
	OCTET_STRING		= 0x04,
	OBJECT_IDENTIFIER	= 0x06,
	IpAddress			= 0x40,
	NULL_asn1			= 0x05,
	SEQUENCE			= 0x30,
	Gauge32				= 0x42,
};

enum ErrorStatus
{
	noError		= 0,
	tooBig		= 1,
	noSuchName	= 2,
	badValue	= 3,
	readOnly	= 4,
	genErr		= 5,
};

enum MaxAccess
{
	not_accessible	= 0,
	read_only		= 1,
	read_write		= 2,
};

enum ObjectType
{
	scalar	= 0,
	table	= 1,
	row		= 2,
	column	= 3,
};

/* Definition of the basic data types */
typedef union A {
	int integer_value;   /* for the INTEGER type */
	char* char_array_value; /* for OCTET STRING, OBJECT IDENTIFIER, IpAddress */
} tvalue;



typedef struct B {
	ObjectType object_type= ObjectType::scalar;
	Asn1DataType data_type;
	MaxAccess max_access=MaxAccess::not_accessible;   
	unsigned int length;
	tvalue value;
} TypeMyNode;

typedef std::map<std::string, TypeMyNode> TypeMyTree; // a tree to store the managed objects


// variable binding
typedef struct {
	std::string oid;
	int length;
	int asn1_type;
	tvalue value;

}VariableBind;



char int2byte(unsigned int number);

unsigned int byte2int(unsigned char bb);


// TLV helping functions

// decoding functions
int read_tlv_int(char *data, int &read_value);

// functions not implemented :
int read_tlv_string(char *data, char *read_value);
int read_tlv_oid(char *data, std::string &oid);
int read_tlv_variable_binding(char *data, VariableBind &tmpVarBind);
int read_tlv_variable_binding_list(char *data, std::vector<VariableBind>  &var_bind_list);

//definition of encoding functions

/// <summary>
/// Converts an integer to its BER enconding format. 
/// Type Length value
/// </summary>
/// <param name="ber_coding">the buffer that will hold the resulting coding</param>
/// <param name="value">The value to be encoded</param>
/// <returns></returns>
unsigned int int_to_tlv(char *ber_coding, unsigned int value);

// not implemented,... TODO
unsigned int char_array_to_tlv(char *ber_coding, const  char *char_array, unsigned int value_length, Asn1DataType type = Asn1DataType::OCTET_STRING);
unsigned int string_to_tlv(char *ber_coding, std::string str);
unsigned int oid_to_tlv(char *ber_coding, std::string oid);
unsigned int varbind_to_tlv( char *ber_coding, VariableBind tmpVarBind);


class SNMP_message
{
	void error_reading_packet() {
		std::cout<<"Error reading packet\n";
		this->valid_paket = 0;
		//throw new std::exception("Error reading the decoding the packet");
	};

public:
	int valid_paket;
	int version;
	std::string comunity;
	enum PduType { GET_REQUEST = (0xA0), GET_NEXT_REQUEST = (0xA1), GET_RESPONSE = (0xA2), SET_REQUEST = (0xA3) };
	PduType pdu_type;
	int request_id;
	ErrorStatus error_status;
	int error_index;
	std::vector<VariableBind>  variable_binding_list;

	/// <summary>
	/// Constructor. Decodes the BER encoded message in "data" and initilizes all the object properties.
	/// </summary>
	/// <param name="data">The received SNMP message</param>
	SNMP_message(char* data); 

	

	/// <summary>
	/// This function builds the BER encoding of the message
	/// </summary>
	/// <param name="ber_MSG"> The buffer where to write the message. It must be preallocated. </param>
	/// <param name="max_length">The buffer size</param>
	/// <returns></returns>
	int to_tlv(char* ber_msg_buffer, int buffer_length);

};
