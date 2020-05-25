#include "mbed.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h" /* SHA-256 only */
#include <stdlib.h>
#include <string.h>

// General Configs
#define BUFFER_SIZE 	256
#define SEND_BUFFER_SIZE 	25
#define DELTA_D 		15.0f

// WiFI Error Codes
#define ERROR_WIFI_NOT_FOUND 	-1
#define ERROR_WIFI_CONNECTION 	-2
#define WIFI_SUCCESS 			0

// Tier 1 Configuration
#define TIER_1_IP 		"192.168.43.73"
#define TIER_1_PORT 	9999

// Global Variables
WiFiInterface *wifi ;
char* IP 		= TIER_1_IP ;
int PORT 		= TIER_1_PORT ;
uint8_t myID 	= 0xFF ;
uint8_t dout 	= 0xFF ;
uint8_t k 		= 0xFF ;
uint8_t n 		= 0xFF ;
uint8_t leader  = 0xFF ;
TCPSocket sock ;

DigitalOut pinout(D10);

unsigned char *key = (unsigned char*)"secretKey";

unsigned char hmacResult[32];

// PROTOCOL_CODES
#define TIER2_INIT_READY 		0x01
#define TIER2_CONNECT_READY 	0x02 
#define TIER2_PROTOCOL_READY 	0x03 
#define BLAME_NO_PROGRESS 		0x04
#define BLAME_EQUIVOCATION 		0x05
#define PROTOCOL_END 			0x06

#define BASE_MULTICAST_ADDR 	(uint8_t*){224,1,1,1}

/** 
 * 1. Initialize WiFi Interface 
 * 2. Connect to WiFi
 * */
int wifiSetup ()
{
	wifi = WiFiInterface::get_default_instance() ;
	if ( !wifi ) {
		return ERROR_WIFI_NOT_FOUND ;
	}
	/** Connect to WiFi */
	printf ( "\nConnecting to %s.\n" , MBED_CONF_APP_WIFI_SSID ) ;
	int ret_con = wifi -> connect ( 
			MBED_CONF_APP_WIFI_SSID, 
			MBED_CONF_APP_WIFI_PASSWORD, 
			NSAPI_SECURITY_WPA_WPA2 
		) ;
	if ( ret_con != 0 ) {
		return ERROR_WIFI_CONNECTION ;
	}
	ret_con = wifi->set_dhcp ( true ) ;
	if ( ret_con != 0 ) {
		return ret_con ;
	}
	return WIFI_SUCCESS ;
}

void print_info ()
{
	printf ( "MAC: %s\n" , wifi->get_mac_address () ) ;
    printf ( "IP: %s\n", wifi->get_ip_address () ) ;
    printf ( "Gateway: %s\n", wifi->get_gateway () ) ;
}


void send_msg ( uint8_t* msg , size_t msg_size , uint8_t k_cast_id )
{
	// Send < kcast_id || msg > to Tier 1
	uint8_t* msg_new = (uint8_t*) malloc ( msg_size + 2 ) ;
	msg_new [ 0 ] = k_cast_id ;
	msg_new [ 1 ] = msg_size ;
	memcpy ( msg_new + 2 , msg , msg_size ) ;
// hmac
// Need to add hmac code here
//done hmac
	sock .send ( msg_new , msg_size + 2 ) ;
	free ( msg_new ) ;
}

void sendAll ( uint8_t* msg, size_t msg_size )
{
	for ( int i = 0 ; i < dout ; i++ ) {
		send_msg ( msg , msg_size , i ) ;
	}
}

bool verify_signature ( uint8_t* msg, size_t msg_size , uint8_t sender_id ) {
// And here
	return true ;
}

volatile bool timeout = false ;

void handle_timeout ( void )
{
	timeout = true ;
}

int main()
{
	pinout=0;
	pinout=1;
	int status = 0 , len = 0;
	nsapi_error_t error ;
	uint8_t msg_buf [ BUFFER_SIZE ] ;
	uint8_t msg_send_buf [SEND_BUFFER_SIZE];
	status = wifiSetup () ;
	if ( status < 0 ) {
		printf ( "WiFi Error [%d]\n" , status ) ;
		return status ;
	}
	print_info () ;
	// Open socket
	sock .open ( wifi ) ;
	// Connect to socket
	SocketAddress t1_addr ( IP , PORT ) ;
	printf ( "Connecting to Tier 1 with IP %s, port %d\n\n" , IP , PORT ) ;
	error = sock .connect ( t1_addr ) ;
	if ( error != NSAPI_ERROR_OK ) {
		printf ( "Connection Error [%d]\n" , error ) ;
		return error ;
	}
	printf ( "Sending <READY> to Tier 1(IP: %s, Port: %d).\n" , IP , PORT ) ;
	msg_buf [ 0 ] = TIER2_INIT_READY ;
	sock .send ( msg_send_buf , 1 ) ;
	printf ( "Sent Tier 1 <READY>.\n" ) ;
	printf ( "Waiting to Receive my ID.\n" ) ;
	len = sock .recv ( msg_buf , BUFFER_SIZE ) ;
	printf ( "Received values to commit from Tier 1.\n" ) ;
	sock .close() ; //close socket
	wifi -> disconnect () ;
	printf ( "Disconnected from the WiFi \n" ) ;
	printf ("End of protocol \n") ;
	pinout=0;
	return 0 ;
}



