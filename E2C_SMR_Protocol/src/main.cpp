#include "mbed.h"
#include <events/mbed_events.h>
#include "ble/BLE.h"
#include "pretty_printer.h"
#include "mbedtls/sha256.h" /* SHA-256 only */
#include "mbedtls/md.h"     /* generic interface */
#include <Types.h>
#include <time.h>
#include <cstdlib>

#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"

#include <string>
#include <stdlib.h>
#include <stdio.h>

// General Configs
#define BUFFER_SIZE 	256
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

// PROTOCOL_CODES
#define TIER2_INIT_READY 		0x01
#define TIER2_CONNECT_READY 	0x02 
#define TIER2_PROTOCOL_READY 	0x03 
#define BLAME_NO_PROGRESS 		0x04
#define BLAME_EQUIVOCATION 		0x05
#define PROTOCOL_END 			0x06

#define BASE_MULTICAST_ADDR 	(uint8_t*){224,1,1,1}

#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#define KEY_SIZE 1260
#define EXPONENT 65537

/** 
 * 1. Initialize WiFi Interface 
 * 2. Connect to WiFi
 * 3. Receive values from Tier 1
 * 4. Use BLE to communicate
 * */

//*************************** Cryptography Stuff ****************

int my_rng(void* x, unsigned char* y, size_t z) {
	return 0;
}

unsigned char* RSA_sign(unsigned char hash[32]){
        unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
	mbedtls_rsa_context rsa;
	mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

	mbedtls_mpi_init( &N );
	mbedtls_mpi_init( &E );
	mbedtls_mpi_init( &P );
	mbedtls_mpi_init( &Q );
	mbedtls_mpi_init( &D );
	mbedtls_mpi_init( &DP );
	mbedtls_mpi_init( &DQ );
	mbedtls_mpi_init( &QP );

	mbedtls_mpi_read_string( &N , 16 , "0D23402FB4F2988E0266EB9E0E1818FB39A76042D49A756DCE9DF1F9818D5D7BA6B274B88BAF5E3298BDCF8872B2FD6BD381A53393B460809870313E270544ED97B57414A160E795958A39258FD596DF165E73E12FC9AA7B520772A5437A2270F69CDFEBCA266598EEC9F82A6D937A81F7A91B1FB076334A827B130C1B0E0B1C1F4E5BF7E8840C599C35F451CA999F33494913813A1E4D2CC08085FDB05B" );

	mbedtls_mpi_read_string( &P , 16 , "3F4B5EF78E55241FBF19CFAE332679476E972CC9409A3D96CE4B87DF2A43A8B09D1C2B1D47E757839DAE741EFF5F9FFA52D3C7236E165D0D5AD08CC35235C4DDF0F1FBD4020579FB842501EBCFF679" );

	mbedtls_mpi_read_string( &Q , 16 , "3522F8CD929A8E24A6238E44AC34CFDC7476F107590038DBCC83560F92690BCF07ACF54E88E0011CE78CECDCEB635AF1F9221E0E69E9D075750981DD1A807C340D9FBB0782EBB6F1FBD5F55303B873" );

	mbedtls_mpi_read_string( &D , 16 , "A4F0A5BF32333D3890617AFED482B6760FFCF048557CE160759FBFF49BBA0D1C35EC2CF0FFE6E5211E69EFA4A7F319D7258C09B556E01C090F970F17C24057309CAA92FDFE6EE987B6A6D52740BA7C3CE88936AB06E1DA85EC5502CA86A097F1D3F8101B800BE9FB27215294744942826F1BBDDEB2186D8A43A33DFB8E49632E2CBA6F16460FBFB767EB5989FFBC33C227D9540B23C5F4235822004519" );

	mbedtls_mpi_read_string ( &E , 16 , "010001" );
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
	mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E );
	int status = mbedtls_rsa_complete (&rsa);

	printf ("Status of RSA Import: %s\n" , status == 0 ? "GOOD to Go": "Failed" );
	if( ( status = mbedtls_rsa_pkcs1_sign( &rsa, NULL, NULL,
	MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 20, hash, buf ) ) != 0 )
    {	
        mbedtls_printf( "Failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", status );
        goto exit;
    }
exit:	mbedtls_mpi_free( &N );
	mbedtls_mpi_free( &E );
	mbedtls_mpi_free( &P );
	mbedtls_mpi_free( &Q );
	mbedtls_mpi_free( &D );
	mbedtls_mpi_free( &DP );
	mbedtls_mpi_free( &DQ );
	mbedtls_mpi_free( &QP );


	return buf;
}

int RSA_verify(unsigned char hash[32], unsigned char buf[MBEDTLS_MPI_MAX_SIZE]){
	mbedtls_rsa_context rsa;
	mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

	mbedtls_mpi_init( &N );
	mbedtls_mpi_init( &E );
	mbedtls_mpi_init( &P );
	mbedtls_mpi_init( &Q );
	mbedtls_mpi_init( &D );
	mbedtls_mpi_init( &DP );
	mbedtls_mpi_init( &DQ );
	mbedtls_mpi_init( &QP );

	mbedtls_mpi_read_string( &N , 16 , "0D23402FB4F2988E0266EB9E0E1818FB39A76042D49A756DCE9DF1F9818D5D7BA6B274B88BAF5E3298BDCF8872B2FD6BD381A53393B460809870313E270544ED97B57414A160E795958A39258FD596DF165E73E12FC9AA7B520772A5437A2270F69CDFEBCA266598EEC9F82A6D937A81F7A91B1FB076334A827B130C1B0E0B1C1F4E5BF7E8840C599C35F451CA999F33494913813A1E4D2CC08085FDB05B" );

	mbedtls_mpi_read_string( &P , 16 , "3F4B5EF78E55241FBF19CFAE332679476E972CC9409A3D96CE4B87DF2A43A8B09D1C2B1D47E757839DAE741EFF5F9FFA52D3C7236E165D0D5AD08CC35235C4DDF0F1FBD4020579FB842501EBCFF679" );

	mbedtls_mpi_read_string( &Q , 16 , "3522F8CD929A8E24A6238E44AC34CFDC7476F107590038DBCC83560F92690BCF07ACF54E88E0011CE78CECDCEB635AF1F9221E0E69E9D075750981DD1A807C340D9FBB0782EBB6F1FBD5F55303B873" );

	mbedtls_mpi_read_string( &D , 16 , "A4F0A5BF32333D3890617AFED482B6760FFCF048557CE160759FBFF49BBA0D1C35EC2CF0FFE6E5211E69EFA4A7F319D7258C09B556E01C090F970F17C24057309CAA92FDFE6EE987B6A6D52740BA7C3CE88936AB06E1DA85EC5502CA86A097F1D3F8101B800BE9FB27215294744942826F1BBDDEB2186D8A43A33DFB8E49632E2CBA6F16460FBFB767EB5989FFBC33C227D9540B23C5F4235822004519" );

	mbedtls_mpi_read_string ( &E , 16 , "010001" );
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
	mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E );
	int status = mbedtls_rsa_complete (&rsa);

	printf ("Status of RSA Import: %s\n" , status == 0 ? "GOOD to Go": "Failed" );
    if( ( status = mbedtls_rsa_pkcs1_verify( &rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
                                  MBEDTLS_MD_SHA256, 20, hash, buf ) ) != 0 )
    {
        mbedtls_mpi_free( &N );
	mbedtls_mpi_free( &E );
	mbedtls_mpi_free( &P );
	mbedtls_mpi_free( &Q );
	mbedtls_mpi_free( &D );
	mbedtls_mpi_free( &DP );
	mbedtls_mpi_free( &DQ );
	mbedtls_mpi_free( &QP );
	return 0;
    }

        mbedtls_mpi_free( &N );
	mbedtls_mpi_free( &E );
	mbedtls_mpi_free( &P );
	mbedtls_mpi_free( &Q );
	mbedtls_mpi_free( &D );
	mbedtls_mpi_free( &DP );
	mbedtls_mpi_free( &DQ );
	mbedtls_mpi_free( &QP );
	return 1;
}


//***************************WiFi Stuff *********************
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

void print_params ( uint8_t* ptr )
{
	printf ( "dout is %u.\n" , ptr [ 0 ] ) ;
	printf ( "k is %u.\n" , ptr [ 1 ] ) ;
	printf ( "n is %u.\n" , ptr [ 2 ] ) ;
	printf ( "leader is %u.\n" , ptr [ 3 ] ) ;
}

//************************* BLE Stuff : Leader *********************

static events::EventQueue event_queue(/* event count */ 16 * EVENTS_EVENT_SIZE);

class LeaderDemo : ble::Gap::EventHandler {
public:
    LeaderDemo(BLE &ble, events::EventQueue &event_queue) :
        _ble(ble),
        _event_queue(event_queue),
        _adv_data_builder(_adv_buffer) { }

    void start() {
        _ble.gap().setEventHandler(this);

        _ble.init(this, &LeaderDemo::on_init_complete);

        _event_queue.dispatch_forever();
    }

private:
    union Payload {
        uint8_t raw[25];
        struct {
            uint16_t companyID;
            uint8_t ID;
            uint8_t len;
	    char proximityUUID[16];
            uint16_t majorNumber;
            uint16_t minorNumber;
           uint8_t txPower;
        };

        Payload(
	    const char *uuid,
            uint16_t majNum,
            uint16_t minNum,
            uint8_t transmitPower,
            uint16_t companyIDIn
        ) : companyID(companyIDIn),
            ID(0x02),
            len(0x15),
            majorNumber(__REV16(majNum)),
            minorNumber(__REV16(minNum)),
            txPower(transmitPower)
        {
            memcpy(proximityUUID, uuid, 10);
        }
    };


    void on_init_complete(BLE::InitializationCompleteCallbackContext *params) {
        if (params->error != BLE_ERROR_NONE) {
            printf("Ble initialization failed.");
            return;
        }
        print_mac_address();
	//************** Preparing Data here: *************
	char original_data[BUFFER_SIZE]="Enctllnkn";
	char data_slice[16]="";
        unsigned char output1[32];
 	static const unsigned char *tmp = (const unsigned char *) original_data;
 	mbedtls_sha256(tmp, BUFFER_SIZE, output1, 0);
	unsigned char* sign_buf;
	sign_buf=RSA_sign(output1);
	//Send data first
	for(int loop=0; loop<=BUFFER_SIZE; loop=loop+16)
	{
	   for(int inn_l=0; inn_l<16; inn_l++)
	   {
		data_slice[inn_l]=original_data[inn_l+loop];
           }
	   int flag=1;
	   start_advertising(data_slice,flag);	
	}
	//Send signature next
	for(int loop=0; loop<=MBEDTLS_MPI_MAX_SIZE; loop=loop+16)
	{
	   for(int inn_l=0; inn_l<16; inn_l++)
	   {
		data_slice[inn_l]=sign_buf[inn_l+loop];
           }
	   int flag=0;
	   start_advertising(data_slice,flag);	
	}
	//************************************************
    }//on_init_complete

    void start_advertising(char data_slice[16],int a ) {
        ble::AdvertisingParameters adv_parameters(
            ble::advertising_type_t::CONNECTABLE_UNDIRECTED,
            ble::adv_interval_t(ble::millisecond_t(1000))
        );
        _adv_data_builder.setFlags();
        uint16_t major_number;
	if(a=1)
        major_number = 1122;  // it is data
	else
        major_number = 2211; // it is a signature
        uint16_t minor_number = 3344;
        uint16_t tx_power     = 0xC8;
        uint16_t comp_id      = 0x004C;

	Payload iLeader(data_slice,major_number, minor_number, tx_power, comp_id);
        _adv_data_builder.setManufacturerSpecificData(iLeader.raw);
        ble_error_t error = _ble.gap().setAdvertisingParameters(
            ble::LEGACY_ADVERTISING_HANDLE,
            adv_parameters
        );

        if (error) {
            print_error(error, "_ble.gap().setAdvertisingParameters() failed");
            return;
        }

        error = _ble.gap().setAdvertisingPayload(
            ble::LEGACY_ADVERTISING_HANDLE,
            _adv_data_builder.getAdvertisingData()
        );
	uint16_t timer=0x1;
	_ble.gap().setAdvertisingTimeout(timer);

        if (error) {
            print_error(error, "_ble.gap().setAdvertisingPayload() failed");
            return;
        }

        /* Start advertising */

        error = _ble.gap().startAdvertising(ble::LEGACY_ADVERTISING_HANDLE);
	clock_t startTime = clock();
        if (error) {
            print_error(error, "_ble.gap().startAdvertising() failed");
            return;
        }
	while(_ble.gap().isAdvertisingActive(ble::LEGACY_ADVERTISING_HANDLE)){
	//printf("In the lop \n");
		if((clock()-startTime)>=100)
		_ble.gap().stopAdvertising(ble::LEGACY_ADVERTISING_HANDLE);
	}
	if((_ble.gap().isAdvertisingActive(ble::LEGACY_ADVERTISING_HANDLE))==false)	
	{
	printf("Advertising ended\n");
	return;
	}

    }

private:
    void onDisconnectionComplete(const ble::DisconnectionCompleteEvent&) {
        _ble.gap().startAdvertising(ble::LEGACY_ADVERTISING_HANDLE);
    }

private:
    BLE &_ble;
    events::EventQueue &_event_queue;
    uint8_t _adv_buffer[ble::LEGACY_ADVERTISING_MAX_SIZE];
    ble::AdvertisingDataBuilder _adv_data_builder;
};

void schedule_ble_events(BLE::OnEventsToProcessCallbackContext *context) {
    event_queue.call(Callback<void()>(&context->ble, &BLE::processEvents));
}

//************************* BLE Stuff : Receiver *********************

static events::EventQueue event_queue1(/* event count */ 16 * EVENTS_EVENT_SIZE);

class ReceiverDemo : ble::Gap::EventHandler {
public:
    ReceiverDemo(BLE &ble, events::EventQueue &event_queue) :
        _ble(ble),
        _event_queue(event_queue),
        _adv_data_builder(_adv_buffer) { }

    void start() {
        _ble.gap().setEventHandler(this);

        _ble.init(this, &ReceiverDemo::on_init_complete);

        _event_queue.dispatch_forever();
    }

private:
    union Payload {
        uint8_t raw[25];
        struct {
            uint16_t companyID;
            uint8_t ID;
            uint8_t len;
	    char proximityUUID[16];
            uint16_t majorNumber;
            uint16_t minorNumber;
           uint8_t txPower;
        };

        Payload(
	    const char *uuid,
            uint16_t majNum,
            uint16_t minNum,
            uint8_t transmitPower,
            uint16_t companyIDIn
        ) : companyID(companyIDIn),
            ID(0x02),
            len(0x15),
            majorNumber(__REV16(majNum)),
            minorNumber(__REV16(minNum)),
            txPower(transmitPower)
        {
            memcpy(proximityUUID, uuid, 10);
        }
    };

    void on_init_complete(BLE::InitializationCompleteCallbackContext *params) {
        if (params->error != BLE_ERROR_NONE) {
            printf("Ble initialization failed.");
            return;
        }
        print_mac_address();
	start_scanning();
    }//on_init_complete


		/* Advertising data  */
	struct AdvertisingData_t {
	    uint8_t length; /* doesn't include itself */
	    GapAdvertisingData::DataType dataType;
	    uint8_t data[1];
	};

	struct ApplicationData_t {
		    uint16_t companyID;
		    uint8_t ID;
		    uint8_t len;
		char proximityUUID[16];
		    uint16_t majorNumber;
		    uint16_t minorNumber;
		    uint8_t txPower;
	};


      virtual void onAdvertisingReport (const Gap::AdvertisementCallbackParams_t *params)
	{
	char original_data[BUFFER_SIZE]="";
	char data_slice[16]="";
	unsigned char* sign_buf;
	int dat_p, sign_p;
	dat_p=0; sign_p=0;
	
	AdvertisingData_t *pAdvData = NULL;
	uint8_t len = 0;
	printf("It is scanning \n");
	while (len < params->advertisingDataLen){
	    pAdvData = (AdvertisingData_t *)&params->advertisingData[len];
	    if(pAdvData->dataType == GapAdvertisingData::MANUFACTURER_SPECIFIC_DATA) {
		ApplicationData_t *pAppData = (ApplicationData_t *)pAdvData->data;
		//Store Data
		if(pAppData->majorNumber==1122){
		for(int in_lop=0; in_lop<16; in_lop++)
			original_data[dat_p]=pAppData->proximityUUID[in_lop];
			dat_p++;
		}
		//Store signature
		if(pAppData->majorNumber==2211){
		for(int in_lop=0; in_lop<16; in_lop++)
			sign_buf[sign_p]=pAppData->proximityUUID[in_lop];
			sign_p++;
		}
		unsigned char output1[32];
 	        static const unsigned char *tmp = (const unsigned char *) original_data;
 	        mbedtls_sha256(tmp, BUFFER_SIZE, output1, 0);
		if(RSA_verify(output1,sign_buf)==1){
		// Accept and forward
	        for(int loop=0; loop<=BUFFER_SIZE; loop=loop+16)
		{
	  		 for(int inn_l=0; inn_l<16; inn_l++)
	   		{
				data_slice[inn_l]=original_data[inn_l+loop];
           		}
	   	int flag=1;
	   	start_advertising(data_slice,flag);	
		}
		//Send signature next
		for(int loop=0; loop<=MBEDTLS_MPI_MAX_SIZE; loop=loop+16)
		{
		   for(int inn_l=0; inn_l<16; inn_l++)
	 	  {
			data_slice[inn_l]=sign_buf[inn_l+loop];
           	  }
	   	  int flag=0;
	          start_advertising(data_slice,flag);	
		}
		printf("Accept \n");
		}
		}//if padvData
		len +=(pAdvData->length + 1);
	    }//while
	}//Void

   void start_scanning(){
	uint16_t timer=1;
	dout=1;
	clock_t startTime_scan = clock();
	_ble.gap().startScan(ble::scan_duration_t(0x1000));
	while((clock()-startTime_scan)<2000){
	//printf("In the lop \n");
		if((clock()-startTime_scan)>=2000)
		_ble.gap().stopScan();
	}
	printf("Its exiting the scan \n");
	dout=0;
	return;
	}

    void start_advertising(char data_slice[16],int a ) {
        ble::AdvertisingParameters adv_parameters(
            ble::advertising_type_t::CONNECTABLE_UNDIRECTED,
            ble::adv_interval_t(ble::millisecond_t(1000))
        );
        _adv_data_builder.setFlags();
        uint16_t major_number;
	if(a=1)
        major_number = 1122;  // it is data
	else
        major_number = 2211; // it is a signature
        uint16_t minor_number = 3344;
        uint16_t tx_power     = 0xC8;
        uint16_t comp_id      = 0x004C;

	Payload iLeader(data_slice,major_number, minor_number, tx_power, comp_id);
        _adv_data_builder.setManufacturerSpecificData(iLeader.raw);
        ble_error_t error = _ble.gap().setAdvertisingParameters(
            ble::LEGACY_ADVERTISING_HANDLE,
            adv_parameters
        );

        if (error) {
            print_error(error, "_ble.gap().setAdvertisingParameters() failed");
            return;
        }

        error = _ble.gap().setAdvertisingPayload(
            ble::LEGACY_ADVERTISING_HANDLE,
            _adv_data_builder.getAdvertisingData()
        );
	uint16_t timer=0x1;
	_ble.gap().setAdvertisingTimeout(timer);

        if (error) {
            print_error(error, "_ble.gap().setAdvertisingPayload() failed");
            return;
        }

        /* Start advertising */

        error = _ble.gap().startAdvertising(ble::LEGACY_ADVERTISING_HANDLE);
	clock_t startTime = clock();
        if (error) {
            print_error(error, "_ble.gap().startAdvertising() failed");
            return;
        }
	while(_ble.gap().isAdvertisingActive(ble::LEGACY_ADVERTISING_HANDLE)){
	//printf("In the lop \n");
		if((clock()-startTime)>=100)
		_ble.gap().stopAdvertising(ble::LEGACY_ADVERTISING_HANDLE);
	}
	if((_ble.gap().isAdvertisingActive(ble::LEGACY_ADVERTISING_HANDLE))==false)	
	{
	printf("Advertising ended\n");
	return;
	}

    }


private:
    void onDisconnectionComplete(const ble::DisconnectionCompleteEvent&) {
        _ble.gap().startAdvertising(ble::LEGACY_ADVERTISING_HANDLE);
    }

private:
    BLE &_ble;
    events::EventQueue &_event_queue;
    uint8_t _adv_buffer[ble::LEGACY_ADVERTISING_MAX_SIZE];
    ble::AdvertisingDataBuilder _adv_data_builder;
};

void schedule_ble_events_r(BLE::OnEventsToProcessCallbackContext *context) {
    event_queue.call(Callback<void()>(&context->ble, &BLE::processEvents));
}


//**************************************************************

int main ()
{
	int status = 0 , len = 0;
	nsapi_error_t error ;
	uint8_t msg_buf [ BUFFER_SIZE ] ;
	uint8_t* ptr = (uint8_t*) msg_buf ;
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
	sock .send ( msg_buf , 1 ) ;
	printf ( "Sent Tier 1 <READY>.\n" ) ;
	printf ( "Waiting to Receive my ID.\n" ) ;
	len = sock .recv ( msg_buf , BUFFER_SIZE ) ;
	myID = (uint8_t) msg_buf [ 0 ] ;
	printf ( "My ID is %u.\n" , msg_buf [ 0 ] ) ;
	len -= 1 ;
	if ( len == 0 ) {
		ptr = (uint8_t*) msg_buf ;
		len = sock .recv ( msg_buf , BUFFER_SIZE ) ;
	} else {
		ptr += 1 ;
	}
	printf ( "Received %d bytes for Initial Parameters.\n" , len ) ;
	print_params ( ptr ) ;
	dout = (uint8_t) ptr [ 0 ] ;
	k = (uint8_t) ptr [ 1 ] ;
	n = (uint8_t) ptr [ 2 ] ;
	leader = (uint8_t) ptr [ 3 ] ;
	len -= 4 ;
	msg_buf [ 0 ] = TIER2_CONNECT_READY ;
	sock .send ( msg_buf , 1 ) ;
	if ( len == 0 ) {
		len = sock .recv ( msg_buf , BUFFER_SIZE ) ;
		// Confirm if it is 0x03
	}
	printf ( "Received PROTOCOL START from Tier 1.\n" ) ;
    BLE &ble_l = BLE::Instance();
    ble_l.onEventsToProcess(schedule_ble_events);

    BLE &ble_r = BLE::Instance();
    ble_r.onEventsToProcess(schedule_ble_events_r);

    LeaderDemo demo(ble_l, event_queue);
    ReceiverDemo demo1(ble_r, event_queue1);

	len -= 1 ;
	unsigned char* msg = (unsigned char*)"Hello" ;
	if ( myID == leader ) {
	   demo.start();
	}
	else{
           demo1.start();
	}
	wait ( n*3.0 ) ;
	sock .close() ; //close socket
	wifi -> disconnect () ;
	printf ( "Disconnected from the WiFi \n" ) ;
	printf ("End of protocol \n") ;

	return 0;
}

