#include "mbed.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <events/mbed_events.h>
#include "ble/BLE.h"
#include "gap/AdvertisingDataParser.h"
#include "pretty_printer.h"
#include "mbedtls/sha256.h" /* SHA-256 only */

#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <vector>


#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"

#define BSIZE 2
#define F 1
#define PAYLOADSIZE 24
#define BLKSIZE 8*BSIZE + 33
#define VOTESIZE 8*BSIZE + 35
#define PROPOSALSIZE BLKSIZE+3
#define NOPROGRESSBLAMESIZE 3
#define EQUIVOCATIONBLAMESIZE 2*SIGSIZE+PROPOSALSIZE+3
#define K 7
#define ND 8
#define SDELTA 10000
#define DELTA ND*SDELTA
#define SIGSIZE 128
#define BYZFLAG 0
#define OS_MAINSTKSIZE  4096
#define ADVSTARTTIME 200
#define ADVSTOPTIME 180

#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#define KEY_SIZE 1260
#define EXPONENT 65537
// generic node class, interface list
// TODO: Have a map of nodes and their keys
static const char *DEVICE_NAME = "N1";
static events::EventQueue event_queue(/* event count */ 200 * EVENTS_EVENT_SIZE);
Mutex stdio_mutex;
DigitalOut dout(D10);
uint8_t mac_addr[9][6] = {{223,67,240,220,36,31},
                                   {246,171,75,3,235,80},
                                   {238,103,88,38,195,251},
                                  {209,144,134,10,89,230},
                                  {201,71,182,141,8,230},
                                  {215,150,143,20,201,170},
                                  {211,43,84,236,50,74},
                                  {242,228,238,29,220,245},
                                  {200,20,152,75,132,78}};
class ConNode: ble::Gap::EventHandler{
public: 
    ConNode(BLE &ble, events::EventQueue &event_queue): 
        _ble(ble),
        _event_queue(event_queue),
		_led1(LED1,1),
        _adv_data_builder(_adv_buffer){}
    
    void start(){
        printf("Starting consensus\n");
        // allocate buffers for signatures and hashes
        sign_buf = (unsigned char *) malloc(SIGSIZE * sizeof(unsigned char));
        hash_buf = (unsigned char *) malloc(32 * sizeof(unsigned char));
        //_event_queue.call_every(1000, this, &ConNode::blink);
        _ble.gap().setEventHandler(this);
        ble_error_t err = _ble.init(this, &ConNode::on_init_complete);
        _ble.onEventsToProcess(
            makeFunctionPointer(this, &ConNode::schedule_ble_events)
        );
        if(err){
            print_error(err,"initialization error \n");
        }
        printf("Initialization complete\n");
        //printf("%d\n",_ble.gap().getMaxAdver);
        printf("%d\n",_ble.gap().getMaxAdvertisingInterval());
        _event_queue.dispatch_forever();
    }

    union Block {
        uint8_t raw[8*BSIZE +33];
        struct {
            uint8_t height;
            char commands[8*BSIZE];
            char prev_hash[32];
        };
    };
    char chain_hash[32] = {0};
    uint8_t leader = 1;
    uint16_t blame_event_timer = 0;
    // only leader prepares certificates
    union Vote {
        uint8_t raw[VOTESIZE];
        struct {
            // id of the host voting
            uint8_t ID;
            // view number
            uint16_t view;
            Block blk;
        };
        Vote(uint8_t ID,uint8_t view,Block blk){
            this->ID = ID;
            this->view = view;
            this->blk = blk;
        }
        Vote(){
            this->ID= 0;
            this->view = 0;
            memset(&this->blk,0 ,sizeof(union Block));
        }
    };
    struct Certificate {
        Vote votes[F+1];
        char signatures[SIGSIZE*(F+1)];
        Certificate(){
            memset(this->signatures, 0,SIGSIZE*(F+1) );
        }
    };
    union Propose {
        // 8 2 byte commands
        uint8_t raw[PROPOSALSIZE];
        struct {
            Block blk;
            uint8_t ID;
            // view number
            uint16_t view;
        };
        Propose(){}
    };
    union NPBlame {
        uint8_t raw[3];
        struct {
            uint8_t view;
            uint8_t ID;
            uint8_t type;
        };
    };
    union EqBlame {
        uint8_t raw[2*SIGSIZE+PROPOSALSIZE+3];
        struct {
            uint8_t view;
            uint8_t ID;
            uint8_t type;
            Propose propose;
            uint8_t sign1[SIGSIZE];
            uint8_t sign2[SIGSIZE];
        };
    };
    private:
        // payload packet
        union Payload {
            // TODO: configure this
            uint8_t raw[PAYLOADSIZE+5];
            struct {
                uint8_t ID;
                // what is the type of the packet?
                uint8_t type;
                // ending packet/starting packet
                uint8_t flag;
                // length of the data in the packet
                uint8_t len;
                // sequence number of the packet
                uint8_t seq;
                unsigned char data[PAYLOADSIZE];
            };

            Payload( uint8_t ID,uint8_t type,uint8_t flag,uint8_t len,uint8_t seq, unsigned char* trData): 
            ID(ID),len(len),flag(flag),type(type),seq(seq){
                // identifier
                memcpy(data, trData, PAYLOADSIZE);
            }
        };

        struct PayloadFrame {
            uint8_t ID;
            // what is the type of the packet?
            uint8_t type;
            // ending packet/starting packet
            uint8_t flag;
            // length of the data in the packet
            uint8_t len;
            // sequence number of the packet
            uint8_t seq;
            char data[PAYLOADSIZE];
        };
    // combine leader and receiver, because leader does receive messages also
    void RSA_sign(){
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

        mbedtls_mpi_read_string(&N, 16 , "f4f23ad7acdcee1c062b76f939f3112e67841d0c92a1628082e6e765c858faf3afe531fac65153a0e427828ef602c7ce2f719471072eac7d73f96bd6ec66429717d42ad166fb35509c8dfb4900fcfe49a0ea8497b032fb8cddcb03d1b2e8b65294a25ccc956f2892a68d114698ad298b9e2ebe44f024e815bd27e31839fc1411");
        //printf("%d\n",mbedtls_mpi_size(&N));
        //mbedtls_mpi_read_string( &N , 16 , "0D23402FB4F2988E0266EB9E0E1818FB39A76042D49A756DCE9DF1F9818D5D7BA6B274B88BAF5E3298BDCF8872B2FD6BD381A53393B460809870313E270544ED97B57414A160E795958A39258FD596DF165E73E12FC9AA7B520772A5437A2270F69CDFEBCA266598EEC9F82A6D937A81F7A91B1FB076334A827B130C1B0E0B1C1F4E5BF7E8840C599C35F451CA999F33494913813A1E4D2CC08085FDB05B" );
        //printf("%d\n",mbedtls_mpi_size(&N));
        mbedtls_mpi_read_string(&P, 16,"fac41aea0859989900da8c94ce565aaaf72d4e18b41f814e35d5ab4608aa6a22affdc044288d7a29ca5aa9ab4cf7f68883b36714d4c9751c4e42b524222db671");
        //mbedtls_mpi_read_string( &P , 16 , "3F4B5EF78E55241FBF19CFAE332679476E972CC9409A3D96CE4B87DF2A43A8B09D1C2B1D47E757839DAE741EFF5F9FFA52D3C7236E165D0D5AD08CC35235C4DDF0F1FBD4020579FB842501EBCFF679" );
        mbedtls_mpi_read_string( &Q , 16 , "fa0f073751cce74563b575065f3eb7f00c7f4e54da79460b4e6a443f3a9111feed53dc1042984a03d8596e0a33ead1e8166cce52d6d5516600652ce9d75347a1" );
        //mbedtls_mpi_read_string( &Q , 16 , "3522F8CD929A8E24A6238E44AC34CFDC7476F107590038DBCC83560F92690BCF07ACF54E88E0011CE78CECDCEB635AF1F9221E0E69E9D075750981DD1A807C340D9FBB0782EBB6F1FBD5F55303B873" );
        mbedtls_mpi_read_string( &D , 16 , "95a0caf528f1a4ba95c243612757262db4aa6d9c5a8e1f3fe5b6ebafaf5d3b9f54d9ab5847813296dc088ea689fd54d4cd0292ed20b810426a6ff8c247928825d646316a69cc1e32f1a541ba3fa401c29ee74c4540559481b1b755e5036b4c5ad1191119d6ab129aea68c6bb2d4f4156617a077d32f8c4d5ecf060b244856c01" );
        //mbedtls_mpi_read_string( &D , 16 , "A4F0A5BF32333D3890617AFED482B6760FFCF048557CE160759FBFF49BBA0D1C35EC2CF0FFE6E5211E69EFA4A7F319D7258C09B556E01C090F970F17C24057309CAA92FDFE6EE987B6A6D52740BA7C3CE88936AB06E1DA85EC5502CA86A097F1D3F8101B800BE9FB27215294744942826F1BBDDEB2186D8A43A33DFB8E49632E2CBA6F16460FBFB767EB5989FFBC33C227D9540B23C5F4235822004519" );

        mbedtls_mpi_read_string ( &E , 16 , "010001" );
        mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
        mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E );
        int status = mbedtls_rsa_complete (&rsa);

        //printf ("Status of RSA Import: %s\n" , status == 0 ? "GOOD to Go": "Failed" );
        if( ( status = mbedtls_rsa_pkcs1_sign( &rsa, NULL, NULL,
        MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 20, hash_buf, sign_buf ) ) != 0 )
        {	
            mbedtls_printf( "Failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", status );
            goto exit;
        }
    exit:  mbedtls_rsa_free(&rsa);	
        mbedtls_mpi_free( &N );
        mbedtls_mpi_free( &E );
        mbedtls_mpi_free( &P );
        mbedtls_mpi_free( &Q );
        mbedtls_mpi_free( &D );
        mbedtls_mpi_free( &DP );
        mbedtls_mpi_free( &DQ );
        mbedtls_mpi_free( &QP );
    }

    int RSA_verify(unsigned char *sign_buffer){
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

        mbedtls_mpi_read_string(&N, 16 , "f4f23ad7acdcee1c062b76f939f3112e67841d0c92a1628082e6e765c858faf3afe531fac65153a0e427828ef602c7ce2f719471072eac7d73f96bd6ec66429717d42ad166fb35509c8dfb4900fcfe49a0ea8497b032fb8cddcb03d1b2e8b65294a25ccc956f2892a68d114698ad298b9e2ebe44f024e815bd27e31839fc1411");
        //printf("%d\n",mbedtls_mpi_size(&N));
        //mbedtls_mpi_read_string( &N , 16 , "0D23402FB4F2988E0266EB9E0E1818FB39A76042D49A756DCE9DF1F9818D5D7BA6B274B88BAF5E3298BDCF8872B2FD6BD381A53393B460809870313E270544ED97B57414A160E795958A39258FD596DF165E73E12FC9AA7B520772A5437A2270F69CDFEBCA266598EEC9F82A6D937A81F7A91B1FB076334A827B130C1B0E0B1C1F4E5BF7E8840C599C35F451CA999F33494913813A1E4D2CC08085FDB05B" );
        mbedtls_mpi_read_string(&P, 16,"fac41aea0859989900da8c94ce565aaaf72d4e18b41f814e35d5ab4608aa6a22affdc044288d7a29ca5aa9ab4cf7f68883b36714d4c9751c4e42b524222db671");
        //mbedtls_mpi_read_string( &P , 16 , "3F4B5EF78E55241FBF19CFAE332679476E972CC9409A3D96CE4B87DF2A43A8B09D1C2B1D47E757839DAE741EFF5F9FFA52D3C7236E165D0D5AD08CC35235C4DDF0F1FBD4020579FB842501EBCFF679" );
        mbedtls_mpi_read_string( &Q , 16 , "fa0f073751cce74563b575065f3eb7f00c7f4e54da79460b4e6a443f3a9111feed53dc1042984a03d8596e0a33ead1e8166cce52d6d5516600652ce9d75347a1" );
        //mbedtls_mpi_read_string( &Q , 16 , "3522F8CD929A8E24A6238E44AC34CFDC7476F107590038DBCC83560F92690BCF07ACF54E88E0011CE78CECDCEB635AF1F9221E0E69E9D075750981DD1A807C340D9FBB0782EBB6F1FBD5F55303B873" );
        mbedtls_mpi_read_string( &D , 16 , "95a0caf528f1a4ba95c243612757262db4aa6d9c5a8e1f3fe5b6ebafaf5d3b9f54d9ab5847813296dc088ea689fd54d4cd0292ed20b810426a6ff8c247928825d646316a69cc1e32f1a541ba3fa401c29ee74c4540559481b1b755e5036b4c5ad1191119d6ab129aea68c6bb2d4f4156617a077d32f8c4d5ecf060b244856c01" );
        //mbedtls_mpi_read_string( &D , 16 , "A4F0A5BF32333D3890617AFED482B6760FFCF048557CE160759FBFF49BBA0D1C35EC2CF0FFE6E5211E69EFA4A7F319D7258C09B556E01C090F970F17C24057309CAA92FDFE6EE987B6A6D52740BA7C3CE88936AB06E1DA85EC5502CA86A097F1D3F8101B800BE9FB27215294744942826F1BBDDEB2186D8A43A33DFB8E49632E2CBA6F16460FBFB767EB5989FFBC33C227D9540B23C5F4235822004519" );

        mbedtls_mpi_read_string ( &E , 16 , "010001" );
        mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
        mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E );
        int status = mbedtls_rsa_complete (&rsa);

        //print("Status of RSA Import: %s\n" , status == 0 ? "GOOD to Go": "Failed" );
        if( ( status = mbedtls_rsa_pkcs1_verify( &rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
                                    MBEDTLS_MD_SHA256, 20, hash_buf, sign_buffer ) ) != 0 )
        {
            mbedtls_rsa_free(&rsa);
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
        mbedtls_rsa_free(&rsa);
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

    void on_init_complete(BLE::InitializationCompleteCallbackContext *params) {
        if (params->error != BLE_ERROR_NONE) {
            printf("Ble initialization failed.");
            return;
        }
        printf("Initialization of BLE complete\n");
        Gap::AddressType_t addr_type;
        Gap::Address_t address;
        BLE::Instance().gap().getAddress(&addr_type, address);
        int8_t devId = -1;
        for(int i=0;i<9;i++){
            uint8_t flag = 1;
            for(uint8_t j=0;j<6;j++){
                flag = flag * (address[j]==mac_addr[i][5-j]);
            }
            if(flag == 1){
                devId = i+1;
                break;
            }
        }
        deviceId = devId;
        printf("Device ID is %d\n",devId);
        print_mac_address();
        //************** Preparing Data here: *************
        // generate 8 new commands, as part of genesis block
        // propose new blocks every x amount of time
        // if(leader == DEVICEID){
        //     printf("I am the leader\n");
        //     _event_queue.call(this,&ConNode::propose_block);
        //     _event_queue.call_every(SDELTA,this,&ConNode::propose_block);
        //     //_event_queue.call_every(SDELTA,this,&ConNode::start_advertising);
        // }
        // else{
        //     printf("I am the replica\n");
        //     //_event_queue.call_every(SDELTA,this,&ConNode::blink);
        //     //_ble.gap().
        //     // BLEProtocol::Address_t addresses[1];
        //     // addresses[0].type = BLEProtocol::AddressType_t::PUBLIC;
        //     // uint8_t mac_addr[6] = {223,67,240,220,36,31};
        //     // for(int tmp = 0;tmp<6; tmp++)
        //     //     addresses[0].address[tmp] = mac_addr[tmp];
        //     // Gap::Whitelist_t wl = {};
        //     // wl.addresses = addresses;
        //     // //wl.size = 1;
        //     // ble_error_t err = _ble.gap().setWhitelist(wl);
        //     // if(err){
        //     //     print_error(err,"Whitelist error \n");
        //     // }
        //     // In E2C, the nodes can scan forever, as they do not need to vote
        //     ble_error_t err = _ble.gap().startScan((ble::scan_duration_t::forever()));
        //     if(err){
        //         print_error(err,"Scanning start error \n");
        //     }
        //     //_event_queue.call_in(DELTA,this,&ConNode::initiate_blame_process,(uint8_t )0);
        //     //timerIds.push_back(blame_event_timer);
        // }
        // every node starts scanning and wait for their turn to send messages to other nodes
        ble_error_t err = _ble.gap().startScan((ble::scan_duration_t::forever()));
        if(err){
            print_error(err,"Scanning start error \n");
        }
        // +5 is because of 
        _event_queue.call_in((deviceId)*SDELTA+5-((ND-deviceId)%ND)*1000,this,&ConNode::time_sequence);
    }

    void time_sequence(){
        // 9 nodes, so 9 nodes get to start in multiplexed intervals
        _event_queue.call(this,&ConNode::perform_action);
        // call every function begins after the specified time interval,
        // but we want the function to execute immediately and also in intervals,
        // hence the additional calls
        _event_queue.call_every(SDELTA*ND+2,this,&ConNode::perform_action);
    }

    void perform_action(){
        _event_queue.call(this,&ConNode::stopScanning);
        if(leader==deviceId){
            _event_queue.call_in(2000,this,&ConNode::propose_block);
        }
        else{
            // replicas forward message or blame or whatever seems fit
            // index 0 is for proposal messages received in the last transmission time
            if(transmission_index[0] != -1){
                printf("Transmitting proposal\n");
                int8_t trIndex = transmission_index[0];
                _event_queue.call_in(2000,this,&ConNode::transmit_data,(uint8_t *)messages[trIndex] ,(uint8_t *)signature_heap[trIndex], (uint16_t)52, (uint8_t)1);
            }
            // index 1 is for votes, this is for synchotstuff
            // if(transmission_index[1] != -1){
            //     printf("Transmitting vote\n");
            //     int8_t trIndex = transmission_index[1];
            //     _event_queue.call_in(2500,this,&ConNode::transmit_data,(uint8_t *)messages[trIndex] ,(uint8_t *)signature_heap[trIndex], (uint16_t)55, (uint8_t)4);
            // }
            // index 2 is for blame messages
            // if(transmission_index[2] != -1){
            //     printf("Transmitting blame\n");
            //     int8_t trIndex = transmission_index[2];
            //     _event_queue.call_in(5000,this,&ConNode::transmit_data,(uint8_t *)messages[trIndex] ,(uint8_t *)signature_heap[trIndex],  (uint16_t)3, (uint8_t)7);
            // }
        }
        _event_queue.call_in(6500,this,&ConNode::start_scanning); 
    }

    void verify_progress_of_leader(){
        if(unconfirmed_blocks.size() <= prev_height ){
            printf("Leader not making progress, initiating blame procedure\n");
            _event_queue.call(this,&ConNode::initiate_blame);
        }
        prev_height = unconfirmed_blocks.size();
    }

    void initiate_blame(){
        //printf("Did not receive proposal for %d seconds, initiating blame process\n",DELTA/1000);
        NPBlame *npBlame = new NPBlame;
        npBlame->ID = deviceId;
        // Type is No Progress blame
        npBlame->type = 0;
        npBlame->view = leader;
        mbedtls_sha256(npBlame->raw,NOPROGRESSBLAMESIZE,hash_buf,0);
        RSA_sign();
        // increase blame counter for current node
        blame_counter ++;
        // stop scanning first
        _event_queue.call(this,&ConNode::stopScanning);
        _event_queue.call_in(1000,this,&ConNode::transmit_data,(uint8_t *)npBlame->raw,(uint8_t *)sign_buf,(uint16_t)3,(uint8_t)4);
        //transmit_data(npBlame->raw, 3,4);
        // start scanning again
        _event_queue.call_in(7000,this,&ConNode::start_scanning);
        //leader = leader+1;
        // send blame to the new leader, broadcast it
        //_event_queue.call_every(DELTA,this,&ConNode::initiate_blame);
    }

    void print_bytes(unsigned char *ptr, int size) 
    {
        unsigned char *p = ptr;
        int i;
        for (i=0; i<size; i++) {
            stdio_mutex.lock();
            printf("%02hhX ", p[i]);
            stdio_mutex.unlock();
        }
        printf("\n");
    }

    void transmit_data(uint8_t *data,uint8_t *signature, uint16_t len, uint8_t message_type){
        //printf("Started data transmission\n");
        dout=1;
        unsigned char data_slice[PAYLOADSIZE]="";
        uint16_t time = 5;
        uint16_t seq = 0;
        uint16_t loop = 0;
        while(loop < len + PAYLOADSIZE - len%PAYLOADSIZE){
            int8_t len_msg = 0;
            int8_t flag = 0;
            if(loop==0){
                flag = 1;
            }
            for(int inn_l=0; inn_l<PAYLOADSIZE; inn_l++)
            {
                if(loop + inn_l == len)
                    break;
                data_slice[inn_l]=(unsigned char)data[inn_l+loop];
                len_msg++;
            }
            // type 1 = Proposal payload
            Payload *packet = new Payload(deviceId,message_type,flag,len_msg,seq,data_slice);
            _event_queue.call_in(time,this,&ConNode::start_advertising,packet->raw,(uint8_t)10);
            seq += 1;
            time += ADVSTARTTIME;
            loop = loop + PAYLOADSIZE;
        }
        // change type to signature
        message_type = 5;
        for(int loop = 0;loop<=SIGSIZE;loop += PAYLOADSIZE){
            int8_t len_msg = 0;
            uint8_t flag = 0;
            // send the flag once the message is over
            if(loop+PAYLOADSIZE >= SIGSIZE){
                flag = 8;
            }
            for(int inn_l=0; inn_l<PAYLOADSIZE; inn_l++)
            {
                if(loop + inn_l == SIGSIZE)
                    break;
                data_slice[inn_l]=(unsigned char)signature[inn_l+loop];
                len_msg++;
            }
            // type 1 = Proposal payload
            Payload *packet = new Payload(deviceId,message_type,flag,len_msg,seq,data_slice);
            if(packet->flag == 8){
                _event_queue.call_in(time,this,&ConNode::start_advertising,packet->raw,(uint8_t)15);   
            }
            else
                _event_queue.call_in(time,this,&ConNode::start_advertising,packet->raw,(uint8_t)10);
            seq += 1;
            time += ADVSTARTTIME;
        }
    }

    void initiate_blame_process(uint8_t seq){
        // blaming is a complicated procedure, that needs time based sequencing of 
        // transmitting intervals for each node
        if(seq == 0){
            // call this function in a while, with a new sequence number,
            // so that we can set timers for the actual blame process
            _event_queue.call_in((deviceId-1)*15000,this,&ConNode::initiate_blame_process,(uint8_t)1);
        }
        else {
            _event_queue.call_every(DELTA,this,&ConNode::verify_progress_of_leader);
        }
    }

    void handle_blame_msg(uint8_t index){
        // depending on the type of the blame message, decide what to do with it
        NPBlame *npBlame = (NPBlame *)messages[index];
        if(npBlame->type == 0){
            printf("Verified blame message from node %d\n",npBlame->ID);
            blame_counter ++;
            if(blame_counter >= F+1){
                printf("F+1 blames received, changing view...\n");
                leader = leader+1;
                blame_counter = 0;
                if(leader == deviceId){
                    printf("I am the new leader\n");
                    _event_queue.call_in(5000,this,&ConNode::start_proposal_process);
                }
            }
        }
    }

    void start_proposal_process(){
        // allow existing block timers to exhaust out
        // send certificate from this node to other nodes
        print("Sending certificate to other nodes\n");
        NPBlame *npBlame = new NPBlame;
        npBlame->ID = deviceId;
        // dummy id for a certificate of equivocating proposals
        npBlame->type = 0;
        npBlame->view = deviceId;
        mbedtls_sha256(npBlame->raw,NOPROGRESSBLAMESIZE,hash_buf,0);
        RSA_sign();
        transmit_data(npBlame->raw, (uint8_t *)sign_buf,(uint16_t) NOPROGRESSBLAMESIZE, 4);
        _event_queue.call_every(SDELTA,this,&ConNode::propose_block);
    }

    void stop_advertising(uint8_t call){
        _ble.gap().stopAdvertising(_adv_handle);
        if(call == 15){
            //printf("Start scanning for new messages\n");
            dout = 0;
        }
    }
    
    // int compute_hash(uint8_t *data,uint8_t length){
    //     static const unsigned char *tmp = (const unsigned char *) data;
    //     print_bytes((unsigned char *)data,length);
    //     unsigned char output[32];
    //     mbedtls_sha256_context ctx;
    //     // initialize
    //     mbedtls_sha256_init(&ctx);
    //     // feed into the context
    //     mbedtls_sha256_starts_ret(&ctx, 0);
    //     // feed data into buffer
    //     int l=0;
    //     while(l < length){
    //         int length_of_seg = 32;
    //         if(length-l<32){
    //             length_of_seg = length-l;
    //         }
    //         int status = mbedtls_sha256_update_ret(&ctx, tmp+l, length_of_seg*sizeof(unsigned char));
    //         l = l+32;
    //     }
    //     // write to output hash buffer
    //     memset(hash_buf,0,32);
    //     int statuscode = mbedtls_sha256_finish_ret(&ctx, output);
    //     memcpy(hash_buf, output, 32*sizeof(char));
    //     // free context
    //     mbedtls_sha256_free(&ctx);
    //     return statuscode;
    // }
    // leader only method
    void propose_block(){
        //printf("Proposing block:\n");
        //dout=1;
        //Block *blk = new Block;
        Propose *proposal = new Propose;
        //proposal->blk = *blk;
        proposal->ID = deviceId;
        proposal->view = deviceId;
        for(int tmp_lop=0;tmp_lop<8*BSIZE;tmp_lop++){
            proposal->blk.commands[tmp_lop] = (tmp_lop)%256;
        }
        // printf("Block commands generated\n");
        // genesis block
        memcpy(proposal->blk.prev_hash,chain_hash,32);
        if(BYZFLAG == 1 && chain.size() ==2){
            //proposal->blk.commands[0] = 123;
            //mbedtls_sha256(proposal->raw,PROPOSALSIZE,hash_buf,0);
            //RSA_sign();
            //transmit_data(proposal->raw, PROPOSALSIZE, 1);
            print("Proposing Equivocating block");
            proposal->blk.height = chain.size()-1;
        }
        else{
            proposal->blk.height = chain.size();
        }
        // genesis block
        chain.push_back(proposal->blk);
        //printf("Chain size: %d\n",chain.size());
        //printf("Height = %d\n",proposal->blk.height);
        static const unsigned char *tmp = (const unsigned char *) proposal->raw;
        mbedtls_sha256(proposal->raw,PROPOSALSIZE,hash_buf,0);
        //print_bytes(hash_buf, 32);
 	    // 4 KB stack
        RSA_sign();
        // calculate block hash
        static const unsigned char *tmp1 = (const unsigned char *)proposal->raw;
        mbedtls_sha256(proposal->raw,BLKSIZE,hash_buf,0);
        memcpy(chain_hash, hash_buf, 32);
        transmit_data(proposal->raw,(uint8_t *)sign_buf,PROPOSALSIZE,1);
        // Byzantine behaviour for equivocation
    }

    // Save this for SyncHotStuff
    // void cast_vote(Block blk){
    //     Vote vote(DEVICEID,leader,blk);
    //     // compute hash
    //     static const unsigned char *tmp = (const unsigned char *) vote.raw;
    //     unsigned char hash[32];
    //     mbedtls_sha256(tmp,VOTESIZE,hash_buf,0);
    //     // sign hash
    //     RSA_sign();
    //     transmit_data(vote.raw,VOTESIZE,2);
    //     // transmit signature
    //     transmit_data(sign_buf,MBEDTLS_MPI_MAX_SIZE,5);        
    // }

    void add_block_to_chain(uint8_t height){
        printf("Confirmed block at height %d\n",height);
        Block blk = unconfirmed_blocks[height];
        chain.push_back(blk);
        // this is a blocking proposal
        // successful block proposal, cancel old event timer and start new one
        // blame_event_timer = _event_queue.call_in(DELTA,this,&ConNode::initiate_blame);
    }

    // bool verify_certificate(uint8_t index){
    //     Propose *pr = (Propose *) messages[index];
    //     for(int in_loop = 0;in_loop<f+1;in_loop++){
    //         unsigned char hash[32];
    //         static const unsigned char *tmp = (const unsigned char *) pr->cert.votes[in_loop].raw;
    //         mbedtls_sha256(tmp,VOTESIZE,hash,0);
    //         // verify signature
    //         if(RSA_verify((unsigned char *)hash,
    //         (unsigned char *)pr->cert.signatures[in_loop*(MBEDTLS_MPI_MAX_SIZE)]) == 0){
    //             printf("Certificate verification failed at vote: %d\n",in_loop);
    //             return false;
    //         }
    //     }
    //     return true;
    // }

    void forward_proposal(uint8_t index){
        // copy leader's signature into the signature buffer and send it to other nodes
        memcpy(sign_buf, signature_heap[index], SIGSIZE);
        transmit_data((uint8_t *) messages[index],(uint8_t *)signature_heap[index], PROPOSALSIZE, 1);
    }

    // Vote forwarding reserved for SyncHotStuff
    // void forward_vote(uint8_t index){
    //     // forward vote
    //     transmit_data((uint8_t *)messages[index],VOTESIZE,2);
    //     transmit_data((uint8_t *)signature_heap[index],MBEDTLS_MPI_MAX_SIZE,5);
    // }

    void countdown_proposal(uint8_t index){
        // verify hash before starting countdown
        // copy block in confirmed chain
        Propose *pr = (Propose *) messages[index];
        // is it the same block sent by a different proposer or a different block at the same height
        // sent by a malicious leader?
        if(pr->ID != leader){
            // reject the block if it is not from the leader
            // or reject it if it has already been received and processed
            free_memory(index);
            return;
        }
        //printf("Verified Signature: OK\n");
        // equivocating block detected, block at this height was proposed previously
        if(chain_height >= pr->blk.height){
            printf("Equivocation detected at height %d, cancel block timer\n",chain_height);
            _event_queue.cancel(timerIds[chain_height]);
            // copy chain hash at previous height to be the chain hash
            memcpy(chain_hash,unconfirmed_blocks[chain_height].prev_hash,32);
            chain_height-= 1;
            // delete the unconfirmed block at the same height
            unconfirmed_blocks.pop_back();
            printf("Leader change from %d to %d\n",leader,leader+1);
            leader +=1;
            if(leader == deviceId){
                printf("I am the new leader\n");
                _event_queue.call_in(deviceId*SDELTA-15000,this,&ConNode::stopScanning);
                _event_queue.call_in(deviceId*SDELTA,this,&ConNode::forward_proposal,index);
                // scanning takes a while to stop
                // delay introduced so that this message can be sent reliably
                _event_queue.call_in(DELTA/2,this,&ConNode::start_proposal_process);
            }
            return;
        }
        // Verify certificates and votes of proposal
        // compute and verify hash
        if(memcmp(chain_hash,pr->blk.prev_hash,32) != 0){
            printf("Hash doesn't match previous proposal, quit view \n");
            free_memory(index);
            return;
        }
        // relay the data after verifying hash
        //transmit_data((uint8_t *)messages[index],PROPOSALSIZE,1);
        //transmit_data((uint8_t *)signature_heap[index],MBEDTLS_MPI_MAX_SIZE,5);
        Block *blk = new Block;
        memcpy(blk->prev_hash,pr->blk.prev_hash,32);
        memcpy(blk->commands,pr->blk.commands,8*BSIZE);
        blk->height = pr->blk.height;
        unconfirmed_blocks.push_back(*blk);
        chain_height +=1;
        mbedtls_sha256((uint8_t *)blk->raw,BLKSIZE,(unsigned char *)chain_hash,0);
        // cast vote
        //cast_vote(*blk);
        // after relaying the proposal, count down for \Delta seconds
        //printf("Started countdown for block %d\n",pr->blk.height);
        // enable this for transmission/relay once the countdown for this block starts here
        transmission_index[0] = index;
        int event_id = _event_queue.call_in(DELTA, this, &ConNode::add_block_to_chain, pr->blk.height);
        //free_memory(index);
        // cancel this event, in case we receive a blame/byzantine leader proof
        timerIds.push_back(event_id);
        // cancel blame timer
        _event_queue.cancel(blame_event_timer);
        // launch new blame timer
        //_event_queue.call(this,&ConNode::start_scanning);
        //_ble.gap().startScan((ble::scan_duration_t::forever()));
        //blame_event_timer = _event_queue.call_in(DELTA,this,&ConNode::initiate_blame);
    }

    void start_scanning(){
        // free memory occupied by transmission and relay messages in every scan interval
        for(int i=0;i<3;i++){
            if(transmission_index[i] != -1){
                free_memory(transmission_index[i]);
                transmission_index[i] = -1;
            }
        }
        ble_error_t err = _ble.gap().startScan(ble::scan_duration_t::forever());
        if(err){
            print_error(err, "Start scanning error\n");
        }
        //printf("Started scanning\n");
    }

    void free_memory(uint8_t index){
        delete signature_heap[index];
        delete messages[index];
        occupied[index] = 0;
        lengths[index] = 0;
        message_types[index] = 0;
    }

    void verify_signature(uint8_t index){
        // TODO: Other node's public key to be used here
        //static const unsigned char *tmp = (const unsigned char *)messages[index];
        dout=1;
        if(message_types[index] == 1){
            //forward message through a separate thread, not from here, for non-blocking calls
            //_event_queue.call_in()
            Propose *pr = (Propose *) messages[index];
            uint8_t cmp = 1;
            if(chain_height>=0)
                cmp = memcmp(pr->blk.raw, unconfirmed_blocks[chain_height].raw, (uint8_t)BLKSIZE);// block received already, return immediately
            if(cmp == 0 || leader==deviceId){
                free_memory(index);
                return;
            }
        }
        mbedtls_sha256((uint8_t *)messages[index],lengths[index],hash_buf,0);
        //compute_hash((unsigned char *)messages[index], lengths[index]);
        //print_bytes((unsigned char *)tmp, PROPOSALSIZE);
        //printf("Message Hash:\n");
        //print_bytes(hash_buf, 32);
        //mbedtls_sha256(tmp, lengths[index], hash_buf, 0);
        //print_bytes(hash_buf, 32);
        int verify =  RSA_verify((unsigned char *)signature_heap[index]);
        dout=0;
        if(verify){
            // depending on type of message, decide what to do
            if(message_types[index] == 1){
                //forward message through a separate thread, not from here, for non-blocking calls
                //_event_queue.call_in()
                if(leader != deviceId)
                    _event_queue.call(this, &ConNode::countdown_proposal, index);
                else
                    free_memory(index);
                
            }
            // blame message
            else if(message_types[index] == 4){
                //_event_queue.call(this,&ConNode::handle_blame_msg,index);
                NPBlame *np = (NPBlame *) messages[index];
                printf("Confirmed certificate from Node %d, transition to view %d\n",np->ID,np->view);
            }
            // forward vote to the leader, synchotstuff's code this is
            // else if(message_types[index] == 2){
            //     //forward vote to every other node [OR TODO: Only leader?]
            //     //forward_vote(index);
            // }
        }
        else{
            print("Signature invalid\n");
            // free memory
            free_memory(index);
        }   
    }

    void print(const char *value){
        stdio_mutex.lock();
        printf("%s\n",value);
        stdio_mutex.unlock();
    }

    virtual void onAdvertisingEnd(const ble::AdvertisingEndEvent &event){
        printf("Advertising ended\r\n");
    }

    void stopScanning(){
        ble_error_t err = _ble.gap().stopScan();
        if(err){
            print_error(err, "Stop scanning error\n");
        }
    }

    //void 

    // void start_advertising()
    // {
    //     ble_error_t error;

    //     ble::AdvertisingParameters adv_params(
    //         ble::advertising_type_t::CONNECTABLE_UNDIRECTED,
    //         ble::adv_interval_t(ble::millisecond_t(500))
    //     );

    //     error = _ble.gap().setAdvertisingParameters(_adv_handle, adv_params);

    //     if (error) {
    //         printf("_ble.gap().setAdvertisingParameters() failed\r\n");
    //         return;
    //     }

    //     _adv_data_builder.clear();
    //     _adv_data_builder.setFlags(
    //         ble::adv_data_flags_t::LE_GENERAL_DISCOVERABLE
    //         | ble::adv_data_flags_t::BREDR_NOT_SUPPORTED
    //     );
    //     _adv_data_builder.setName(DEVICE_NAME);

    //     /* Set payload for the set */
    //     error = _ble.gap().setAdvertisingPayload(
    //         _adv_handle, _adv_data_builder.getAdvertisingData()
    //     );

    //     if (error) {
    //         print_error(error, "Gap::setAdvertisingPayload() failed\r\n");
    //         return;
    //     }

    //     error = _ble.gap().startAdvertising(_adv_handle);

    //     if (error) {
    //         print_error(error, "Gap::startAdvertising() failed\r\n");
    //         return;
    //     }

    //     printf("Advertising started.\r\n");
    // }
    void start_advertising(uint8_t *data,uint8_t call) {
        dout = 1;
        ble_error_t err;
        ble::AdvertisingParameters adv_parameters(
            ble::advertising_type_t::CONNECTABLE_UNDIRECTED,
            ble::adv_interval_t(ble::millisecond_t(10)),
            ble::adv_interval_t(ble::millisecond_t(15))
        );
        mbed::Span<const uint8_t> span(data,PAYLOADSIZE + 5);
        //print_bytes((unsigned char *)span.data(), 32);
        err = _ble.gap().setAdvertisingParameters(_adv_handle, adv_parameters);
        if (err) {
            printf("_ble.gap().setAdvertisingParameters() failed\r\n");
            return;
        }
        _adv_data_builder.clear();
	    err = _adv_data_builder.setManufacturerSpecificData(span);
        if(err != 0){
               print_error(err,"Setting payload error\n");
        }
        err = _ble.gap().setAdvertisingPayload(
            _adv_handle,
            _adv_data_builder.getAdvertisingData()
        );
        err = _ble.gap().startAdvertising(_adv_handle);
	    if (err) {
            print_error(err, "_ble.gap().startAdvertising() failed");
            return;
        }
        clock_t startTime = clock();
        _event_queue.call_in(ADVSTOPTIME,this,&ConNode::stop_advertising,call);
        delete data;
    }

    uint8_t match_MAC_address(ble::address_t addr){
        for(uint8_t loop = 0;loop<9;loop++){
            uint8_t flag = 1;
            for(uint8_t i=0;i<6;i++){
                flag = flag *(addr[i]==mac_addr[loop][5-i]);
            }
            if(flag == 1){
                // it is a broadcast in synchotstuff,
                // everyone forwards to everyone else
                int8_t mod = ND;
                for(int8_t i=1;i<=K;i++){
                    int8_t control = deviceId-i<=0 ? deviceId-i+mod:deviceId-i;
                    if(control == (loop+1)){
                        return loop;
                    }
                }
                //return loop;
            }
        }
        return 255;
    }
    // advertising report
    virtual void onAdvertisingReport(const ble::AdvertisingReportEvent &event){
        //printf("Message received from address %s\n",(char *)event.getPeerAddress().data());
        //stdio_mutex.lock();
        ble::AdvertisingDataParser adv_parser(event.getPayload());
        int i=0;
        bool flag = false;
        uint8_t index = match_MAC_address(event.getPeerAddress());
        if(index == (uint8_t)255){
            return;
        }
        //printf("%d\n",index);
        PayloadFrame *payload = NULL;
        while (adv_parser.hasNext()) {
            ble::AdvertisingDataParser::element_t field = adv_parser.next();
            if(field.type == ble::adv_data_type_t::MANUFACTURER_SPECIFIC_DATA){
                payload = (PayloadFrame *) field.value.data();
                //print_bytes((unsigned char *)field.value.data(), PAYLOADSIZE + 5);
            }
            i++;
        }
        // if there is space allocated for this message
        if(occupied[index]){
            // if the message is not a signature
            if(payload->type != 5){
                // if the message matches the sequence number
                // printf("%d %d\n",payload->seq,seq[index]);
                if(payload->seq == seq[index]+1){
                    //printf("%d %d %d\n",payload->seq,seq[index],payload->len);
                    //print_bytes((unsigned char *)payload->data, PAYLOADSIZE);
                    memcpy(messages[index] + lengths[index],payload->data,payload->len);
                    lengths[index] += payload->len;
                    seq[index] += 1;
                }
                // else print sequence is missing
                else if(payload->seq > seq[index] + 1){
                    printf("Missed sequence %d\n",seq[index] + 1);
                }
            }
            // if the incoming message is a signature for the previous message
            else{
                //printf("%d %d %d\n",payload->seq,seq[index],payload->len);
                //print_bytes((unsigned char *)payload->data, PAYLOADSIZE);
                if(payload->seq - seq[index] == sig_seq[index]+1){
                    memcpy(signature_heap[index] + sig_lengths[index],payload->data,payload->len);
                    sig_lengths[index] += payload->len;
                    sig_seq[index] += 1;
                }
                else if(payload->seq > seq[index] + sig_seq[index] + 1){
                    printf("Missed sequence %d\n",sig_seq[index] + 1);
                }
                //printf("%d %d\n",payload->len,sig_lengths[index]);
            }
            // verify signature if the sequence reached it's end
            if(occupied[index] && payload->flag == 8){
                // end of the signature, verify signature
                //printf("Verifying signature\n");
                //printf("%d %d\n",lengths[index],sig_lengths[index]);
                //if(unconfirmed_blocks.size() > 0)
                //print_bytes((unsigned char *)messages[index], lengths[index]);
                //_event_queue.call(this,&ConNode::stopScanning);
                //dout=0;
                verify_signature(index);
                //_event_queue.call(this,&ConNode::verify_signature,index);
                occupied[index] = false;
                seq[index] = 0;
                sig_seq[index] = 0;
                lengths[index] = 0;
                sig_lengths[index] = 0;
                message_types[index] = 0;
            }
        }
        else{
            // allocate memory on heap and store the data
            uint16_t payloadsize = 0;
            if(payload->type == 1){
                // if it is new data
                payloadsize = PROPOSALSIZE;
                // copy message
            }
            // Blame message
            else if(payload->type == 4){
                // blame
                NPBlame *np = (NPBlame *) payload->data;
                if(np->type == 0){
                    // No progress blame
                    payloadsize = NOPROGRESSBLAMESIZE;
                }
                else if(np->type == 1){
                    // equivocation blame
                    payloadsize = EQUIVOCATIONBLAMESIZE;
                }
                // invalid type of the message
                else{
                    return;
                }
            }
            if(payload->seq != 0){
                return;   
            }
            //dout=1;
            // message memory
            messages[index] = (char *)malloc(payloadsize*sizeof(uint8_t));
            // signature memory
            signature_heap[index] = (char *)malloc(SIGSIZE*sizeof(uint8_t));
            // occupied flag
            occupied[index] = true;
            // message type flag
            message_types[index] = payload->type;
            memcpy(messages[index],payload->data,payload->len);
            lengths[index] += payload->len;
            seq[index] =0;
            sig_seq[index] = 0;
        }
        //stdio_mutex.unlock();
    }
	void blink(void) {
        printf("Blinking!!!\n");
        _led1 = !_led1;
    }
    void schedule_ble_events(BLE::OnEventsToProcessCallbackContext *context) {
        event_queue.call(Callback<void()>(&context->ble, &BLE::processEvents));
    }
    private:
        BLE &_ble;
        events::EventQueue &_event_queue;
        uint8_t _adv_buffer[ble::LEGACY_ADVERTISING_MAX_SIZE];
        ble::AdvertisingDataBuilder _adv_data_builder;
        // device id
        int8_t deviceId;
        // signature storage
        char *signature_heap[ND];
        // message storage
        char *messages[ND];
        // sequences of incoming big messages
        char seq[ND] = {0};
        // sequences of incoming signatures
        uint8_t sig_seq[ND] = {0};
        // length of the signature received till then
        uint16_t sig_lengths[ND] = {0};
        // check if the index for each node is occupied
        bool occupied[ND] = {0};
        // length of the message sent by each node
        uint16_t lengths[ND] = {0};
        // type of the message that is under occupation
        uint8_t message_types[ND];
        int8_t chain_height = -1;
        vector<Block> chain;
        vector<Block> unconfirmed_blocks;
        vector<int> timerIds;
		DigitalOut _led1;
        unsigned char *sign_buf;
        unsigned char *hash_buf;
        uint8_t prev_height;
        uint8_t blame_counter = 0;
        int8_t transmission_index[3] = {-1,-1,-1};
        int8_t transmission_sigindex[3] = {-1,-1,-1};

        uint8_t transmission_type = -1;
        ble::advertising_handle_t _adv_handle = ble::LEGACY_ADVERTISING_HANDLE;
        // uint8_t mac_addr[9][6] = {{223,67,240,220,36,31},
        //                            {246,171,75,3,235,80},
        //                           {201,71,182,141,8,230},
        //                           {209,144,134,10,89,230},
        //                           {200,20,152,75,132,78},
        //                           {215,150,143,20,201,170},
        //                           {211,43,84,236,50,74},
        //                           {242,228,238,29,220,245},
        //                           {238,103,88,38,195,251}};
};
void schedule_ble_events_l(BLE::OnEventsToProcessCallbackContext *context) {
    event_queue.call(Callback<void()>(&context->ble, &BLE::processEvents));
}
int main ()
{
    dout = 0;
	// int status = 0 , len = 0;
	// nsapi_error_t error ;
	// uint8_t msg_buf [ BUFFER_SIZE ] ;
	// uint8_t* ptr = (uint8_t*) msg_buf ;
	// status = wifiSetup () ;
	// if ( status < 0 ) {
	// 	printf ( "WiFi Error [%d]\n" , status ) ;
	// 	return status ;
	// }
	// print_info () ;
	// // Open socket
	// sock .open ( wifi ) ;
	// // Connect to socket
	// SocketAddress t1_addr ( IP , PORT ) ;
	// printf ( "Connecting to Tier 1 with IP %s, port %d\n\n" , IP , PORT ) ;
	// error = sock .connect ( t1_addr ) ;
	// if ( error != NSAPI_ERROR_OK ) {
	// 	printf ( "Connection Error [%d]\n" , error ) ;
	// 	return error ;
	// }
	// printf ( "Sending <READY> to Tier 1(IP: %s, Port: %d).\n" , IP , PORT ) ;
	// msg_buf [ 0 ] = TIER2_INIT_READY ;
	// sock .send ( msg_buf , 1 ) ;
	// printf ( "Sent Tier 1 <READY>.\n" ) ;
	// printf ( "Waiting to Receive my ID.\n" ) ;
	// len = sock .recv ( msg_buf , BUFFER_SIZE ) ;
	// myID = (uint8_t) msg_buf [ 0 ] ;
	// printf ( "My ID is %u.\n" , msg_buf [ 0 ] ) ;
	// len -= 1 ;
	// if ( len == 0 ) {
	// 	ptr = (uint8_t*) msg_buf ;
	// 	len = sock .recv ( msg_buf , BUFFER_SIZE ) ;
	// } else {
	// 	ptr += 1 ;
	// }
	// printf ( "Received %d bytes for Initial Parameters.\n" , len ) ;
	// print_params ( ptr ) ;
	// dout = (uint8_t) ptr [ 0 ] ;
	// k = (uint8_t) ptr [ 1 ] ;
	// n = (uint8_t) ptr [ 2 ] ;
	// leader = (uint8_t) ptr [ 3 ] ;
	// len -= 4 ;
	// msg_buf [ 0 ] = TIER2_CONNECT_READY ;
	// sock .send ( msg_buf , 1 ) ;
	// if ( len == 0 ) {
	// 	len = sock .recv ( msg_buf , BUFFER_SIZE ) ;
	// 	// Confirm if it is 0x03
	// }
	// printf ( "Received PROTOCOL START from Tier 1.\n" ) ;
    Thread thr(osPriorityNormal,16*1024);
    BLE &ble_l = BLE::Instance();
    ble_l.onEventsToProcess(schedule_ble_events_l);

    //BLE &ble_r = BLE::Instance();
    //ble_r.onEventsToProcess(schedule_ble_events_r);
    ConNode demo(ble_l, event_queue);
    printf("Starting node for byzantine consensus...\n");
    //demo.start();
    thr.start(callback(&demo,&ConNode::start));
    thr.join();
    //ReceiverDemo demo1(ble_r, event_queue1);
    printf("Exiting...\n");
	return 0;
}