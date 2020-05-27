/*
 * Adithya Bhat <bhat24@purdue.edu>
 * 2020
 * */

#include "mbedtls/ecdsa.h"
#include "string.h"
#include <stdlib.h>
#include "mbed.h"

#define BUFSIZE         1024
Serial pc(SERIAL_TX, SERIAL_RX);
DigitalOut dout(D10);
unsigned char* buf ;

#define mbedtls_exit       exit
#define mbedtls_free       free

void ecp_clear_precomputed ( mbedtls_ecp_group *grp )
{
	if ( grp->T != NULL )
	{
		size_t i ;
		for( i = 0; i < grp->T_size; i++ )
			mbedtls_ecp_point_free( &grp->T[i] );
		mbedtls_free( grp->T );
	}
	grp->T = NULL;
	grp->T_size = 0;
}

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
	for ( size_t i = 0 ; i < len ; i++ ) {
		output [ i ] = 0x86;
	}

	return( 0 );
}

int main()
{ 
	dout=0;
	// mlen varies from 1 to 10000
	for(int i=1000; i<=10000; i=i+1000){
        pc.printf("Started %d loop \n",i);
	size_t mlen = i ;
	buf = ( unsigned char* ) malloc ( mlen ) ;
	mbedtls_ecdsa_context ecdsa;
	const mbedtls_ecp_curve_info *curve_info;
	size_t sig_len;
	unsigned char tmp[200];
	int ret;

	memset( buf, 0x2A, sizeof( buf ) );
// All possible curves
//typedef enum
   //78 {
   //79     MBEDTLS_ECP_DP_NONE = 0,       
   //80     MBEDTLS_ECP_DP_SECP192R1,      
   //81     MBEDTLS_ECP_DP_SECP224R1,      
   //82     MBEDTLS_ECP_DP_SECP256R1,      
   //83     MBEDTLS_ECP_DP_SECP384R1,      
   //84     MBEDTLS_ECP_DP_SECP521R1,      
   //85     MBEDTLS_ECP_DP_BP256R1,        
   //86     MBEDTLS_ECP_DP_BP384R1,        
   //87     MBEDTLS_ECP_DP_BP512R1,        
   //88     MBEDTLS_ECP_DP_CURVE25519,     
   //89     MBEDTLS_ECP_DP_SECP192K1,      
   //90     MBEDTLS_ECP_DP_SECP224K1,      
   //91     MBEDTLS_ECP_DP_SECP256K1,      
   //92     MBEDTLS_ECP_DP_CURVE448,       
   //93 } mbedtls_ecp_group_id;
   //94 
	// MBEDTLS_ECP_DP_SECP192R1
	mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_SECP256R1;
	curve_info = mbedtls_ecp_curve_info_from_grp_id(grp_id);

	mbedtls_ecdsa_init( &ecdsa );

	if( mbedtls_ecdsa_genkey( &ecdsa, curve_info->grp_id, myrand, NULL ) != 0 )
	{
		//fprintf (stdout, "Key generation failed\n");
		mbedtls_exit( 1 );
	}
	ecp_clear_precomputed( &ecdsa.grp );

	// Start measuring here
	
	ret = mbedtls_ecdsa_write_signature( &ecdsa, MBEDTLS_MD_SHA256, buf, curve_info->bit_size,
			tmp, &sig_len, myrand, NULL  );
	// Stop measuring here
	dout=0;

	ecp_clear_precomputed( &ecdsa.grp );
	// Start measuring here
        dout=1;
	ret = mbedtls_ecdsa_read_signature( &ecdsa, buf, curve_info->bit_size,
			tmp, sig_len  );
        dout=0;
	// Stop measuring here

	mbedtls_ecdsa_free( &ecdsa );
}//loop
        pc.printf("Done \n");
}
