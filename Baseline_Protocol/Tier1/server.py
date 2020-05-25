#!/usr/bin/python3

from utils  import *
from config import *
from msg    import *

from threading import Thread
import select
import signal

def client_setup ( sock , tid ) :
    # For every thread, get a mutex lock and add it to the clients dictionary.
    # Initialize the Tier 1 node with initialization information
    Log ( "Waiting for Tier 2 Node #%d" % ( tid , ) )
    while True :
        data = sock .recv ( 1024 )
        if len(data) == 1 and bytes_to_int ( data ) == READY: 
            break
    Log ( "Received <READY> from Tier 2 Node #%d" % ( tid , ) )


def get_key ( obj , val ) :
    for k, v in obj .items () :
        if v == val :
            return k
    return None


class t1_ctx :
    def __init__ ( self ) :
        self .CLIENT_SOCKETS = {}
        self .CLIENT_ADDR = {}
        self .servSock = None
        self .timeout = True

    def handle_timeout ( self , signum , frame ) :
        self .timeout = not self .timeout

    def setup ( self ) :
        self .servSock = socket .socket ( socket .AF_INET , socket .SOCK_STREAM )
        self .servSock .bind ( ( "0.0.0.0" , PORT ) )
        self .servSock .listen ( N )
        Log ( "Waiting for Tier 2 nodes to join the system." )
        threads = []
        for i in range ( 1 , N+1 ) :
            sock , conn = self .servSock .accept ()
            Log ( "Incoming Connection from: " , conn )
            self .CLIENT_SOCKETS [ i ] = sock
            self .CLIENT_ADDR [ i ] = conn
            client = Thread ( target = client_setup , args = ( sock , i , ) ) 
            threads .append ( client )
            client .run ()
        for i in range ( 1 , N+1 ) :
            if threads [ i-1 ] .is_alive() :
                threads [ i-1 ] .join ()
        Log ( "All Tier 2 nodes are ready." )
        Log ( "Initializing Tier 2 nodes." )
        for i in range ( 1 , N + 1 ) :
            msg = self .CLIENT_SOCKETS [ i ] .recv (1024)
            while ( bytes_to_int ( msg ) != 0x02 ) :
                msg = self .CLIENT_SOCKETS [ i ] .recv (1024)
            Log ( "Received <READY-II> from Tier 2 - Node %d" % ( i ) )
        Log ( "Tier 2 nodes ready for diffusion." )
        for i in range ( 1 , N + 1 ) :
            self .CLIENT_SOCKETS [ i ] .send ( int_to_bytes ( 0x03 ) )
            Log ( "Sent <READY-II> to Tier 2 - Node %d" % ( i ) )
        i = 1
        while ( i < N + 1 ) :
            msg = self .CLIENT_SOCKETS [ i ] .recv ( 1024 )
            if ( len (msg) == 1 and msg [ 0 ] == 0x06 ) :
                # Log ( "Protocol End for Node - #%d [By Signal]" % ( i ) )
                continue
            if ( msg [ 0 ] == 0x06 ) :
                # Log ( "Protocol End for Node - #%d" % ( i ) )
                msg = msg [ 1 : ]
            Log ( "Node #%d committing to [ %s ]" % ( i , msg ) )
            i += 1

    def shutdown ( self ) :
        for i in range ( 1 , N+1 ) :
            self .CLIENT_SOCKETS [ i ] .close ()
        self .servSock .close ()
        self .servSock = None

if __name__ == "__main__" :
    t1 = t1_ctx ()
    t1 .setup ()
    t1 .shutdown ()
