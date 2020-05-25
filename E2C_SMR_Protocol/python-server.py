from threading import Thread
import socket

PORT = 9999
N = 9
CLIENTS = {}

def clientThread ( sock ) :
    # For every thread, get a mutex lock and add it to the clients dictionary.
    # Initialize the Tier 1 node with initialization information
    print ( "Starting thread" )
    print ( "Waiting for a message" )
    data = sock .recv ( 1024 )
    print ( "Received " , data )
    sock .send ( data )
    # open server port
    # for every client:
        # Recv bytes
        # Send whatever is received

if __name__ == "__main__" :
    servSock = socket .socket ( socket .AF_INET , socket .SOCK_STREAM )
    servSock .bind ( ( "0.0.0.0" , PORT ) )
    servSock .listen ( N )
    threads = []
    while True :
        print ( "Waiting for connections" )
        sock , conn = servSock .accept ()
        print ( "Connected to " , conn )
        client = Thread ( target = clientThread , args = ( sock ) ) 
        client .run()
        threads .append ( client )
