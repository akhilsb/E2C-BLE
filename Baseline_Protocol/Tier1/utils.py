#!/usr/bin/python3 

"""

Author Information:
 Adithya Bhat
 Purdue University
 <bhat24@purdue.edu>
 2020

"""

import struct
import socket

def Log (*args) :
    print ( "[INFO]: " , *args )

def int_to_bytes ( num ) :
    return struct.pack ( "B" , num )

def bytes_to_int ( byte ) :
    return struct.unpack ( "B" , byte ) [ 0 ]

def ip_to_bytes ( ip ) :
    return socket.inet_aton ( ip )

def bytes_to_ip ( byte ) :
    return struct.unpack ( "!L" , byte ) [ 0 ]
