#client
import socket
import sys
import os
import time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
host = "192.168.0.161"
port = 8000
s.connect((host, port))
i=0
msg=str(i)
s.send(msg.encode('utf-8'))
s.close()