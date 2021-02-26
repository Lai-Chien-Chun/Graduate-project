#server
import socket
import sys
import os
import time
import _thread

def write():
	Stime=time.time()
	while 1:
		if time.time()-Stime>=9:
			fs = open('file.html','r',encoding='UTF-8')
			header=fs.readlines()
			header[33]=" //"+'\n'
			fs.close()
			fs = open('file.html','w',encoding='UTF-8')
			fs.writelines(header)
			fs.close()
			break
def init():
	serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
	port = 8000
	serversocket.bind(('192.168.0.161', port))
	serversocket.listen()
	while 1:
		
		clientsocket, addr = serversocket.accept() 
		msg = clientsocket.recv(1024)
		msg=msg.decode('utf-8')
		str='msg='+'"'+msg+'"'+';'
		f = open('file.html','r',encoding='UTF-8')
		header=f.readlines()
		header[33]="lock=1;"+str+'\n'
		f.close()
		f = open('file.html','w',encoding='UTF-8')
		f.writelines(header)
		f.close()
		print (msg)	
		clientsocket.close()
		write()


	

