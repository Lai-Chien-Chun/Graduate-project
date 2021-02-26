import sys
from http.server import BaseHTTPRequestHandler ,HTTPServer ,SimpleHTTPRequestHandler
import time
import _thread
import paramiko
import http_request
import server
def connect_ssh(ip,username,passwd,cmd,sip):  
     
        ssh = paramiko.SSHClient()  
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  
        ssh.connect(ip,22,username,passwd,timeout=10,allow_agent=False,look_for_keys=False)  
        for m in cmd:  
            stdin, stdout, stderr = ssh.exec_command(m)  
            out = stdout.readlines()  
        #print('%s\解除成功\n'%(cip)) 
        ssh.close()  
      
        print ('%s\成功下指令\n'%(sip))  
def handle_ip(sip,dip,str):
	if str=='b':
	#iptable -I -t mangle PREROUTING -d 目標IP -j DROP
	#iptable -I -t mangle -d 目標IP -j DROP
		if len(sip)>0 and len(dip)>0:
			cmd=['iptables -I FORWARD -d '+dip+' -s '+sip+' -j DROP']
		elif len(sip)>0:
			cmd=['iptables -I FORWARD -s '+sip+' -j DROP']
		elif len(dip)>0:
			cmd=['iptables -I FORWARD -d '+dip+' -j DROP']
		else:
			return
	elif str=='r':
		print("release",sip)
		if len(sip)>0 and len(dip)>0:
			cmd=['iptables -D FORWARD -d '+dip+' -s '+sip+' -j DROP']
		elif len(sip)>0:
			cmd=['iptables -D FORWARD -s '+sip+' -j DROP']
		elif len(dip)>0:
			cmd=['iptables -D FORWARD -d '+dip+' -j DROP']
		else:
			return
	print(cmd)
	username = "root"  
	passwd = "12345"
	connect_ssh('192.168.0.150',username,passwd,cmd,sip)
class RequestHandler(BaseHTTPRequestHandler):
	
	def _set_response(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
	def _writehander(self):
		self.send_response(200)
		self.send_header('Content-type','text/html')
		self.end_headers()
	def do_GET(self):
		filepath = "file.html"
		self._writehander()
		#print(str(self.path), str(self.headers))
		#startTime=time.time()
		fp = open(filepath,"r",encoding='UTF-8')
		content=fp.read()
		self.wfile.write(content.encode())
		fp.close()
		#self.wfile.write(("%s<br>"%(self.path)).encode())

	def do_POST(self):
		filepath = "file.html"
		self._writehander()
		content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
		print("content_length",content_length)
		post_data = self.rfile.read(content_length) # <--- Gets the data itself
		#print(str(self.path), str(self.headers), post_data.decode('utf-8'))
		post_data=post_data.decode('utf-8')
		#print(post_data)
		st=post_data.find('&');
		if st<=0:
			return 
		print(post_data)
		
		if post_data[0:4]== "rip=":
			#print("success !!!!!!!!!!!",post_data[3:])
			handle_ip(post_data[st+5:],post_data[4:st],'r')
		elif post_data[0:4]== "bip=":
			#print("success !!!!!!!!!!!",post_data[4:])
			handle_ip(post_data[st+5:],post_data[4:st],'b')
		
		#if st>0 and post_data[st:st+5]=='srip=':
			#handle_ip(post_data[4:],'b')
		
		#self._set_response()
		fp = open(filepath,"r",encoding='UTF-8')
		content=fp.read()
		self.wfile.write(content.encode())
		fp.close()
def getip():
	
	serveraddr= ('',9001)
	ser1 = HTTPServer(serveraddr,RequestHandler)
	
	ser1.serve_forever()
_thread.start_new_thread(getip,())
_thread.start_new_thread(http_request.init,())
_thread.start_new_thread(server.init,())
server_address = ('', 9000)
httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
httpd.serve_forever()

