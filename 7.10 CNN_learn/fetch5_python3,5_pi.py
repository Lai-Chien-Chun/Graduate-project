#!/usr/bin/python
#coding:utf-8
from pcapy import findalldevs, open_live
import _thread
from scapy.all import *
import time
import math

#目標IP
SERVER_IP = '192.168.1.13'
#目標port
SERVER_PORT = [22,80,81]
#程式執行時間
RUN_TIME = 10
#儲存檔案名稱
FILE_NAME ='all.csv'
#--------------------------------------------------
#start time
#程式開始的時間
start_time=time.time()
#define packet_type class

#--------------------------------------------------
#一個class以一秒鐘為單位記錄封包的整體狀態
class Packet_Type:
	#define 初始化
	#constructor
	#--------------------------------------------
	def __init__(self,pid,timest,pkt):
		#id,time用來記錄先後順序
		self.pid = pid
		self.time = timest
		#IP上的重要特徵
		self.src = pkt.src
		self.dst = pkt.dst
		self.proto = pkt.proto
		
		#記錄數量
		self.account = 1
		
		#此封包是ICMP
		if ICMP in pkt:
			self.types = pkt[ICMP].type
			self.port = -1
			self.flags = -1
			#記錄長度
			#記錄長度
			if pkt.len>65536:
				self.length = 1
			else:
				self.length = -1
		
		#此封包是TCP
		elif TCP in pkt:
			if self.is_server_ip(self.dst)==1:#表示是目標IP記錄port
				self.port = pkt[TCP].dport
			else:#表示非目標IP不必記錄port
				self.port = -1
			self.flags = pkt[TCP].flags
			self.types = -1
			self.length = -1#非ICMP不必記錄長度
		else:
			self.port = -1
			self.flags = -1
			self.types = -1
			self.length = -1#非ICMP不必記錄長度
	#----------------------------------------------------------
	
	#封包比較
	#--------------------------------------------------------------
	#針對IP
	#針對三個特徵值dst_ip,proto,time
	def IP_equal(self,fp,ft):
		if ft ==self.time and fp.proto==self.proto and fp.dst==self.dst:
			if ICMP in fp:
				return self.ICMP_equal(fp)
			elif TCP in	fp:
				return self.TCP_equal(fp)
			else:#不明的封包
				return 0
	#針對TCP
	#針對兩個特徵值port,flag
	def TCP_equal(self,fp):
		 #確認四個參數是否一樣
		if fp[TCP].flags==self.flags:
			#確認是否要比較port(目標端必須是受害者IP才要記錄port)
			if self.is_server_ip(self.dst)==0 or (self.is_server_ip(self.dst)==1 and fp[TCP].dport == self.port):
				return 1
			else:
				return 0
		else:
			return 0
	#針對ICMP
	#針對兩個特徵值type,length
	def ICMP_equal(self,fp):
		if fp[ICMP]==self.types and fp.len==self.length:
			return 1
		else:
			return 0
	#--------------------------------------------------------------
	
	#畫面輸出與解碼
	#----------------------------
	def printf(self):
		ssID = "id= "+str(self.pid).zfill(3)+"| time= ",str(self.time).zfill(5)
		ssIP = "|sip= "+self.src+"|dip= "+self.dst+"|protocol= "+self.protocal_decoded(self.proto)
		ssTCP = "| port="+str(self.port)+"|flags= "+self.TCP_flag_decoded(self.flags).rjust(2)
		ssICMP = "|type="+str(self.types)
		ssOL ="|counts="+str(self.account) +"|length= "+str(self.length)
		#if self.account!=1:
		#	sss=ssid+ssIP+ssTCP+ssICMP+ssOL+"|!!"
		#else:
		sss=str(ssID)+str(ssIP)+str(ssTCP)+str(ssICMP)+str(ssOL)
		print(sss)
		#print str(self.pid)+":ip= "+self.src+"|protocol= "+self. protocal_decoded(self.proto)+"|time= "+str(self.time)+"| counts="+str(self.account)+"|flags= "+self.TCP_flag_decoded(self.flags)+"|length= "+str(self.length)
	#flag的解碼
	def TCP_flag_decoded(self,x):
		
		return{
			17:"FA",
			16:"A",
			24:"PA",
			18:"SA",
			20:"RA",
			4:"R",
			2:"S"
		}.get(x,"XX")	
	#協定的解碼
	def protocal_decoded(self,x):
		
		return{
			1:"ICMP",
			6:"TCP",
		}.get(x,"XX")
	#------------------------------------
	
	#確認這類型封包的IP是否為目標IP
	#---------------------------------------------
	def is_server_ip(self,ip):
		if ip ==SERVER_IP:
			return 1
		else:
			return 0
	#確認這類型封包的port是否為目標port
	def is_server_port(self,port):
		#如果此IP port 為 -1 表示它不在目標ip內
		if port == -1:
			return -1
		else:
			for i in range(len(SERVER_PORT)):#確認此類型封包的port是否被警戒
				if SERVER_PORT[i]==port:
					return 1
			return -1
	#------------------------------------
	#把它轉成CSV檔的格式
	#------------------------------------
	def getall(self):
		return str(self.pid)+","+str(self.is_server_ip(self.dst))+","+str(self.is_server_ip(self.src))+","+str(self.proto)+","+str(self.account)+","+str(self.is_server_port(self.port))+","+str(int(self.flags))+","+str(self.types)+","+str(self.length)+"\n"

	#------------------------------------

#a list to save packet imformation
pktt=[]
pktlen=0
pkt_newn=0
#寫入檔案
#--------------------------------------------------
#use this to sniff network
def writefile():
	global pktlen
	global pkt_newn
	print (pktlen,math.ceil(time.time()-start_time))
	
	with open(FILE_NAME, 'a') as write_file:

		for i in range(pkt_newn,pktlen):
			write_file.write(pktt[i].getall())
			pktt[i].printf()
	pkt_newn = pktlen
#-------------------------------------------------
end_program = 0
def one_second_write():

	global end_program
	run_time = start_time 	
	while end_program==0:
		if time.time()-start_time>=RUN_TIME:
			end_program=1
		if(time.time()-run_time>=1):
			run_time = time.time()
			writefile()
def sniff():
    #fetch network card name
	interface = "wlan0"

	print ("Listening on: %s" % interface)
	#寫入表頭
	with open(FILE_NAME, 'wt') as write_file:
		write_file.write('id,dst_ip,src_ip,proto,count,port,flag,type,length\n')
	# Open a live capture
	reader = open_live(interface, 65535, 1, 100)

	# Set a filter to be notified only for TCP packets
	#reader.setfilter('ip proto \\icmp')
	#過濾器設定ip的src或dst為192.168.0.160也就是host端的
	#reader.setfilter('ip dst \\'+SERVER_IP+' || ip src \\'+SERVER_IP)
	#reader.setfilter('ip dst \\'+SERVER_IP)
	# Run the packet capture loop

	#用新的thread去計時間並一秒寫一次檔案
	_thread.start_new_thread(one_second_write,())
	while end_program==0:
		#讀取下一個封包
		(hdr,data)= reader.next()
		#執行callback
		callback(hdr,data)
			
#顯示封包
#----------------------------
pktn=0
def pkgshow(data):
	global pktn
	print (pktn)
	data.show()
	pktn+=1

#封包截取
#---------------------------
def callback(hdr, data):
	#use_time:capture packet time
	#取得時間值的整數化
	use_time=math.ceil(time.time()-start_time)
	pkt = Ether(data)
	#當pkt有IP這層的協議時，一般都會有
	if IP in pkt:
		#pkgshow(pkt)
		#print pkt[TCP].flags

		#取得目前class pktlen的數量
		global pktlen
		pkt_exist=0
		pkt_id=-1
		#跑整個class一遍確認有無相同的特徵存在
		for i in range(pktlen-1,0,-1):
			#從ip層先比
			if pktt[i].IP_equal(pkt[IP],use_time):
				pkt_exist=1
				pkt_id=i
				pktt[i].account+=1
				break

		#表示沒有相同特徵的封包類型		
		if pkt_exist==0:
			pktt.append(Packet_Type(pktlen,use_time,pkt[IP]))	
			pkt_id=pktlen
			pktlen+=1
		#pktt[pkt_id].printf()
		
def main():
    sniff()
    #writefile()
if __name__ == "__main__":
    main()
