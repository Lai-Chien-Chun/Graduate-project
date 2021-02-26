#!/usr/bin/python
#coding:utf-8
from pcapy import findalldevs, open_live
from impacket import ImpactDecoder, ImpactPacket
from scapy.all import *
import time
import math
#目標IP
SERVER_IP = '192.168.0.160'
#目標port
SERVER_PORT = [22,80,82,1097,10]
#程式執行時間
RUN_TIME = 600
#儲存檔案名稱
FILE_NAME ='t_a_sys_all.csv'
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
			if pkt.len>65536:
				self.length = 1
			else:
				self.length = -1
		#此封包是TCP
		elif TCP in pkt:
			if self.is_server_ip(self.dst)==1:
				self.port = pkt[TCP].dport#表示是目標IP記錄port
			else:
				self.port = -1#表示非目標IP不必記錄port
			self.flags = pkt[TCP].flags
			self.types = -1
			self.length = -1
		else:
			self.port = -1
			self.flags = -1
			self.types = -1
			self.length = -1
		
	def SPTF_equal(self,fetch_src,fetch_proto,fetch_time,fetch_flags):
		if fetch_time==self.time and fetch_src==self.src and fetch_proto==self.proto and fetch_flags==self.flags:
			self.account+=1
			return 1
		else:
			return 0
	#針對TCP
	#針對四個特徵值dst_ip,proto,port,flag,time
	def TCP_equal(self,fetch_proto,fetch_time,fetch_flags,fetch_port):
		 #確認三個參數是否一樣
		 if fetch_time==self.time and fetch_proto==self.proto and fetch_flags==self.flags:
			#確認是否要比較port(目標端必須是受害者IP才要記錄port)
			if self.is_server_ip(self.dst)==0 or (self.is_server_ip(self.dst)==1 and fetch_port == self.port):
				self.account+=1
				return 1
			else:
				return 0
		 else:
			return 0
	#針對ICMP
	#針對四個特徵值dst_ip,proto,type,time
	def DPTT_equal(self,fetch_dst,fetch_proto,fetch_time,fetch_type):
		if fetch_time==self.time and fetch_proto==self.proto and fetch_dst==self.dst and fetch_type==self.types:
			self.account+=1
                        return 1
		else:
			return 0
	#畫面輸出
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
		print sss
		#print str(self.pid)+":ip= "+self.src+"|protocol= "+self. protocal_decoded(self.proto)+"|time= "+str(self.time)+"| counts="+str(self.account)+"|flags= "+self.TCP_flag_decoded(self.flags)+"|length= "+str(self.length)
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
	def protocal_decoded(self,x):
		
		return{
			1:"ICMP",
			6:"TCP",
		}.get(x,"XX")
	#確認這類型封包的IP是否為目標IP
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
			for i in range(0,len(SERVER_PORT)):#確認此類型封包的port是否被警戒
				if SERVER_PORT[i]==port:
					return 1
			return -1
	#把它轉成CSV檔的格式
	def getall(self):
		return str(self.pid)+","+str(self.is_server_ip(self.dst))+","+str(self.is_server_ip(self.src))+","+str(self.proto)+","+str(self.account)+","+str(self.is_server_port(self.port))+","+str(self.flags)+","+str(self.types)+","+str(self.length)+"\n"

#a list to save packet imformation
pktt=[]
pktlen=0
pkt_newn=0
#--------------------------------------------------
#use this to sniff network
def writefile():
	global pktlen
	global pkt_newn
	print pktlen,math.ceil(time.time()-start_time)
	with open(FILE_NAME, 'a') as write_file:

		for i in range(pkt_newn,pktlen):
			write_file.write(pktt[i].getall())
			pktt[i].printf()
	pkt_newn = pktlen
def sniff():
    #fetch network card name
	interface = "eth0"

	print "Listening on: %s" % interface
	#寫入表頭
	with open(FILE_NAME, 'wt') as write_file:
		write_file.write('id,dst_ip,src_ip,proto,count,port,flag,type,length\n')
	# Open a live capture
	reader = open_live(interface, 65535, 1, 100)

	# Set a filter to be notified only for TCP packets
	reader.setfilter('ip proto \\icmp')
	#過濾器設定ip的src或dst為192.168.0.160也就是host端的
	reader.setfilter('ip dst \\'+SERVER_IP+' || ip src \\'+SERVER_IP)
	#reader.setfilter('ip dst \\'+SERVER_IP)
	# Run the packet capture loop
	run_time = start_time 
	while 1:
		#讀取下一個封包
		(hdr,data)= reader.next()
		#執行callback
		callback(hdr,data)
		if time.time()-start_time>=RUN_TIME:
			break
		if(time.time()-run_time>=1):
			run_time = time.time()
			writefile()
#顯示封包
#----------------------------
pktn=0
def pkgshow(data):
	global pktn
	print pktn
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
		
		#pkt.show()
		#取得目前class pktlen的數量
		global pktlen
		pkt_exist=0
		pkt_id=-1
		#跑整個class一遍確認有無相同的特徵存在
		for i in range(pktlen-1,0,-1):
			#TCP的封包
			if TCP in pkt:
				if pktt[i].TCP_equal(pkt[IP].proto,use_time,pkt[TCP].flags,pkt[TCP].dport):
					pkt_exist=1
					pkt_id=i
					pktt[i].src = pkt[IP].src
					break
			#ICMP
			elif ICMP in pkt:
				if pktt[i].DPTT_equal(pkt[IP].dst,pkt[IP].proto,use_time,pkt[ICMP].type):
					pkt_exist=1
					pkt_id=i
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
