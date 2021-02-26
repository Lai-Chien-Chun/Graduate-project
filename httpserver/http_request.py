import requests
import time
import os
import paramiko  
new_data=''

def savefile(s):
	try:
		f = open('temp.txt','w')
		f.write(s)
		f.close()
	except:
		return
def subfind(sss,start,end):
	#整理好的資訊
	global new_data
	#找到起點
	st = sss.find('<td>',start)
	#找到終點
	en = sss.find('</td>',end)
	if st==-1 or en==-1:
		return
	else:
		#print(st,en,sss[st+4:en])
		#控制換行
		if len(new_data)==0 or new_data[len(new_data)-1]=='\n':
			new_data=new_data+sss[st+4:en]
		else:
			new_data=new_data+','+sss[st+4:en]
		subfind(sss,st+1,en+1)
#找到forward table 內的所有rule
def rulefind(forward):
	global new_data
	#紀錄每個rule的起點
	rule_start=[]
	rule_start.append(0)
	for i in range(1,20):
		p =forward.find('cbi-section-table-row cbi-rowstyle',rule_start[i-1]+1)
		rule_start.append(p)
		if i>=2:
			#print('######################')
			#print(forward[rule_start[i-1]:rule_start[i]])
			rule=forward[rule_start[i-1]:rule_start[i]]
			subfind(rule,0,0)
			new_data=new_data+'\n'
		if p==-1:
			break
	#print(new_data)
	savefile(new_data)
def write_filter(text,arp):
	try:
		start=text.find("Table: Filter")
		end=text.find("References: 1")
		#MangoSatrt=text.find("Table: Mangle")
		#MangoEnd=text.find("Table: Raw")
		arp_start=arp.find("ARP")
		arp_end=arp.find('-Routes')
	
		f = open('file.html','r+',encoding='UTF-8')
		header=f.readlines()
		header=header[:99]
		#print(text)
		header.append(text[start+18:end-250])
		#+text[MangoSatrt:MangoEnd]
		f.close()
		f = open('file.html','w+',encoding='UTF-8')
		f.writelines(header)
		f.writelines('<SCRIPT language="JavaScript">window.setInterval(PlaySound, 6000); </SCRIPT>')
		f.writelines("</table>")
		f.writelines("</div>")
		f.writelines("</body>")
		f.close()
		print("write filter success")
		
		farp = open('farp.html','r+',encoding='UTF-8')
		header=farp.readlines()
		header=header[:54]
		farp.close()
		header.append(arp[arp_start+13:arp_end-160])
		farp = open("farp.html","w",encoding='UTF-8')
		farp.writelines(header)
		farp.writelines("</table>")
		farp.writelines("</div>")
		farp.writelines("</div>")
		farp.writelines("</body>")
		farp.close()
		print("write arp success")
	except:
		print("write file error")
def superme_filter(text,arp):
	try:
		start=text.find("Table: Filter")
		end=text.find("References: 3")
		#MangoSatrt=text.find("Table: Mangle")
		#MangoEnd=text.find("Table: Raw")
		arp_start=arp.find("ARP")
		arp_end=arp.find('-Routes')
	
		f = open('supermeFilter.html','r',encoding='UTF-8')
		header=f.readlines()
		header=header[:54]
		#print(text)
		header.append(text[start+18:end-250])
		#+text[MangoSatrt:MangoEnd]
		# f.close()
		F = open('supermeFilter.html','w',encoding='UTF-8')
		F.writelines(header)
		
		F.writelines("</table>")
		F.writelines("</div>")
		F.writelines("</body>")
		F.close()
		print("write superme filter success")
		
		farp = open('supermeARP.html','r+',encoding='UTF-8')
		header=farp.readlines()
		header=header[:54]
		farp.close()
		header.append(arp[arp_start+13:arp_end-160])
		farp = open("supermeARP.html","w",encoding='UTF-8')
		farp.writelines(header)
		farp.writelines("</table>")
		farp.writelines("</div>")
		farp.writelines("</div>")
		farp.writelines("</body>")
		farp.close()
		print("write superme arp success")
	except:
		print("write superme error")
def read_superme():
	my_data = [['luci_username', 'root'], ['luci_password', '12345']]
	url ='http://192.168.0.143/cgi-bin/luci/'
	ip_url = 'http://192.168.0.143/cgi-bin/luci/admin/status/iptables'
	arp_url="http://192.168.0.143/cgi-bin/luci/admin/status/routes"
	r = requests.post(url,data = my_data)
	ip = requests.post(ip_url,data = my_data)
	arp1=requests.post(arp_url,data = my_data)
	#print(arp.text)
	text = ip.text
	#print(text)
	superme_filter(text,arp1.text)
def read_html():
	#print("ok")
	my_data = [['username', 'root'], ['password', '12345']]
	url ='http://192.168.0.150/cgi-bin/luci/;stok=e428fd16eeb8c3c7b4f058be08d40290/admin/status/iptables'
	arp_url="http://192.168.0.150/cgi-bin/luci/;stok=1f94f6c6df9dcdb9ad74c5c301c9eaf7/admin/status/routes"
	r = requests.post(url,data = my_data)
	arp=requests.post(arp_url,data = my_data)
	#print(arp.text)
	texts = r.text
	write_filter(texts,arp.text)
	
	#過濾filter table把forward table的內容抓取出來
	start = r.text.find('rule_filter_FORWARD',0)
	end = r.text.find('rule_filter_OUTPUT',0)
	forward = r.text[start:end]
	rulefind(forward)
	
def init():
	run_time=time.time()
	
	while 1:
		#每三秒更新一次
		if time.time()-run_time>=3:
			new_data=''
			
			read_html()
			#read_superme()
			run_time=time.time()
			#print('更新')