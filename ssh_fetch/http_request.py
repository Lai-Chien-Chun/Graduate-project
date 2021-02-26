import requests
import time
new_data=''

def savefile(s):
	try:
		f = open('temp','w')
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
	print(new_data)
	savefile(new_data)
def read_html():
	my_data = [['username', 'root'], ['password', '12345']]
	url ='http://192.168.1.1/cgi-bin/luci/;stok=e428fd16eeb8c3c7b4f058be08d40290/admin/status/iptables'
	r = requests.post(url,data = my_data)
	#print(r.text)
	texts = r.text
	#過濾filter table把forward table的內容抓取出來
	start = r.text.find('rule_filter_FORWARD',0)
	end = r.text.find('rule_filter_OUTPUT',0)
	forward = r.text[start:end]
	rulefind(forward)

run_time=time.time()
while 1:
	#每三秒更新一次
	if time.time()-run_time>=3:
		new_data=''
		read_html()
		run_time=time.time()
		print('更新')