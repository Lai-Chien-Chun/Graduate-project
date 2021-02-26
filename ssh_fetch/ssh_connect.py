import paramiko  
 
def connect_ssh(ip,username,passwd,cmd,cip):  
    try:  
        ssh = paramiko.SSHClient()  
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  
        ssh.connect(ip,22,username,passwd,timeout=10,allow_agent=False,look_for_keys=False)  
        for m in cmd:  
            stdin, stdout, stderr = ssh.exec_command(m)  
            out = stdout.readlines()  
			
            #for o in out:  
                #print(o),  
        print('%s\t封鎖成功\n'%(cip)) 
        ssh.close()  
    except :  
        print ('%s\t封鎖失敗\n'%(cip))  

def ban_ip(cip,sip): 
	cmd=['iptables -I FORWARD -s '+cip+' -d '+sip+' -j DROP']
	username = "root"  
	passwd = "12345"
	connect_ssh('192.168.1.1',username,passwd,cmd,cip)
#if __name__=='__main__':  
	#ban_ip('192.168.1.140')