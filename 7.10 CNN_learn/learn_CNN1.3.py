import tensorflow as tf
import time
import numpy as np
#用這個去解析Csv的資料
import pandas as pd
#用這個去分割資料集為驗證和訓練
from sklearn.model_selection import train_test_split

start_time = time.time()
np.set_printoptions(precision=3) #set printing option
#1.資料的導入
#資料設定
#------------------------------------------------------

#1.1讀取train資料
data = pd.read_csv('dataset_icmp.csv',index_col=None,header=0)
data2 = pd.read_csv('dataset_tcp_ex.csv',index_col=None,header=0)
data3 = pd.read_csv('dataset_icmp2.csv',index_col=None,header=0)
data4 = pd.read_csv('nt_na_icmp.csv',index_col=None,header=0)
data5 = pd.read_csv('nt_na_tcp.csv',index_col=None,header=0)
data6 = pd.read_csv('t_a_icmp_all.csv',index_col=None,header=0)
data7 = pd.read_csv('t_a_sys_all.csv',index_col=None,header=0)
data8 = pd.read_csv('t_a_sys_o.csv',index_col=None,header=0)
data=data.append([data2,data3,data4,data5,data6,data7,data8],ignore_index=True)
print(data)

#檢視讀取的資料
#data.info()
#資料補0
data = data.fillna(0)

#1.2輸入資料X
#------------------------------------
#X = [?:8]
data_X = data[['dst_ip','src_ip','proto','count','port','flag','type','length']]
#data_X.info()
#轉變成 Numpy-array representation
data_X = data_X.as_matrix()
#print(data_X)

#1.3輸出資料Y[?,4]
#------------------------------------
#增加欄位normal為attack的相反
data['icmp_flood']=data['attack'].apply(lambda s:1 if s == 1 else 0) #lambda:一種簡單的一行函式。冒號後面接返回值
data['sys_flood']=data['attack'].apply(lambda s:1 if s == 2 else 0)
data['reset_flood']=data['attack'].apply(lambda s:1 if s == 3 else 0)
data['normal']=data['attack'].apply(lambda s:1 if s == 0 else 0)

data_Y = data[['icmp_flood','sys_flood','reset_flood','normal']]
data_Y= data_Y.as_matrix()
#print(data_Y)

#切割資料成80%的train和20%的test
X_train,X_test,Y_train,Y_test=train_test_split(data_X,data_Y,test_size=0.2,random_state=42)

#1.4建立共用函數
#-------------------------------
#權重值產生
def weight(shape):
	#產生常態隨機分布 大小為參數傳入，隨機的標準偏差為0.1

	w = tf.truncated_normal(shape,stddev=0.1)   #random_normal
	return tf.Variable(w,name='W')
#偏差值產生
def bias(shape):
	#產生一個形狀大小為shape的tensor，值全部為0.1
	
	b = tf.constant(0.1,shape=shape)
	return tf.Variable(b,name='b')
#卷積運算
def conv(x,W):
	#參數
	#x = 輸入圖像，必須是三維的Tensor
	#W參數用來帶入filter weight的權重
	#stride = 1個整數，指濾鏡每次移動時，移動幾步
	#padding = A string from: "SAME", "VALID"，表示邊界外數字的值是什麼
	return tf.nn.conv(x,W,stride=1,padding = 'SAME')

#----------------------------------

#------------------------------------------

#2正向傳播
#使用CNN模型

#2.1輸入層
#宣告輸入的神經元
#為[-1,8,1]            怎麼決定神經元的值?
#---------------------------
with tf.name_scope('Input_Layer'):#設定計算圖的名稱   #with用法:確保不管使用过程中是否发生异常都会执行必要的“清理”操作，释放资源
	X_data = tf.placeholder(tf.float32,shape=[None,8])#placehoader(type,struct)設定變數模板，等到sess.run時才會triger
	X = tf.reshape(X_data,[-1,8,1]) #shape返回行列，reshape改變維度 我覺得這裡應該是1,8,1 因為第一個是batch 參數:batch height width channel
	print("x:",X.shape)
	
	
#-----------------------------------------

#2.2第一層卷積層
#輸入X->[?,8,1] 轉成[?,1,8,1]與W1->[1,2,1,16]做卷積 輸出C1->[?,8,16]
#---------------------------
with tf.name_scope('Conv1_Layer'):
	
	W1 = weight([2,1,16])
	b1 = bias([16])
	#conv1d為covd2d但其中一維代入1
	#實際上X為[?,1,8,1](代表資料數、長、寬、通道數)
	#W1則是[1,2,1,16] (代表著長、寬、輸入通道數、輸出通道數)
	Conv1 = tf.nn.conv1d(X,W1,stride=1,padding = 'SAME')+b1  #為什麼padding要用same:使得圖像大小一致  1.stride決定步長  2.
	C1 = tf.nn.relu(Conv1)
	print("C1:",C1.shape)
	
#-----------------------------------------

#2.3第二層卷積層
#輸入C1->[?,8,16] 轉成[?,1,8,16]與W2->[1,2,16,36]做卷積 輸出C2->[?,8,36]
#---------------------------
with tf.name_scope('Conv1_Layer'):
	
	W2 = weight([2,16,36])
	b2 = bias([36])
	
	Conv2 = tf.nn.conv1d(C1,W2,stride=1,padding = 'SAME')+b2
	C2 = tf.nn.relu(Conv2)
	print("C2:",C2.shape)
	
#-----------------------------------------

#2.4平坦層
#------------------------------------
#將圖像轉成1維陣列
#輸入 C2->[?,8,36] 輸出 F1->[?,288]
with tf.name_scope('Flat_Layer'):
	F1 = tf.reshape(C2,[-1,288])
	print("F1:",F1.shape)

#------------------------------------	

#2.5輸出層
#宣告輸出的神經元
#輸入 F1->[?,288] 輸出 y_pred ->[?,4]
#---------------------------
with tf.name_scope('Output_Layer'):
	
	
	
	Wf = weight([288,4])
	bf = bias([4])
	#矩陣乘法
	#[?,288]*[288,4]+[?,4]=[?,4]
	MML = tf.matmul(F1,Wf)+bf
	#百分比的分化
	y_pred = tf.nn.softmax(MML)
	#實際結果
	Y = tf.placeholder(tf.float32,shape=[None,4]) #shape[None]:1維 
	print("y_predict:",y_pred.shape)
	
#-----------------------------------------

#3.反向傳播
#-------------------------------------------

#用代價函數求出最佳化方向以及反向傳播
#-------------------------------------------
#最佳化 y*log(y_pred)

#3.1損失函數
cross_entropy = -tf.reduce_sum(Y*tf.log(y_pred+1e-10),reduction_indices=1)
#計算所有cross_entropy平均值
cost = tf.reduce_mean(cross_entropy)

#3.2最佳化函數
#用隨機梯度下降法最小化代價進行反向傳播
train_op = tf.train.GradientDescentOptimizer(0.0001).minimize(cost)
#-------------------------------------------

#儲存模型
saver = tf.train.Saver()
#利用Session建立反覆運算的過程
with tf.Session() as sess:
	#初始化所有變數
	tf.global_variables_initializer().run()
	#反覆訓練三十次
	for epoch in range(1):
		total_loss=0.
		#反覆訓練每筆資料in X
		for i in range(len(X_train)):
			feed = {X_data:[X_train[i]],Y:[Y_train[i]]}
			#正向傳播與計算損失函數 
			_,loss = sess.run([train_op,cost],feed_dict=feed)
			#測試某個資料的過程
			if i==9002:
				print('Y',sess.run(Y,feed_dict=feed))
				print('y_pred',sess.run(y_pred,feed_dict=feed))
        
		total_loss+=loss
		print('Epoch: %04d ,total loss =%.9f' %(epoch+1,total_loss))
	

		#實際跑Test資料	
		pred =sess.run(y_pred,feed_dict={X_data:X_test})
		#計算與實際結果的準確率
		#np.argmax(data,axis)
		#表示回傳data這個形狀陣列中第axis維內的最大值的索引
		#這裡為[icmp,sys,reset,normal]->回傳裡面值較大的索引
		correct = np.equal(np.argmax(pred,1),np.argmax(Y_test,1))
		for i in range(len(correct)):
			if correct[i] == 0:
				print (i,":",pred[i],",",Y_test[i],",",X_test[i])
		#改成float
		accuracy=np.mean(correct.astype(np.float32))
		print("Accuracy on vaidation set: %.9f" %accuracy)
	print ('Training complete')
	save_path = saver.save(sess,"./CNN_model/CNN1.3_model")
end_time=time.time()
print('Time: %.9f s' %(end_time-start_time))
