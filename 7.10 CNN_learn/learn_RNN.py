#-*- coding: UTF-8 -*-
import tensorflow as tf
import pandas as pd
import numpy as ny
from sklearn.model_selection import train_test_split
import time
from tensorflow.contrib import rnn
startTime=time.time()
np.set_printoptions(precision=4)

data = pd.read_csv('dataset_icmp.csv',index_col=None,header=0)
data2 = pd.read_csv('dataset_tcp_ex.csv',index_col=None,header=0)
data3 = pd.read_csv('dataset_icmp2.csv',index_col=None,header=0)
data4 = pd.read_csv('nt_na_icmp.csv',index_col=None,header=0)
data5 = pd.read_csv('nt_na_tcp.csv',index_col=None,header=0)
data6 = pd.read_csv('t_a_icmp_all.csv',index_col=None,header=0)
data7 = pd.read_csv('t_a_sys_all.csv',index_col=None,header=0)
data8 = pd.read_csv('t_a_sys_o.csv',index_col=None,header=0)
data=data.append([data2,data3,data4,data5,data6,data7,data8],ignore_index=True)

data = data.fillna(0)

data_X = data[['dst_ip','src_ip','proto','count','port','flag','type','length']]
data_X = data_X.as_matrix()
data['icmp_flood']=data['attack'].apply(lambda s:1 if s == 1 else 0) 
data['sys_flood']=data['attack'].apply(lambda s:1 if s == 2 else 0)
data['reset_flood']=data['attack'].apply(lambda s:1 if s == 3 else 0)
data['normal']=data['attack'].apply(lambda s:1 if s == 0 else 0)

data_Y = data[['icmp_flood','sys_flood','reset_flood','normal']]
data_Y= data_Y.as_matrix()
#準備訓練的data:data_X      比對的答案:data_Y

#

#---------------------------------------

learning_rate = 0.001
batch_size = 1

# Network Parameters
n_inputs = 8 # 8 data input (shape: 1*8)
n_steps = 1 # timesteps
n_hidden_units = 128 # hidden layer num of features
n_classes = 4 # 四種結果

# tf x:input (1,8)  y:output  (1,4)
X = tf.placeholder(tf.float32, [n_steps, n_inputs])
Y = tf.placeholder(tf.float32, [n_steps, n_classes])

# Define weights
weights = 
{   #(8,128)
	'in':tf.Vairable(tf.random_normal([n_inputs,n_hidden_units])),
	#(128,4)
	'out': tf.Variable(tf.random_normal([n_hidden_units, n_classes]))
}
biases = 
{
	#(128,)
	'in':tf.Variable(tf.constant(0.1,shape=[n_hidden_units, ])),
	#(4,)
	'out': tf.Variable(tf.constant(0.1,shape=[n_classes, ]))
}


def RNN(x, weights, biases):
	#hidden layer 
    
    #x(1 steps,8 inputs)
	#X_in==(1 ,128)
	X_in=tf.matmul(x,weights['in'])+biases['in']
	
	#X_in==(1,1 steps,128 hidden)
	X_in=tf.reshape(X_in,[-1,n_steps,n_hidden_units])
	
	#cell 三維才能傳入
	lstm_cell = tf.nn.rnn_cell.BasicLSTMCell(n_hidden_units, forget_bias=1.0,state_is_tuple=True)
	#lstm cell is devided into two parts(c_state,m_state)
	_init_state = lstm_cell.zero_state(batch_size,dtype=tf.float32)
    # Get lstm cell output
	outputs, states = tf.nn.dynamic_rnn(lstm_cell, X_in, initial_state=_init_state,time_major=False)
	
	results = tf.matmul(state[1],weights['out'])+biases['out']
	#另一種做法:
	# outputs = tf.unpack(tf,transpose(outputs,[1,0,2])) #states is the last outputs
	# results = tf.matmul(outputs[-1],weights['out'])+biases['out']
	return results

pred = RNN(X, weights, biases)
# Define loss and optimizer
cost = tf.reduce_mean(tf.nn.softmax_cross_entropy_with_logits(pred,y))
train_op=tf.train.AdamOptimizer(learning_rate).minimize(cost)

correct_pred = tf.equal(tf.argmax(pred, 1), tf.argmax(y, 1))
accuracy = tf.reduce_mean(tf.cast(correct_pred, tf.float32))

# Initialize the variables (i.e. assign their default value)
init = tf.global_variables_initializer()

# Start training
with tf.Session() as sess:
	sess.run(init)

	for step in range(len(data_X)):
        #batch_x, batch_y = mnist.train.next_batch(batch_size)
        # Reshape data to get 28 seq of 28 elements
        #batch_x = batch_x.reshape((, n_steps, n_inputs))
        # Run optimization op (backprop)
        loss, train1=sess.run([cost,train_op], feed_dict={X: data_X[step], Y: data_Y[step]})
        # Calculate accuracy
		if step%2000 == 0:
			print("Step: " + str(step)+" ")
			print(sess.run(accuracy, feed_dict={feed_dict={X: data_X[step], Y: data_Y[step]}))

    print("Optimization Finished! lost :"+loss)

    # Calculate accuracy for 128 mnist test images
    # test_len = 128
    # test_data = mnist.test.images[:test_len].reshape((-1, timesteps, num_input))
    # test_label = mnist.test.labels[:test_len]
    # print("Testing Accuracy:", \
        # sess.run(accuracy, feed_dict={X: test_data, Y: test_label}))











