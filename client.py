import socket
import threading
import time
import json

import crypto
import os.path
from Crypto.PublicKey import RSA
import paho.mqtt.client as mqtt

# Idea for protocol:
#	New client broadcast to network with desierd channel as search term. Using UDP
#	Any client on the network that maintains a channel matching the search term responds. Using UDP
#	The new client waits for a timeout. While waiting the client will collect responses.
#	The new client can then set up a TCP connection to one of these response clients.
#		With the TCP connection the new client shares its public key with the response client.
#		The response client then uses encrypts the symmetric key with the new clients public key.

messageTypes = {
	"HelloMessage" : {
		"type" : "Hello",
		"search" : ""
	},
	"HelloResponseMessage" : {
		"type" : "HelloResponse",
		"ip" : "",
		"found" : ""
	},
	"KeyRequestMessage" : {
		"type" : "KeyRequest",
		"topic" : ""
	},
	"StopMessage" : {
		"type" : "STOP"
	}
}

class getThreadUDP (threading.Thread):
	def __init__(self, host, port):
		super().__init__()

		self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		self.socket.bind((host, port))

		self.active = True

		self.responseList = []

	def run(self):
		while self.active:
			try:
				data, addr = self.socket.recvfrom(1024)
				message = json.loads(data.decode())
				self.handleMessage(message, addr)
			except socket.timeout:
				self.socket.settimeout(None)
				print("ResponseList")
				print(self.responseList)
				if len(self.responseList) > 0:
					symmKey = requestSymmetricKey(publicRsaKey.exportKey('PEM'), \
						self.responseList[0]['ip'], self.responseList[0]['found'], tcp_port)
					publishedChannels.append( \
						{'topic' : self.responseList[0]['found'], \
						'key' : symmKey})
				self.responseList.clear()
		self.socket.close()

	def handleMessage(self, message, addr):
		if message['type'] == 'Hello':
			print(addr[0])
			print(message['search'])
			symmKey = findChannel(message['search'])
			if symmKey != None:
				sendHelloResponseMessage(addr[0], symmKey['topic'])
		elif message['type'] == 'HelloResponse':
			print(addr[0])
			print('HelloResponseMessage received')
			print(message['found'])
			message["ip"] = addr[0]
			self.responseList.append(message)
		else:
			pass

	def stop(self):
		self.active = False
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.sendto(json.dumps(messageTypes['StopMessage']).encode(), ('127.0.0.1', udp_port))
		s.close()

class getThreadTCP (threading.Thread):
	def __init__(self, host, port):
		super().__init__()

		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind((host, port))

		self.active = True

	def run(self):
		self.socket.listen()
		while self.active:
			conn, addr = self.socket.accept()
			data = conn.recv(1024)
			message = json.loads(data.decode())
			self.handleMessage(message, addr, conn)
			conn.close()
		self.socket.close()

	def handleMessage(self, message, addr, conn):
		if message['type'] == 'KeyRequest':
			print('Key request from: ' + addr[0])
			data = conn.recv(1024)
			otherKey = RSA.importKey(data)
			symmKey = findChannel(message['topic'])
			response = b'None'
			if symmKey != None:
				response =  otherKey.encrypt(symmKey['key'], 32)
			print(len(response[0]))
			conn.sendall(response[0])
		else:
			pass

	def stop(self):
		self.active = False
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('127.0.0.1', tcp_port))
		s.sendall(json.dumps(messageTypes['StopMessage']).encode())
		s.close()

def createRsaKeys(pubFilename, privateFilename):
	if not os.path.exists(pubFilename) or not os.path.exists(privateFilename):
		print('Creating new RSA keys.')
		pubKey, privKey = crypto.generate_rsa_key()
		crypto.write_key_to_file(pubKey, pubFilename)
		crypto.write_key_to_file(privKey, privateFilename)

	pubKey = crypto.read_rsa_key_from_file(pubFilename)
	privKey = crypto.read_rsa_key_from_file(privateFilename)
	return pubKey, privKey

# Send UDP messages
def sendUdpMessage(message, ip, port):
	datagramSendSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	datagramSendSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

	messageData = json.dumps(message)

	datagramSendSocket.sendto(messageData.encode(), (ip, udp_port))
	datagramSendSocket.close()

def sendHelloMessage(search):
	udpGetThread.socket.settimeout(0.5)
	helloMessage = messageTypes['HelloMessage'].copy()
	helloMessage['search'] = search
	sendUdpMessage(helloMessage, multicast_ip, udp_port)

def sendHelloResponseMessage(ip, found):
	helloResponseMessage = messageTypes['HelloResponseMessage'].copy()
	helloResponseMessage['found'] = found
	sendUdpMessage(helloResponseMessage, ip, udp_port)

# Send TCP messages
def requestSymmetricKey(publicKey, ip, topic, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))

	message = messageTypes['KeyRequestMessage'].copy()
	message['topic'] = topic

	s.sendall(json.dumps(message).encode())
	s.sendall(publicKey)

	data = s.recv(1024)
	plainText = privateRsaKey.decrypt(data)

	s.close()
	return plainText

def findChannel(search):
	for c in publishedChannels:
		if c['topic'] == search and c['key'] != None:
			return c
	return None

def mqttConnectCallback(client, userdata, flags, rc):
	print("Connected to broker with code :" + str(rc))

def mqttPublishCallback(client, userdata, mid):
	print("Published data: " + str(mid))

def messageReceiveCallback(client, userdata, msg):
	print()
	print(msg.payload)
	key = findChannel(msg.topic)['key']
	plainText = decrypt_aes_message(msg.payload, key)
	print(plainText)
	if plainText == 'stop':
		mqttClient.disconnect()

udp_port = 666
tcp_port = 667
mqtt_port = 1883
with open('mqtt_host.txt') as f:
	mqtt_host = f.read().rstrip()
multicast_ip = "255.255.255.255"
local_ip = ''

mqttClient = mqtt.Client()
mqttClient.on_connect = mqttConnectCallback
mqttClient.on_publish = mqttPublishCallback
mqttClient.on_message = messageReceiveCallback

publishedChannels = [
	{'topic':'markus/data', 'key':None}
	]
for channel in publishedChannels:
	channel['key'] = crypto.generate_aes_key()

publicRsaKey, privateRsaKey = createRsaKeys('pub_rsa_key.pem', 'priv_rsa_key.pem')

udpGetThread = getThreadUDP('', udp_port)
tcpGetThread = getThreadTCP('', tcp_port)

udpGetThread.start()
tcpGetThread.start()

sendHelloMessage("pi3/data")
time.sleep(10)

mqttClient.connect(mqtt_host, mqtt_port, 60)

def pubTestData(num, msg, topic):
	key = findChannel(topic)['key']
	mqttClient.loop_start()
	for i in range(num):
		payload = crypto.encrypt_aes_message(msg + str(i), key)
		mqttClient.publish(topic, payload, 1)
	payload = crypto.encrypt_aes_message("stop", key)
	mqttClient.publish(topic, payload, 1)
	mqttClient.loop_stop()

def receiveTestData(topic):
	mqttClient.subscribe(topic, 1)
	mqttClient.loop_forever()

udpGetThread.stop()
print("Stopped udp thread")
tcpGetThread.stop()
print("Stopped tcp thread")

udpGetThread.join()
tcpGetThread.join()
