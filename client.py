import socket
import threading
import time
import json

import crypto
import os.path
from Crypto.PublicKey import RSA

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
		"ip" : ""
	},
	"KeyRequestMessage" : {
		"type" : "KeyRequest",
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
					test = requestSymmetricKey(publicRsaKey.exportKey('PEM'), self.responseList[0]["ip"], tcp_port)
					print(test)
				self.responseList.clear()
		self.socket.close()

	def handleMessage(self, message, addr):
		if message['type'] == 'Hello':
			print(addr[0])
			print(message['search'])
			if message['search'] in publishedChannels:
				sendHelloResponseMessage(addr[0])
		elif message['type'] == 'HelloResponse':
			print(addr[0])
			print('HelloResponseMessage received')
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
		self.socket.close()

	def handleMessage(self, message, addr, conn):
		if message['type'] == 'KeyRequest':
			print('Key request from: ' + addr[0])
			data = conn.recv(1024)
			otherKey = RSA.importKey(data)
			response =  otherKey.encrypt(b'Halloj', 32)
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


udp_port = 666
tcp_port = 667
multicast_ip = "192.168.0.255"
local_ip = ''

publishedChannels = ['/markus/data']

def createRsaKeys(pubFilename, privateFilename):
	if not os.path.exists(pubFilename) or not os.path.exists(privateFilename):
		print('Creating new RSA keys.')
		pubKey, privKey = crypto.generate_rsa_key()
		crypto.write_key_to_file(pubKey, pubFilename)
		crypto.write_key_to_file(privKey, privateFilename)

	pubKey = crypto.read_rsa_key_from_file(pubFilename)
	privKey = crypto.read_rsa_key_from_file(privateFilename)
	return pubKey, privKey

publicRsaKey, privateRsaKey = createRsaKeys('pub_rsa_key.pem', 'priv_rsa_key.pem')

udpGetThread = getThreadUDP('', udp_port)
tcpGetThread = getThreadTCP('', tcp_port)

def getLocalIpAddress():
	global local_ip
	if len(local_ip) == 0:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("8.8.8.8", 80))
		local_ip = s.getsockname()[0]
		s.close()
	return local_ip

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

def sendHelloResponseMessage(ip):
	helloResponseMessage = messageTypes['HelloResponseMessage'].copy()
	sendUdpMessage(helloResponseMessage, ip, udp_port)

# Send TCP messages
def requestSymmetricKey(publicKey, ip, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))

	message = messageTypes['KeyRequestMessage'].copy()

	s.sendall(json.dumps(message).encode())
	s.sendall(publicKey)

	data = s.recv(1024)
	plainText = privateRsaKey.decrypt(data)

	s.close()
	return plainText

udpGetThread.start()
tcpGetThread.start()

sendHelloMessage("/pi/data")

time.sleep(10)
udpGetThread.stop()
print("Stopped udp thread")
tcpGetThread.stop()
print("Stopped tcp thread")

udpGetThread.join()
tcpGetThread.join()
