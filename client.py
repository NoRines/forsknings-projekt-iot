import socket
import threading
import time
import json

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
		"type" : "HelloResponse"
	},
	"StopMessage" : {
		"type" : "STOP"
	}
}

udp_port = 666
multicast_ip = "192.168.0.255"
local_ip = ''

publishedChannels = ['/bla/bahoo']

getThreadActive = True
datagramReciveSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
datagramReciveSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
datagramReciveSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
datagramReciveSocket.bind(('', udp_port))

def stopGetThread():
	global getThreadActive
	global datagramReciveSocket
	getThreadActive = False
	tmpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	tmpSocket.sendto(json.dumps(messageTypes['StopMessage']).encode(), (socket.gethostname(), udp_port))
	tmpSocket.close()
	datagramReciveSocket.close()

def getLocalIpAddress():
	global local_ip
	if len(local_ip) == 0:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("8.8.8.8", 80))
		local_ip = s.getsockname()[0]
		s.close()
	return local_ip

class getThread (threading.Thread):
	def __init__(self):
		super().__init__()
		self.responseList = []

	def run(self):
		while getThreadActive:
			try:
				data, addr = datagramReciveSocket.recvfrom(1024)
				message = json.loads(data.decode())
				self.handleMessage(message, addr)
			except socket.timeout:
				datagramReciveSocket.settimeout(None)
				print("ResponseList")
				print(self.responseList)
				self.responseList.clear()

	def handleMessage(self, message, addr):
		if message['type'] == 'Hello':
			print(addr[0])
			print(message['search'])
			if message['search'] in publishedChannels:
				sendHelloResponseMessage(addr[0])
		elif message['type'] == 'HelloResponse':
			print(addr[0])
			print('HelloResponseMessage recived')
			self.responseList.append(message)
		else:
			pass

def sendMessage(message, ip):
	datagramSendSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	datagramSendSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

	messageData = json.dumps(message)

	datagramSendSocket.sendto(messageData.encode(), (ip, udp_port))
	datagramSendSocket.close()

def sendHelloMessage(search):
	datagramReciveSocket.settimeout(0.5)
	helloMessage = messageTypes['HelloMessage'].copy()
	helloMessage['search'] = search
	sendMessage(helloMessage, multicast_ip)

def sendHelloResponseMessage(ip):
	helloResponseMessage = messageTypes['HelloResponseMessage'].copy()
	sendMessage(helloResponseMessage, ip)

thread1 = getThread()
thread1.start()

sendHelloMessage("/bla/markus")

time.sleep(4)
stopGetThread()

thread1.join()
