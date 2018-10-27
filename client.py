import socket
import threading
import time
import json

messageTypes = {
	"HelloMessage" : {
		"type" : "Hello",
		"senderIp" : "",
	},
	"HelloResponseMessage" : {
		"type" : "HelloResponse",
		"senderIp" : "",
	},
	"StopMessage" : {
		"type" : "STOP"
	}
}

udp_port = 666
multicast_ip = "192.168.0.255"
local_ip = ''
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
	def run(self):
		while getThreadActive:
			data, addr = datagramReciveSocket.recvfrom(1024)
			message = json.loads(data.decode())
			self.handleMessage(message)

	def handleMessage(self, message):
		if message['type'] == 'Hello':
			print(message['senderIp'])
			print('HelloMessage recived')
			sendHelloResponseMessage(message['senderIp'])
		elif message['type'] == 'HelloResponse':
			print(message['senderIp'])
			print('HelloResponseMessage recived')
		else:
			pass

def sendMessage(message, ip):
	datagramSendSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	datagramSendSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

	messageData = json.dumps(message)

	datagramSendSocket.sendto(messageData.encode(), (ip, udp_port))
	datagramSendSocket.close()

def sendHelloMessage():
	helloMessage = messageTypes['HelloMessage'].copy()
	helloMessage['senderIp'] = getLocalIpAddress()
	sendMessage(helloMessage, multicast_ip)

def sendHelloResponseMessage(ip):
	helloResponseMessage = messageTypes['HelloResponseMessage'].copy()
	helloResponseMessage['senderIp'] = getLocalIpAddress()
	sendMessage(helloResponseMessage, ip)

thread1 = getThread()
thread1.start()

sendHelloMessage()

time.sleep(4)
stopGetThread()

thread1.join()
