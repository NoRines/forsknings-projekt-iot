import socket
import threading
import time

udp_port = 666
multicast_ip = "192.168.0.255"
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
	tmpSocket.sendto("STOP".encode(), (socket.gethostname(), udp_port))
	tmpSocket.close()
	datagramReciveSocket.close()

class getThread (threading.Thread):
	def run(self):
		while getThreadActive:
			data, addr = datagramReciveSocket.recvfrom(1024)
			if len(data.decode()) > 0 and data.decode() != 'STOP':
				print("Message: " + data.decode())


datagramSendSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
datagramSendSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

thread1 = getThread()
thread1.start()

message = "HEJ SLGKJSLGKJSLHKFDJSLDKHJLKJ"
datagramSendSocket.sendto(message.encode(), (multicast_ip, udp_port))
datagramSendSocket.close()
stopGetThread()

thread1.join()
