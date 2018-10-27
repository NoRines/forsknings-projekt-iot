import socket
import threading
import time



udp_port = 666
multicast_ip = "192.168.0.255"
running = True


class getThread (threading.Thread):
	def __init__(self, ip, port):
		threading.Thread.__init__(self)
		self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		self.s.bind(('', port))

	def run(self):
		print("Run getThread")
		while running:
			data, addr = self.s.recvfrom(1024)
			print("Message: " + data.decode())
		self.s.close()

class sendThread (threading.Thread):
	def __init__(self, ip, port):
		threading.Thread.__init__(self)
		self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		self.address = (ip, port)

	def run(self):
		print("Run sendThread")
		time.sleep(5)
		message = "Hej hej"
		print("Sending: " + message)
		self.s.sendto(message.encode(), self.address)
		print(message + " sent.")
		self.s.close()
		running = False


thread1 = getThread(multicast_ip, udp_port)
thread2 = sendThread(multicast_ip, udp_port)

thread2.start()
thread1.start()
thread2.join()
thread1.join()
