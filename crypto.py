from Crypto.PublicKey import RSA
from Crypto import Random
import random
import time

def generate_rsa_key(bits = 2048):
	random.seed(time.time())
	rng = Random.new().read
	new_key = RSA.generate(bits, rng)
	public_key = new_key.publickey().exportKey('PEM')
	private_key = new_key.exportKey('PEM')
	return public_key, private_key

def write_key_to_file(key, filename):
	f = open(filename, 'wb')
	f.write(key)
	f.close()

def read_rsa_key_from_file(filename):
	f = open(filename, 'rb')
	key = RSA.importKey(f.read())
	f.close()
	return key
