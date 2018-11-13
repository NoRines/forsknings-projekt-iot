from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import random
import time

def generate_rsa_key(bits = 2048):
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


def generate_aes_key(bits = 128):
	return Random.new().read(int(bits / 8))

def create_aes_cipher(key, iv = None):
	if iv == None:
		iv = Random.new().read(AES.block_size)
	return AES.new(key, AES.MODE_CFB, iv)

def encrypt_aes_message(plainText, key):
	cipher = create_aes_cipher(key)
	return cipher.IV + cipher.encrypt(plainText)

def decrypt_aes_message(cipherText, key):
	iv = cipherText[:AES.block_size]
	cipher = create_aes_cipher(key, iv)
	return cipher.decrypt(cipherText[AES.block_size:])

def read_aes_key_from_file(filename):
	f = open(filename, 'rb')
	key = f.read()
	f.close()
	return key
