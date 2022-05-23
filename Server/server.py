import socket
import json
import time
import math
import aes
import pyotp
import os
from pbkdf2 import PBKDF2

IP = "localhost"
PORT = 6663
print("Сервер ASTGS запущен!")

def hash_to_str(hash):
	result2 = bin(int(hash, base = 16))[2:]
	result2 = "0"*(256 - len(result2)) + result2
	return result2

def text_to_str(text):
	result = ""
	for i in text:
		result += f'{ord(i):08b}'
	return result

def str_to_text(string):
	result = ""
	string = string.lstrip("0")
	string = "0"*((8 - len(string) % 8) % 8) + string
	for i in range(len(string) // 8):
		result += chr(int(string[i*8:(i+1)*8], base = 2))
	return result

def generate_tgs_session_key(secret_string):
	salt = os.urandom(8)
	key = PBKDF2(secret_string, salt).read(32)
	return hash_to_str(key.hex())

def generate_service_session_key(secret_string):
	salt = os.urandom(8)
	key = PBKDF2(secret_string, salt).read(32)
	return hash_to_str(key.hex())

def initialize_totp(client, request):
	with open('server.json', 'r') as file:
		file_data = json.loads(file.read())
	if (request.find("INIT_TOTP") == -1):
		print("Incorrect initialize TOTP request accepted.")
	else:
		
		username_index = request.find("username")
		userhash_index = request.find("userhash")
		if (username_index == -1 or userhash_index == -1):
			print("Incorrect initialize TOTP request accepted.")
		else:
			username = request[username_index+8:userhash_index]
			userhash = request[userhash_index+8:]
			if (username not in file_data or username == "astgs"):
				print("initialize TOTP request with incorrect username accepted.")
			else:
				encryptor = aes.AESEncryptor()
				encryptor.INSERTKEY(hash_to_str(file_data[username]["userhash"]))
				encryptor.INSERTMODE("ECB")
				decrypted = encryptor.DECRYPT(userhash)
				if (decrypted == hash_to_str(file_data[username]["userhash"])):
					totp_key = pyotp.random_base32()
					file_data[username]["TOTPKey"] = totp_key
					totp_key = encryptor.ENCRYPT(text_to_str(totp_key))
					client.send(totp_key.encode())
					with open('server.json', 'w') as file:
						json.dump(file_data, file, indent="\t")
				else:
					print("initialize TOTP request with incorrect user hash accepted.")

def authenticate(client, addr, username):
	with open('server.json', 'r') as file:
		file_data = json.loads(file.read())
	print("authenticating...")
	client.send("KRB_ERROR".encode())
	request = client.recv(8192).decode()
	timestamp_index = request.find("timestamp")
	if (timestamp_index == -1):
		print("Incorrect authentication request accepted")
		file_data[username]["authenticated"] = 0
		with open('server.json', 'w') as file:
			json.dump(file_data, file, indent="\t")
		return "AS_FAILIncorrect authentication request"
	else:
		encrypted_timestamp = request[timestamp_index+9:]
		encryptor = aes.AESEncryptor()
		encryptor.INSERTKEY(hash_to_str(file_data[username]["userhash"]))
		encryptor.INSERTMODE("ECB")
		decrypted_timestamp = int(encryptor.DECRYPT(encrypted_timestamp), base = 2)
		timestamp = math.floor(time.time())

		request = client.recv(8192).decode()
		totp = pyotp.TOTP(file_data[username]["TOTPKey"])

		if ((abs(decrypted_timestamp - timestamp) <= 300) and (totp.now() == request)):

			file_data[username]["authenticated"] = 1
			file_data[username]["authtimestamp"] = str(math.floor(time.time()))
			with open('server.json', 'w') as file:
				json.dump(file_data, file, indent="\t")
			print("User at " + addr[0] + ":" + str(addr[1]) + " successfully authenticated")
			return "AS_SUCCESS"
		elif (abs(decrypted_timestamp - timestamp) > 300):
			print("Authentication request timestamp expired")
			file_data[username]["authenticated"] = 0
			with open('server.json', 'w') as file:
				json.dump(file_data, file, indent="\t")
			return "AS_FAILIncorrect information provided"
		print("Incorrect one-time password accepted")
		file_data[username]["authenticated"] = 0
		with open('server.json', 'w') as file:
			json.dump(file_data, file, indent="\t")	
		return "AS_FAILIncorrect information provided"

def authorize(client, addr, request):
	username_index = request.find("username")
	astgs_index = request.find("astgs")
	if (username_index == -1 or astgs_index == -1):
		print("Incorrect authorization request accepted")
	else:
		username = request[username_index + 8:astgs_index]
		astgs_requested = request[astgs_index + 5:]
		with open('server.json', 'r') as file:
			file_data = json.loads(file.read())

		if (file_data["astgs"]["principal"] != astgs_requested):
			client.send("AS_FAILWrong ASTGS Principal.".encode())
		else:

			if ((file_data[username]["authenticated"] == 0) or (math.floor(time.time()) - int(file_data[username]["authtimestamp"]) > int(file_data["astgs"]["authresettime"]))):
				authenticated = authenticate(client, addr, username)
			else:
				authenticated = "AS_SUCCESS"

			if (authenticated.find("AS_SUCCESS") != -1):

				with open('server.json', 'r') as file:
					file_data = json.loads(file.read())
					
				tgs_session_key = generate_tgs_session_key(file_data["astgs"]["serverhash"])
				file_data[username]["tgssessionkey"] = tgs_session_key
				astgs = file_data['astgs']['principal']
				tgt_lifetime = file_data['astgs']['tgtlifetime']
				encryptor = aes.AESEncryptor()
				encryptor.INSERTKEY(hash_to_str(file_data[username]["userhash"]))
				encryptor.INSERTMODE("ECB")
				userdata = encryptor.ENCRYPT(text_to_str("tgssessionkey" + tgs_session_key + "astgs" + astgs + "tgtlifetime" + tgt_lifetime))

				timestamp = math.floor(time.time())
				encryptor.INSERTKEY(hash_to_str(file_data["astgs"]["serverhash"]))

				tgt = encryptor.ENCRYPT(text_to_str("tgssessionkey" + tgs_session_key + "tgtlifetime" + tgt_lifetime + "username" + username + "timestamp" + str(timestamp)))

				client.send(("AS_REP" + "userdata" + userdata + "tgt" + tgt).encode())
				with open ('server.json', 'w') as file:
					json.dump(file_data, file, indent = "\t")
				print("User at " + addr[0] + ":" + str(addr[1]) + " successfully authorized")
			else:
				client.send(authenticated.encode())

def grant_tgs(client, addr, request):

	with open('server.json', 'r') as file:
		file_data = json.loads(file.read())

	tgt_index = request.find("tgt")
	authenticator_index = request.find("authenticator")
	if (tgt_index == -1 or authenticator_index == -1 or request.find("servicename") == -1):
		print("Incorrect TGS request accepted")
	else:
		service_name = request[18:tgt_index]
		with open('services.json', 'r') as file:
			services_data = json.loads(file.read())
		if service_name not in services_data:
			client.send("TGS_FAILIncorrect service name".encode())
		else:
			tgt = request[tgt_index+3:authenticator_index]
			authenticator = request[authenticator_index+13:]
			
			encryptor = aes.AESEncryptor()
			encryptor.INSERTKEY(hash_to_str(file_data["astgs"]["serverhash"]))
			encryptor.INSERTMODE("ECB")

			tgt = str_to_text(encryptor.DECRYPT(tgt))
			tgt_lifetime_index = tgt.find("tgtlifetime")
			username_index = tgt.find("username")
			timestamp_index = tgt.find("timestamp")
			if (tgt_lifetime_index == -1 or username_index == -1 or timestamp_index == -1):
				print("Incorrect TGT accepted")
			else:
				tgs_session_key = tgt[13:tgt_lifetime_index]
				tgt_lifetime = tgt[tgt_lifetime_index+11:username_index]
				timestamp = tgt[timestamp_index+9:]
				current_time = math.floor(time.time())

				if ((current_time - int(timestamp) <= int(tgt_lifetime)) and (current_time - int(timestamp) >= 0)):
					encryptor.INSERTKEY(tgs_session_key)
					authenticator = str_to_text(encryptor.DECRYPT(authenticator))
					timestamp_index = authenticator.find("timestamp")
					if (timestamp_index == -1):
						print("Incorrect authenticator timestamp within TGS request")
					else:
						decrypted_timestamp = int(authenticator[timestamp_index+9:])
						timestamp = math.floor(time.time())
						if (abs(timestamp-decrypted_timestamp) < 300):
							service_session_key = generate_service_session_key(file_data["astgs"]["serverhash"])
							tgs_lifetime = services_data[service_name]["tgslifetime"]
							username = authenticator[8:timestamp_index]
							
							userdata = encryptor.ENCRYPT(text_to_str("servicesessionkey" + service_session_key + "servicename" + service_name + "tgslifetime" + tgs_lifetime))
							
							encryptor.INSERTKEY(hash_to_str(services_data[service_name]["servicehash"]))
							tgs = encryptor.ENCRYPT(text_to_str("servicesessionkey" + service_session_key + "tgslifetime" + tgs_lifetime + "username" + username + "timestamp" + str(timestamp)))

							client.send(("TGS_REPuserdata" + userdata + "tgs" + tgs).encode())
						else:
							client.send("TGS_FAILAuthenticator expired.".encode())

				else:
					answer = "TGT expired"
					client.send(answer.encode())	

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((IP, PORT))
server.listen()

while True:
	client, addr = server.accept()
	request = client.recv(8192).decode()
	if (request.find("AS_REQ") != -1):
		authorize(client, addr, request)
	elif (request.find("TGS_REQ") != -1):
		grant_tgs(client, addr, request)
	elif (request.find("INIT_TOTP") != -1):
		initialize_totp(client, request)
	else:
		print("Unknown request")
