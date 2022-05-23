import socket
import time
import math
import hashlib
import json
import aes

CLIENT_IP = "localhost"
CLIENT_PORT = 6666
IP = "localhost"
PORT = 6663
SERVICE_PORT = 6665
REALM = "DNS.COM"
SERVICE = "youtube.com"
print("Клиент запущен!")

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

def initialize():
	password = input("Введите ваш пароль: ")
	hash_digest = hashlib.sha256(password.encode()).hexdigest()
	with open("client.json", 'r') as file:
		file_data = json.loads(file.read())
	file_data["userhash"] = hash_digest
	file_data["realm"] = REALM
	with open("client.json", 'w') as file:
		json.dump(file_data, file, indent="\t")

def authenticate(client):
	encryptor = aes.AESEncryptor()
	timestamp = math.floor(time.time())
	with open('client.json', 'r') as file:
		file_data = json.loads(file.read())
	encryptor.INSERTKEY(hash_to_str(file_data["userhash"]))
	encryptor.INSERTMODE("ECB")
	encrypted = encryptor.ENCRYPT(bin(timestamp)[2:])
	request = "AS_REQtimestamp" + encrypted
	client.send(request.encode())
	totp = input("Введите ваш одноразовый пароль: ")
	while True:
		try:
			int(totp)
		except:
			totp = input("Неверный формат ввода. Попробуйте снова: ")
		else:
			break
	client.send(totp.encode())
	answer = client.recv(8192).decode()
	return answer

def authorize():
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect((IP, PORT))
	with open('client.json', 'r') as file:
		file_data = json.loads(file.read())
	request = "AS_REQusername" + file_data["username"] + "astgs" + file_data["astgs"]
	client.send(request.encode())
	answer = client.recv(8192).decode()
	if (answer.find("KRB_ERROR") != -1):
		answer = authenticate(client)
	elif (answer.find("AS_FAIL") != -1):
		print(answer[7:] + " Authorization failed!")
		return False
	
	if (answer.find("AS_REP") != -1):
		encryptor = aes.AESEncryptor()
		encryptor.INSERTKEY(hash_to_str(file_data["userhash"]))
		encryptor.INSERTMODE("ECB")
		userdata_index = answer.find("userdata")
		tgt_index = answer.find("tgt")
		tgt = answer[tgt_index+3:]
		userdata_encrypted = answer[userdata_index+8:tgt_index]
		userdata = str_to_text(encryptor.DECRYPT(userdata_encrypted))
		astgs_index = userdata.find("astgs")
		tgt_lifetime_index = userdata.find("tgtlifetime")
		file_data["tgssessionkey"] = userdata[13:astgs_index]
		file_data["tgtlifetime"] = userdata[tgt_lifetime_index+11:]
		with open ('tgt.json', 'w') as file:
			json.dump({"tgt": tgt}, file, indent="\t")
		with open ('client.json', 'w') as file:
			json.dump(file_data, file, indent="\t")
	elif (answer.find("AS_FAIL") != -1):
		print("Authentication failed. " + answer[7:] + ".")
	client.close()

def request_tgs(service_name):
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect((IP, PORT))
	with open('client.json', 'r') as file:
		file_data = json.loads(file.read())
	with open('tgt.json', 'r') as file:
		tgt_data = json.loads(file.read())

	username = file_data["username"]
	timestamp = math.floor(time.time())
	tgs_session_key = file_data["tgssessionkey"]
	encryptor = aes.AESEncryptor()
	encryptor.INSERTKEY(tgs_session_key)
	encryptor.INSERTMODE("ECB")
	authenticator = encryptor.ENCRYPT(text_to_str("username" + username + "timestamp" + str(timestamp)))
	tgt = tgt_data["tgt"]

	request = "TGS_REQservicename" + service_name + "tgt" + tgt + "authenticator" + authenticator
	client.send(request.encode())
	answer = client.recv(8192).decode()

	if (answer.find("TGT expired") != -1):
		print("Your TGT expired. Please, request new TGT")
	elif (answer.find("TGS_FAIL") != -1):
		print(answer[8:])
	else:
		tgs_index = answer.find("tgs")
		userdata = answer[15:tgs_index]
		tgs = answer[tgs_index+3:]
		with open('servicesc.json', 'r') as file:
			servicesc_data = json.loads(file.read())
		servicesc_data[service_name]["tgs"] = tgs
		
		userdata = str_to_text(encryptor.DECRYPT(userdata))
		service_name_index = userdata.find("servicename")
		tgs_lifetime_index = userdata.find("tgslifetime")
		service_session_key = userdata[17:service_name_index]
		servicesc_data[service_name]["servicesessionkey"] = service_session_key
		with open('servicesc.json', 'w') as file:
			json.dump(servicesc_data, file, indent="\t")
	client.close()

def connect_to_service(service_name):
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect((IP, SERVICE_PORT))
	with open('servicesc.json', 'r') as file:
		servicesc_data = json.loads(file.read())
	if service_name not in servicesc_data:
		print("Wrong service name")
	else:
		service_session_key = servicesc_data[service_name]["servicesessionkey"]
		encryptor = aes.AESEncryptor()
		encryptor.INSERTKEY(service_session_key)
		encryptor.INSERTMODE("ECB")
		with open('client.json', 'r') as file:
			file_data = json.loads(file.read())
		username = file_data["username"]
		timestamp = math.floor(time.time())
		authenticator = encryptor.ENCRYPT(text_to_str("username" + username + "timestamp" + str(timestamp)))
		with open('servicesc.json', 'r') as file:
			servicesc_data = json.loads(file.read())
		tgs = servicesc_data[service_name]["tgs"]
		request = "SERVICE_AS_REQtgs" + tgs + "authenticator" + authenticator
		client.send(request.encode())
		
		totp = input("Введите ваш одноразовый пароль: ")
		while True:
			try:
				int(totp)
			except:
				totp = input("Неверный формат ввода. Попробуйте снова: ")
			else:
				break
		client.send(totp.encode())

		answer = client.recv(8192).decode()
		
		if (answer.find("TGS expired") != -1):
			print("Your TGS expired. Please, request new TGS")
		elif (answer.find("one-time") != -1):
			print("Incorrect one-time password")
		else:
			answer = str_to_text(encryptor.DECRYPT(answer))
			if (int(answer) - timestamp != 1):
				print("Service sent wrong timestamp")
			else:
				print("success")
		client.close()

while True:
	try:
		eval(input())
	except:
		print("Unknown command. Try again")