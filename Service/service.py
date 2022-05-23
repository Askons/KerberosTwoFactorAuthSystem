import socket
import json
import time
import math
import pyotp
import aes

IP = "localhost"
SERVICE_PORT = 6665
SERVICE_NAME = "youtube.com"
print("Сервис запущен!")

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

def key_exchange(client, addr, request):
	with open('service.json', 'r') as file:
		file_data = json.loads(file.read())
	encryptor = aes.AESEncryptor()
	encryptor.INSERTKEY(hash_to_str(file_data[SERVICE_NAME]["servicehash"]))
	encryptor.INSERTMODE("ECB")

	authenticator_index = request.find("authenticator")
	if (authenticator_index == -1):
		print("Incorrect key exchange request accepted")
	else:
		tgs = request[17:authenticator_index]
		authenticator = request[authenticator_index+13:]

		tgs = str_to_text(encryptor.DECRYPT(tgs))
		tgs_lifetime_index = tgs.find("tgslifetime")
		username_index = tgs.find("username")
		timestamp_index = tgs.find("timestamp")
		if (tgs_lifetime_index == -1 or username_index == -1 or timestamp_index == -1):
			print("Incorrect TGS accepted")
		else:
			service_session_key = tgs[17:tgs_lifetime_index]
			tgs_lifetime = tgs[tgs_lifetime_index+11:username_index]
			timestamp = tgs[timestamp_index+9:]
			current_time = math.floor(time.time())
			if ((current_time - int(timestamp) <= int(tgs_lifetime)) and (current_time - int(timestamp) > 0)):
				username = tgs[username_index+8:timestamp_index]
				file_data[username]["servicesessionkey"] = service_session_key
				with open('service.json', 'w') as file:
					json.dump(file_data, file, indent="\t")

				encryptor.INSERTKEY(service_session_key)

				authenticator = str_to_text(encryptor.DECRYPT(authenticator))
				auth_timestamp_index = authenticator.find("timestamp")
				if (auth_timestamp_index == -1 or authenticator.find("username") == -1):
					print("Incorrect authenticator accepted")
				else:
					auth_timestamp = authenticator[auth_timestamp_index+9:]
					timestamp = math.floor(time.time())
					if (int(timestamp) - int(auth_timestamp) <= 300 and int(timestamp) - int(auth_timestamp) >= 0):
						client_totp = client.recv(8192).decode()
						totp = pyotp.TOTP(file_data[username]["TOTPKey"])
						if (client_totp == totp.now()):
							answer = encryptor.ENCRYPT(text_to_str(str(int(auth_timestamp) + 1)))
							client.send(answer.encode())
							print("Key exchange successfully completed with client at address: " + addr[0] + ":" + str(addr[1]))
						else:
							client.send("Incorrect one-time password".encode())
					else:
						print("Expired authenticator accepted")
			else:
				client.send("TGS expired".encode())

service = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
service.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
service.bind((IP, SERVICE_PORT))
service.listen()

while True:
	client, addr = service.accept()
	request = client.recv(8192).decode()

	if (request.find("SERVICE_AS_REQ") != -1):
		key_exchange(client, addr, request)
	else:
		print("Unknown request")



