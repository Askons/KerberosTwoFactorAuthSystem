import socket
import json
import time
import pyotp
import aes
IP = "localhost"
PORT = 6663



#--------------------------Инициализация модуля временных паролей---------------------------

def initialize_totp():
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect((IP, PORT))
	encryptor = aes.AESEncryptor()
	
	request = "INIT_TOTPusernameAskons"
	client.send(request.encode())
	answer = client.recv(8192).decode()
	with open('two_factor_auth.json', 'r') as file:
		file_data = json.loads(file.read())
	file_data["TOTPKey"] = answer
	with open('two_factor_auth.json', 'w') as file:
		json.dump(file_data, file, indent="\t")
	client.close()

#-------------------------------------------------------------------------------------------



#----------------------------------Вывод пароля в консоль-----------------------------------

def show_pass():
	with open('two_factor_auth.json', 'r') as file:
		file_data = json.loads(file.read())
	totp_key = file_data["TOTPKey"]
	totp = pyotp.TOTP(totp_key)
	while True:
		print(totp.now())
		time.sleep(3)

#-------------------------------------------------------------------------------------------


while True:
	try:
		eval(input())
	except:
		print("Unknown command. Try again")