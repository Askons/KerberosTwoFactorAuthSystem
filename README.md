# KerberosTwoFactorAuthSystem
Two-factor authentication system based on Kerberos protocol

Система двухфакторной аутентификации на основе протокола Kerberos с использованием TOTP-паролей в качестве второго фактора

Папка Client - программное обеспечение пользователя;

Папка Server - программное обеспечение сервера аутентификации и выдачи мантадов;

Папка Service - программное обеспечение для сервиса, с которым требуется провести аутентификацию;

Папка TwoFactorAuth - программное обеспечение для мобильного аутентификатора.

Для полноценной работы системы запускаются следующие файлы:

Client.py

Server.py

Service.py

TwoFactorAuth.py

Файл aes.py содержит в себе алгоритм шифрования AES и используется для шифровния данных, передаваемых в процессе аутентификации

Так как данная версия системы является тестовой, все программы запускаются на одном компьютере, в качестве ip-адресов используется localhost

В системе используются следующие функции:
  
  TwoFactorAuth.py:
      
      show_pass() - функция запускает отображение в консоли одноразового пароля (обновляется каждые 3 секунды);
  Client.py:
      
      authorize() - функция, запускающая процесс получения пользователем TGT;
      
      request_tgs(SERVICE) - функция, запускающая процесс получения пользователем TGS на доступ к SERVICE;
     
      connect_to_service(SERVICE) - функция, запускающая процесс взаимной аутентификации пользователя и SERVICE.
  
