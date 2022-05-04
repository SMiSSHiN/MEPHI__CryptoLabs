# EncryptThenMacImpl
Здесь и далее в качестве шифра используется `AES-128` в режиме `CTR`. В качестве кода аутентичности `HMAC-SHA-256`.

Ожидаемый формат шифртекста на ключе, независимом от ключа шифрования: 
```
(CTR(IV) || ENCRYPTED_DATA || MAC)
```
где MAC вычисляется от (CTR(IV) || ENCRYPTED_DATA)

## 1. Интерфейс класса `EtM`::
```py
class EtM():
    def __init__(self, aes_key: bytes, mac_key: bytes):

    @property
    def aes_key(self):
    @aes_key.setter
    def aes_key(self, aes_key: bytes):
    
    def __add_encrypt_block(self, block, isFinal):
    def __add_decrypt_block(self, block, isFinal):

    def encrypt(self, data):
    def decrypt(self, data):
```

## 2. Зашифровать и проверить произвольный блок данных, размера 100 MB.
Результат работы `main.py`: 
```
[STEP 01] Data generated.
[STEP 02] Cipher text was calculated.
[STEP 03] Plain text was calculated.
[STEP 04] Check ciphertext.txt and plaintext.txt.
```