from os     import urandom
from etm    import EtM

etm = EtM(urandom(16), urandom(16))

data = urandom(1024 * 1024)
print('[STEP 01] Data generated.')

cipher_text = etm.encrypt(data)
with open('ciphertext.txt', 'wb') as f:
    f.write(cipher_text)    
print('[STEP 02] Cipher text was calculated.')

plain_text = etm.decrypt(cipher_text)
with open('plaintext.txt', 'wb') as f:
    f.write(plain_text) 
print('[STEP 03] Plain text was calculated.')
print('[STEP 04] Check ciphertext.txt and plaintext.txt.')
