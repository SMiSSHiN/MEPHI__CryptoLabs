from Crypto.Cipher import AES

from constants  import *
from math       import ceil
from utils      import xor

class truncMAC():
    def __init__(self, K, M):
        if len(K) != KEY_SIZE:
            raise ValueError(f'invalid key size, expecting {KEY_SIZE} bytes')

        self.K = K
        self.M = M
        self.E = AES.new(K, AES.MODE_ECB)


    def set_key(self, K):
        if len(K) != KEY_SIZE:
            raise ValueError(f'invalid key size, expecting {KEY_SIZE} bytes')
        
        self.K = K
        self.E = AES.new(K, AES.MODE_ECB)

        return self

    def set_message(self, M):
        self.M = M

        return self


    def _pkcs7(self, M):
        if len(M) % BLOCK_SIZE == 0:
            padding_data = M + BLOCK_SIZE * (BLOCK_SIZE).to_bytes(1, byteorder = 'big')
        else:
            padding_length = BLOCK_SIZE - (len(M) % BLOCK_SIZE) 
            padding_data = M + padding_length * (padding_length).to_bytes(1, byteorder = 'big')
        
        return padding_data


    def encrypt(self):
        M = self.M

        M_len   = len(M)       
        n       = ceil(M_len / BLOCK_SIZE)
        M_last  = ZERO

        flag = True if (M_len % BLOCK_SIZE) == 0 else False
        
        if n == 0:
            n = 1
            flag = False

        M_n = M[(n - 1)*BLOCK_SIZE:]
        if flag == False:
            M_last = self._pkcs7(M_n)

        X = ZERO 
        for i in range(n - 1):
            M_i = M[BLOCK_SIZE * (i): BLOCK_SIZE * (i + 1)]

            Y = xor(M_i, X)
            X = self.E.encrypt(Y)

        Y = xor(M_last, X)
        T = self.E.encrypt(Y)

        return T[:len(T) // 2]

    def verify(self, M, T):
        return self.set_message(M).encrypt() == T
