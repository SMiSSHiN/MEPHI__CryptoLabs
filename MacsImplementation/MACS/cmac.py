from Crypto.Cipher  import AES
from struct         import pack, unpack

from constants  import *
from math       import ceil
from utils      import xor

# def generate_subkey(K):
#     k0 = AES.new(K, AES.MODE_ECB).encrypt(ZERO)
    
#     K  = int.from_bytes(K, 'big')
#     k0 = int.from_bytes(k0, 'big')

#     k1 = (k0 << 1)
#     if (k0 >> 127):
#         k1 ^= Rb

#     k2 = (k1 << 1)
#     if (k1 >> 127):
#         k2 ^= Rb

#     k1 = (k1).to_bytes(17, byteorder = 'big')[1:17]
#     k2 = (k2).to_bytes(17, byteorder = 'big')[1:17]

#     return k1, k2 

def generate_subkey(K):
    AES_128 = AES.new(K, AES.MODE_ECB)

    L = AES_128.encrypt(bytes(bytearray(16)))

    LHigh = unpack('>Q',L[:8])[0]
    LLow  = unpack('>Q',L[8:])[0]

    K1High = ((LHigh << 1) | ( LLow >> 63 )) & 0xFFFFFFFFFFFFFFFF
    K1Low  = (LLow << 1) & 0xFFFFFFFFFFFFFFFF

    if (LHigh >> 63):
        K1Low ^= 0x87

    K2High = ((K1High << 1) | (K1Low >> 63)) & 0xFFFFFFFFFFFFFFFF
    K2Low  = ((K1Low << 1)) & 0xFFFFFFFFFFFFFFFF

    if (K1High >> 63):
        K2Low ^= 0x87

    K1 = bytearray(pack('>QQ', K1High, K1Low))
    K2 = bytearray(pack('>QQ', K2High, K2Low))

    return K1, K2

class CMAC():
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


    def _pad(self, M):
        P_len   = BLOCK_SIZE - len(M)
        P       = 0b10

        M = int.from_bytes(M, 'big')
        M = (M << (P_len * 8)) | (P << (P_len * 8) - 2)
        M = M.to_bytes(16, byteorder = 'big')

        return M


    def encrypt(self):
        K = self.K
        M = self.M

        k1, k2  = generate_subkey(K)
        M_len   = len(M)       
        n       = ceil(M_len / BLOCK_SIZE)

        flag = True if (M_len % BLOCK_SIZE) == 0 else False
        
        if n == 0:
            n = 1
            flag = False

        M_n = M[(n - 1)*BLOCK_SIZE:]
        if flag:
            M_last = xor(M_n, k1)
        else:
            M_last = xor(self._pad(M_n), k2)

        X = ZERO 
        for i in range(n - 1):
            M_i = M[BLOCK_SIZE * (i): BLOCK_SIZE * (i + 1)]

            Y = xor(M_i, X)
            X = self.E.encrypt(Y)

        Y = xor(M_last, X)
        T = self.E.encrypt(Y)

        return T

    def verify(self, M, T):
        return self.set_message(M).encrypt() == T
