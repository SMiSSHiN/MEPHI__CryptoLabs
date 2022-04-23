import hmac
import hashlib

from math import ceil

HASHLEN_HMAC_SHA256 = 32
MAX_L               = 255 * HASHLEN_HMAC_SHA256

BYTES_TYPE          = type(bytes())

class HKDF():
    def __init__(self, salt, IKM, info, L):
        if type(salt) != BYTES_TYPE:
            raise ValueError('Salt must be ', BYTES_TYPE)
        if type(IKM) != BYTES_TYPE:
            raise ValueError('Input key material must be ', BYTES_TYPE)
        if type(info) != BYTES_TYPE:
            raise ValueError('Info must be ', BYTES_TYPE)
        if L > MAX_L:
            raise ValueError('L must too longdk must be less 255 * HashLen')

        self.salt   = salt  # Optional salt value
        self.IKM    = IKM   # Input key material
        self.info   = info  # Optional context and application specific information                            
        self.L      = L     # Length of OKM in octets


    def __extract(self):
        return hmac.new(self.salt, self.IKM, hashlib.sha256).digest() 

    def __expand(self, PRK):
        N = ceil(self.L/HASHLEN_HMAC_SHA256)
        
        T       = bytes()
        T_prev  = bytes()
        
        for i in range(N):
            T_next = hmac.new(PRK, T_prev + self.info + (i + 1).to_bytes(1, byteorder = 'big'), hashlib.sha256).digest()
            T_prev = T_next
            
            T += T_next

        return T[:self.L]


    def calculate(self):
        PRK = self.__extract()
        OKM = self.__expand(PRK)

        return OKM
