from hashlib import sha256

from constants  import *
from utils      import *

class HMAC():
    def __init__(self, K, M):
        self.K = K
        self.M = M


    def set_key(self, K):
        self.K = K

        return self

    def set_message(self, M):
        self.M = M

        return self


    def _pad(self):
        K = self.K
        
        if len(K) > BLOCK_SIZE_HMAC_SHA256:
            K = sha256(K).digest()
        
        if len(K) < BLOCK_SIZE_HMAC_SHA256:
            K += b'\x00' * (BLOCK_SIZE_HMAC_SHA256 - len(K))

        return K


    def encrypt(self):
        K = self._pad()
        M = self.M

        Ki = xor(K, IPAD)
        Ko = xor(K, OPAD)
        
        T = sha256(concat(Ko, sha256(concat(Ki, M)).digest())).digest()

        return T
    
    def verify(self, M, T):
        return self.set_message(M).encrypt() == T
