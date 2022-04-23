import hmac
import hashlib

from math import ceil

HASHLEN_HMAC_SHA256     = 32
MAX_DKLEN               = (2 ** 32 - 1) * HASHLEN_HMAC_SHA256

BYTES_TYPE  = type(bytes())

class PBKDF2():
    def __init__(self, P, S, c, dkLen):
        if type(P) != BYTES_TYPE:
            raise ValueError('Password must be ', BYTES_TYPE)
        if type(S) != BYTES_TYPE:
            raise ValueError('Salt must be ', BYTES_TYPE)
        if c <= 0:
            raise ValueError('Count must be a positive integer')
        if dkLen > MAX_DKLEN:
            raise ValueError('Derived key too longdk must be less (2^32 - 1) * hLen')
        
        self._P      = P     # Password, an octet string
        self._S      = S     # Salt, an octet string
        self._c      = c     # Iteration count, a positive integer
        self._dkLen  = dkLen # intended length in octets of the derived key, a positive integer, at most (2^32 - 1) * hLen

    @property
    def P(self):
        return AttributeError("Password is write-only")
    
    @P.setter
    def P(self, P):
        if type(P) != type(bytes()):
            raise ValueError('Password must me ', type(bytes()))

        self._P = P
        
    def __F(self, i):
        U_1 = hmac.new(self._P, self._S + bytes([0, 0, 0, i]), hashlib.sha256).digest()
        T_i = int.from_bytes(U_1, byteorder = 'big')

        U_prev = U_1
        for j in range(2, self._c + 1):
            U_curr = hmac.new(self._P, U_prev, hashlib.sha256).digest()
            U_prev = U_curr

            T_i ^= int.from_bytes(U_curr, byteorder = 'big')

        return (T_i).to_bytes(HASHLEN_HMAC_SHA256, byteorder = 'big')


    def calculate(self):
        l = ceil(self._dkLen/HASHLEN_HMAC_SHA256)
        r = self._dkLen - (l - 1)*HASHLEN_HMAC_SHA256

        DK = bytes()

        for i in range(1, l):
            DK += self.__F(i)
        
        DK += self.__F(l)[:r]

        return DK[:self._dkLen]
