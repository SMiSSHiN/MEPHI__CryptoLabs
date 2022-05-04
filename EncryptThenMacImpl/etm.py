import  hmac
from    hashlib        import sha256
from os import urandom

from    Crypto.Cipher  import AES
from    Crypto.Util    import Counter

from    math           import ceil

BLOCK_SIZE = 16
BYTES_TYPE = type(bytes())

class EtM():
    def __init__(self, aes_key: bytes, mac_key: bytes):
        if type(aes_key) != BYTES_TYPE or len(aes_key) != BLOCK_SIZE:
            raise ValueError('AES key must be', BYTES_TYPE, BLOCK_SIZE, 'bytes long.')
        if type(mac_key) != BYTES_TYPE or len(aes_key) != BLOCK_SIZE:
            raise ValueError('MAC key must be', BYTES_TYPE, 'of any length.')

        self._aes_key    = aes_key
        self._mac_key    = mac_key

        self._iv         = urandom(BLOCK_SIZE)
        self._ctr        = Counter.new(BLOCK_SIZE * 8, initial_value = int.from_bytes(self._iv, 'big'))
        self._cipher     = AES.new(self._aes_key, AES.MODE_CTR, counter = self._ctr)
        self._hmac       = hmac.new(self._mac_key, self._iv, digestmod = sha256)

    @property
    def aes_key(self):
        return AttributeError("Key is write-only")

    @aes_key.setter
    def aes_key(self, aes_key: bytes):
        if type(aes_key) != BYTES_TYPE or len(aes_key) != BLOCK_SIZE:
            raise ValueError('AES key must be', BYTES_TYPE, BLOCK_SIZE, 'bytes long.')
        
        self._aes_key   = aes_key
        self._cipher    = AES.new(self._aes_key, AES.MODE_CTR, counter = self._ctr)

    def __add_encrypt_block(self, block, isFinal):
        cipher_block = self._cipher.encrypt(block)
        self._hmac.update(cipher_block)

        if isFinal:
            cipher_block += self._hmac.digest()
        
        return cipher_block
    
    def __add_decrypt_block(self, block, isFinal):
        if isFinal:
            if block != self._hmac.digest():
                raise ValueError('MAC verification failed')

        self._hmac.update(block)
        plain_block = self._cipher.decrypt(block)

        return plain_block

    def encrypt(self, data):
        data_block_size = BLOCK_SIZE * BLOCK_SIZE
        cipher_text = self._iv
        
        N = ceil(len(data) / data_block_size)
        for i in range(N):
            idx = i * data_block_size
            flag = (i == N - 1)
            cipher_text += self.__add_encrypt_block(data[idx:idx + data_block_size], flag)

        return cipher_text

    def decrypt(self, data):
        self._iv        = data[:BLOCK_SIZE]
        self._ctr       = Counter.new(BLOCK_SIZE * 8, initial_value = int.from_bytes(self._iv, 'big'))
        self._cipher    = AES.new(self._aes_key, AES.MODE_CTR, counter = self._ctr)
        self._hmac      = hmac.new(self._mac_key, self._iv, digestmod = sha256)

        plain_text = bytes()
        mac  = data[(-2) * BLOCK_SIZE:]
        data = data[BLOCK_SIZE:(-2)*BLOCK_SIZE]
        data_block_size = BLOCK_SIZE * BLOCK_SIZE

        N = ceil(len(data) / data_block_size) 
        for i in range(N):
            idx = i * data_block_size
            plain_text += self.__add_decrypt_block(data[idx:idx + data_block_size], False)

        self.__add_decrypt_block(mac, True)

        return plain_text
    