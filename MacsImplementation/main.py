from MACS.cmac      import CMAC
from MACS.truncmac  import truncMAC
from MACS.hmac      import HMAC
from constants      import *

from Crypto.Hash    import CMAC as cMAC
import hmac         as hMAC

from math           import ceil
from os             import urandom
from Crypto.Cipher  import AES
from hashlib        import sha256
import time
import matplotlib.pyplot as plt

KBYTES  = 1000
M_SIZES = [(x ** 2) * KBYTES for x in range(1, 19)]
COUNT   = 1500

def macs_valdn():
    message         = urandom(ceil(BLOCK_SIZE * 2.5))
    fake_ver_msg    = message
    key             = urandom(KEY_SIZE)

    cmac        = CMAC(key, message)
    truncmac    = truncMAC(key, message)
    hmac        = HMAC(key, message)

    T_cmac = cmac.encrypt()
    T_tmac = truncmac.encrypt()
    T_hmac = hmac.encrypt()

    print('====================Task 3====================')

    if T_cmac == cMAC.new(key, ciphermod=AES).update(message).digest():
        print('[+] CMAC algorithm implementation works correctly')
    else:
        print('[!] CMAC algorithm implemented incorrectly')

    if T_hmac == hMAC.new(key, message, sha256).digest():
        print('[+] HMAC algorithm implementation works correctly')
    else:
        print('[!] HMAC algorithm implemented incorrectly')

    print('----------------------------------------------')
    print('===================Task 3.1===================')
    
    if cmac.verify(fake_ver_msg, T_cmac):
        print('CMAC     algorithm verification works')
    if truncmac.verify(fake_ver_msg, T_tmac):
        print('TruncMAC algorithm verification works')
    if hmac.verify(fake_ver_msg, T_hmac):
        print('HMAC     algorithm verification works')

def macs_perf(M_size):
    msgs = [urandom(M_size)   for _ in range(COUNT)]
    keys = [urandom(KEY_SIZE) for _ in range(COUNT)]

    cmac_start_time = time.time()
    for i in range(COUNT):
        CMAC(keys[i], msgs[i]).encrypt()
    cmac_end_time = time.time() - cmac_start_time

    hmac_start_time = time.time()
    for i in range(COUNT):
        HMAC(keys[i], msgs[i]).encrypt()
    hmac_end_time = time.time() - hmac_start_time

    return cmac_end_time / COUNT, hmac_end_time / COUNT

if __name__ == '__main__':
    macs_valdn()

    macs_perf_cmac = []
    macs_perf_hmac = []

    for element in M_SIZES:
        macs_perf_i = macs_perf(element)

        macs_perf_cmac.append(macs_perf_i[0] * 1000)
        macs_perf_hmac.append(macs_perf_i[1] * 1000)

    M_SIZES = [x ** 2 for x in range(1, 19)]
    
    plt.subplots(2, 2, figsize=(12,12))

    plt.subplot(211)
    plt.title('Dep. of the avg. execution time of CMAC on the size of msgs.')
    plt.plot(M_SIZES, macs_perf_cmac, '--bo')
    plt.xlabel('msg size (kB)')
    plt.ylabel('avg. time (msec)')

    plt.subplot(212)
    plt.title('Dep. of the avg. execution time of HMAC on the size of msgs.')
    plt.plot(M_SIZES, macs_perf_hmac, '--ro')
    plt.xlabel('msg size (kB)')
    plt.ylabel('avg. time (msec)')

    plt.savefig('macs_perf.svg')
