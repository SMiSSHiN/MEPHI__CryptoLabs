import  json
import  matplotlib.pyplot as plt

from    os   import urandom
from    math import ceil
from    backports.pbkdf2 import pbkdf2_hmac

from    HKDF.hkdf       import HKDF
from    PBKDF2.pbkdf2   import PBKDF2

# ++++++++++++++++++++++++
# Checking HKDF and PBKDF2
# ++++++++++++++++++++++++
def hkdf_check(salt, IKM, info, L, OKM, i):
    if HKDF(salt, IKM, info, L).calculate() == OKM:
        print('[+] [HKDF  ] Test #',i ,'passed')
    else:
        print('[+] [HKDF  ] Test #',i ,'failed')

def pbkdf2_check():
    P, s, c, dkLen = urandom(32), urandom(4), 100, 32

    if pbkdf2_hmac("sha256", P, s, c, dkLen) == PBKDF2(P, s, c, dkLen).calculate():
        print('[+] [PBKDF2] Test # 1 passed')
    else:
        print('[-] [PBKDF2] Test # 1 failed')

# ++++++++++++++++++++++++++++++++++++
# Built histograms for HKDF and PBKDF2
# ++++++++++++++++++++++++++++++++++++
def hkdf_hist(IKM, keys):
    plt.rc('axes', axisbelow = True)
    plt.figure(figsize = (20, 9))
    plt.subplots_adjust(wspace = 0.4, hspace = 0.4)

    plt.subplot(121)
    plt.xlabel('temp | hum | wind | cloud | ozone')
    plt.ylabel('Probability')
    plt.title('Histogram of weather')
    plt.grid(True, linestyle = '--', linewidth = 0.5)
    plt.hist(IKM, 15, density = 1, facecolor = 'r', alpha = 0.75)

    plt.subplot(122)
    plt.xlabel('First byte of key')
    plt.ylabel('Probability')
    plt.title('Histogram of HKDF keys')
    plt.grid(True, linestyle = '--', linewidth = 0.5)
    plt.hist(keys, 15, density = 1, facecolor = 'r', alpha = 0.75)

    plt.savefig('hkdf_hist.png')

def pbkdf2_hist(passwords, keys):
    plt.rc('axes', axisbelow = True)
    plt.figure(figsize = (20, 9))
    plt.subplots_adjust(wspace = 0.4, hspace = 0.4)

    plt.subplot(121)
    plt.xlabel('')
    plt.ylabel('Probability')
    plt.title('Histogram of passwords')
    plt.grid(True, linestyle = '--', linewidth = 0.5)
    plt.hist(passwords, 15, density = 1, facecolor = 'b', alpha = 0.75)

    plt.subplot(122)
    plt.xlabel('First byte of key')
    plt.ylabel('Probability')
    plt.title('Histogram of PBKDF2 keys')
    plt.grid(True, linestyle = '--', linewidth = 0.5)
    plt.hist(keys, 15, density = 1, facecolor = 'b', alpha = 0.75)

    plt.savefig('pbkdf2_hist.png')


if __name__ == '__main__':
    # ++++++++++++++++++++++++++
    # Test vectors from RFC 5869
    # ++++++++++++++++++++++++++
    hkdf_check(bytes.fromhex('000102030405060708090a0b0c'),
            bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
            bytes.fromhex('f0f1f2f3f4f5f6f7f8f9'),
            42,
            bytes.fromhex('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'),
            1)

    hkdf_check(bytes.fromhex('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf'),
            bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f'),
            bytes.fromhex('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
            82,
            bytes.fromhex('b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87'),
            2)

    hkdf_check(bytes.fromhex(''),
            bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
            bytes.fromhex(''),
            42,
            bytes.fromhex('8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'),
            3)

    # +++++++++++++++++++++++++++++
    # Random test vector for PBKDF2
    # +++++++++++++++++++++++++++++
    pbkdf2_check()

    # ++++++++++++++
    # HKDF histogram
    # ++++++++++++++
    with open('./data/weather.json', 'r') as f:
        weather = json.load(f)

    data = weather['hourly']['data']

    temp, hum, wind, cloud, ozone = [], [], [], [], []

    for element in data:
        temp.append(element['temperature'])
        hum.append(element['humidity'])
        wind.append(element['windSpeed'])
        cloud.append(element['cloudCover'])
        ozone.append(element['ozone'])

    IKM = [*temp, *hum, *wind, *cloud, *ozone]

    keys = [HKDF(urandom(32), ceil(element).to_bytes(2, byteorder = 'big'), bytes(), 32).calculate()[0] for element in IKM]
    # keys = [int.from_bytes(key, 'big') >> (256 - 10) for key in keys]

    corr_temp   = [(element * 10)  for element in  temp]
    corr_hum    = [(element * 100) for element in   hum]
    corr_wind   = [(element * 100) for element in  wind]
    corr_cloud  = [(element * 100) for element in cloud]
    corr_ozone  = [(element)       for element in ozone]

    IKM = [*corr_temp, *corr_hum, *corr_wind, *corr_cloud, *corr_ozone]

    hkdf_hist(IKM, keys)

    # ++++++++++++++++
    # PBKDF2 histogram
    # ++++++++++++++++
    with open('./data/passwords.json', 'r') as f:
        passwords = json.load(f)

    passwords   = [bytes(pwd, 'utf-8') for pwd in passwords]
    keys        = [PBKDF2(pwd, urandom(4), 10, 64).calculate()[0] for pwd in passwords]

    passwords   = [pwd[0] for pwd in passwords]

    pbkdf2_hist(passwords, keys)
