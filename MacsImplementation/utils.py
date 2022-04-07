from constants import BLOCK_SIZE

def xor(M1, M2):
    # Input     : M1 (N-byte message)
    #           : M2 (N-byte message)
    #
    # Output    : _  ((M1 xor M2) 16-byte message)

    if len(M1) != len(M2):
        raise ValueError(f'invalid message length, expecting len(M1) = len(M2)')

    N = len(M1)

    M1 = int.from_bytes(M1, 'big')
    M2 = int.from_bytes(M2, 'big')

    return (M1 ^ M2).to_bytes(N, byteorder = 'big')

def concat(M1, M2):
    # Input     : M1 (N1-byte message)
    #           : M2 (N2-byte message)
    #
    # Output    : _  (M1 || M2 (N1+N2)-byte message)

    M1_len = len(M1)
    M2_len = len(M2)

    M1 = int.from_bytes(M1, 'big')
    M2 = int.from_bytes(M2, 'big')

    M  = (M1 << (M2_len * 8)) | M2

    return M.to_bytes((M1_len + M2_len), byteorder = 'big')
