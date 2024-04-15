### AES cryptosystem.
#### Author: Vadym Tunik.

"""
WARNING:
In the implementation of the cryptosystem in the state, words are placed in ROWS, NOT COLUMNS.

Also, to use AES-128, AES-192 i AES-256 cryptosystems, use keys of the appropriate length.
"""

from gf256 import GF256


SBOX = {0x00: 0x63, 0x01: 0x7c, 0x02: 0x77, 0x03: 0x7b, 0x04: 0xf2, 0x05: 0x6b, 0x06: 0x6f, 0x07: 0xc5,
        0x08: 0x30, 0x09: 0x01, 0x0a: 0x67, 0x0b: 0x2b, 0x0c: 0xfe, 0x0d: 0xd7, 0x0e: 0xab, 0x0f: 0x76,
        0x10: 0xca, 0x11: 0x82, 0x12: 0xc9, 0x13: 0x7d, 0x14: 0xfa, 0x15: 0x59, 0x16: 0x47, 0x17: 0xf0,
        0x18: 0xad, 0x19: 0xd4, 0x1a: 0xa2, 0x1b: 0xaf, 0x1c: 0x9c, 0x1d: 0xa4, 0x1e: 0x72, 0x1f: 0xc0,
        0x20: 0xb7, 0x21: 0xfd, 0x22: 0x93, 0x23: 0x26, 0x24: 0x36, 0x25: 0x3f, 0x26: 0xf7, 0x27: 0xcc,
        0x28: 0x34, 0x29: 0xa5, 0x2a: 0xe5, 0x2b: 0xf1, 0x2c: 0x71, 0x2d: 0xd8, 0x2e: 0x31, 0x2f: 0x15,
        0x30: 0x04, 0x31: 0xc7, 0x32: 0x23, 0x33: 0xc3, 0x34: 0x18, 0x35: 0x96, 0x36: 0x05, 0x37: 0x9a,
        0x38: 0x07, 0x39: 0x12, 0x3a: 0x80, 0x3b: 0xe2, 0x3c: 0xeb, 0x3d: 0x27, 0x3e: 0xb2, 0x3f: 0x75,
        0x40: 0x09, 0x41: 0x83, 0x42: 0x2c, 0x43: 0x1a, 0x44: 0x1b, 0x45: 0x6e, 0x46: 0x5a, 0x47: 0xa0,
        0x48: 0x52, 0x49: 0x3b, 0x4a: 0xd6, 0x4b: 0xb3, 0x4c: 0x29, 0x4d: 0xe3, 0x4e: 0x2f, 0x4f: 0x84,
        0x50: 0x53, 0x51: 0xd1, 0x52: 0x00, 0x53: 0xed, 0x54: 0x20, 0x55: 0xfc, 0x56: 0xb1, 0x57: 0x5b,
        0x58: 0x6a, 0x59: 0xcb, 0x5a: 0xbe, 0x5b: 0x39, 0x5c: 0x4a, 0x5d: 0x4c, 0x5e: 0x58, 0x5f: 0xcf,
        0x60: 0xd0, 0x61: 0xef, 0x62: 0xaa, 0x63: 0xfb, 0x64: 0x43, 0x65: 0x4d, 0x66: 0x33, 0x67: 0x85,
        0x68: 0x45, 0x69: 0xf9, 0x6a: 0x02, 0x6b: 0x7f, 0x6c: 0x50, 0x6d: 0x3c, 0x6e: 0x9f, 0x6f: 0xa8,
        0x70: 0x51, 0x71: 0xa3, 0x72: 0x40, 0x73: 0x8f, 0x74: 0x92, 0x75: 0x9d, 0x76: 0x38, 0x77: 0xf5,
        0x78: 0xbc, 0x79: 0xb6, 0x7a: 0xda, 0x7b: 0x21, 0x7c: 0x10, 0x7d: 0xff, 0x7e: 0xf3, 0x7f: 0xd2,
        0x80: 0xcd, 0x81: 0x0c, 0x82: 0x13, 0x83: 0xec, 0x84: 0x5f, 0x85: 0x97, 0x86: 0x44, 0x87: 0x17,
        0x88: 0xc4, 0x89: 0xa7, 0x8a: 0x7e, 0x8b: 0x3d, 0x8c: 0x64, 0x8d: 0x5d, 0x8e: 0x19, 0x8f: 0x73,
        0x90: 0x60, 0x91: 0x81, 0x92: 0x4f, 0x93: 0xdc, 0x94: 0x22, 0x95: 0x2a, 0x96: 0x90, 0x97: 0x88,
        0x98: 0x46, 0x99: 0xee, 0x9a: 0xb8, 0x9b: 0x14, 0x9c: 0xde, 0x9d: 0x5e, 0x9e: 0x0b, 0x9f: 0xdb,
        0xa0: 0xe0, 0xa1: 0x32, 0xa2: 0x3a, 0xa3: 0x0a, 0xa4: 0x49, 0xa5: 0x06, 0xa6: 0x24, 0xa7: 0x5c,
        0xa8: 0xc2, 0xa9: 0xd3, 0xaa: 0xac, 0xab: 0x62, 0xac: 0x91, 0xad: 0x95, 0xae: 0xe4, 0xaf: 0x79,
        0xb0: 0xe7, 0xb1: 0xc8, 0xb2: 0x37, 0xb3: 0x6d, 0xb4: 0x8d, 0xb5: 0xd5, 0xb6: 0x4e, 0xb7: 0xa9,
        0xb8: 0x6c, 0xb9: 0x56, 0xba: 0xf4, 0xbb: 0xea, 0xbc: 0x65, 0xbd: 0x7a, 0xbe: 0xae, 0xbf: 0x08,
        0xc0: 0xba, 0xc1: 0x78, 0xc2: 0x25, 0xc3: 0x2e, 0xc4: 0x1c, 0xc5: 0xa6, 0xc6: 0xb4, 0xc7: 0xc6,
        0xc8: 0xe8, 0xc9: 0xdd, 0xca: 0x74, 0xcb: 0x1f, 0xcc: 0x4b, 0xcd: 0xbd, 0xce: 0x8b, 0xcf: 0x8a,
        0xd0: 0x70, 0xd1: 0x3e, 0xd2: 0xb5, 0xd3: 0x66, 0xd4: 0x48, 0xd5: 0x03, 0xd6: 0xf6, 0xd7: 0x0e,
        0xd8: 0x61, 0xd9: 0x35, 0xda: 0x57, 0xdb: 0xb9, 0xdc: 0x86, 0xdd: 0xc1, 0xde: 0x1d, 0xdf: 0x9e,
        0xe0: 0xe1, 0xe1: 0xf8, 0xe2: 0x98, 0xe3: 0x11, 0xe4: 0x69, 0xe5: 0xd9, 0xe6: 0x8e, 0xe7: 0x94,
        0xe8: 0x9b, 0xe9: 0x1e, 0xea: 0x87, 0xeb: 0xe9, 0xec: 0xce, 0xed: 0x55, 0xee: 0x28, 0xef: 0xdf,
        0xf0: 0x8c, 0xf1: 0xa1, 0xf2: 0x89, 0xf3: 0x0d, 0xf4: 0xbf, 0xf5: 0xe6, 0xf6: 0x42, 0xf7: 0x68,
        0xf8: 0x41, 0xf9: 0x99, 0xfa: 0x2d, 0xfb: 0x0f, 0xfc: 0xb0, 0xfd: 0x54, 0xfe: 0xbb, 0xff: 0x16}


InvSBOX = {value: key for key, value in SBOX.items()}


ROUND_CONSTANT =   [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
                    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
                    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
                    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
                    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
                    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
                    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
                    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
                    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
                    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
                    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
                    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
                    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
                    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
                    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
                    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d]



def SubBytes(state: list) -> list:
    """
    Byte substitution using a non-linear S-Box (independently on each byte).

    Params:
    state: 4 by 4 size 2d array

    Return:
    new_state: 4 by 4 size 2d array state after SBOX
    """
    new_state = []
    state_len = len(state)
    for i in range(state_len):
        new_row = []
        for j in range(state_len):
            new_row.append(SBOX[state[i][j]])
        new_state.append(new_row)
    return new_state


def InvSubBytes(state: list) -> list:
    """
    InvSubBytes() is the inverse of the byte substitution transformation, in which the inverse Sbox is applied to each byte of the State.

    Params:
    state: 4 by 4 size 2d array

    Return:
    new_state: 4 by 4 size 2d array state after SBOX
    """
    new_state = []
    state_len = len(state)
    for i in range(state_len):
        new_row = []
        for j in range(state_len):
            new_row.append(InvSBOX[state[i][j]])
        new_state.append(new_row)
    return new_state


def AddRoundKey(state: list, key:list) -> list:
    """
    Element-wise state XOR key.

    Params:
    state: 4 by 4 size 2d array
    key: 4 by 4 size 2d array

    Return:
    new_state: 4 by 4 size 2d array state after XOR operation
    """
    new_state = []
    state_len = len(state)
    # key = [[row[i] for row in key] for i in range(len(key))]
    for i in range(state_len):
        new_row = []
        for j in range(state_len):
            new_row.append(state[i][j] ^ key[i][j])
        new_state.append(new_row)
    return new_state


def ShiftRows(state: list) -> list:
    """ 
    Circular Left Shift of a number of bytes equal to the row number

    Params:
    state: 4 by 4 size 2d array

    Return:
    new_state: 4 by 4 size 2d array state after Left Shift operations
    """
    new_state = []
    for i in range(len(state)):
        row = [state[i][0], state[(i+1)%4][1], state[(i+2)%4][2], state[(i+3)%4][3]]
        new_state.append(row)
    return new_state


def InvShiftRows(state: list) -> list:
    """ 
    InvShiftRows() is the inverse of the ShiftRows() transformation.

    Params:
    state: 4 by 4 size 2d array

    Return:
    new_state: 4 by 4 size 2d array state after Left Shift operations
    """
    new_state = []
    for i in range(len(state)):
        row = [state[i][0], state[(i+3)%4][1], state[(i+2)%4][2], state[(i+1)%4][3]]
        new_state.append(row)
    return new_state


def MixColumns(state: list) -> list:
    """ 
    The MixColumns() transformation operates on the State row-by-row, treating each row as a four-term polynomial 
    
    Params:
    state: 4 by 4 size 2d array

    Return:
    new_state: 4 by 4 size 2d array state after Left Shift operations
    """
    new_state = []
    state_len = len(state)
    for i in range(state_len):
        b0, b1, b2, b3 = state[i][0], state[i][1], state[i][2], state[i][3]
        d0 = int(GF256(2) * GF256(b0)) ^ int(GF256(3) * GF256(b1)) ^ int(GF256(1) * GF256(b2)) ^ int(GF256(1) * GF256(b3))
        d1 = int(GF256(1) * GF256(b0)) ^ int(GF256(2) * GF256(b1)) ^ int(GF256(3) * GF256(b2)) ^ int(GF256(1) * GF256(b3))
        d2 = int(GF256(1) * GF256(b0)) ^ int(GF256(1) * GF256(b1)) ^ int(GF256(2) * GF256(b2)) ^ int(GF256(3) * GF256(b3))
        d3 = int(GF256(3) * GF256(b0)) ^ int(GF256(1) * GF256(b1)) ^ int(GF256(1) * GF256(b2)) ^ int(GF256(2) * GF256(b3))
        new_state.append([d0,d1,d2,d3])

    return new_state


def InvMixColumns(state: list) -> list:
    """ 
    InvMixColumns() is the inverse of the MixColumns() transformation. 

    Params:
    state: 4 by 4 size 2d array

    Return:
    new_state: 4 by 4 size 2d array state after Left Shift operations
    """
    new_state = []
    state_len = len(state)
    for i in range(state_len):
        b0, b1, b2, b3 = state[i][0], state[i][1], state[i][2], state[i][3]
        d0 = int(GF256(14) * GF256(b0)) ^ int(GF256(11) * GF256(b1)) ^ int(GF256(13) * GF256(b2)) ^ int(GF256(9) * GF256(b3))
        d1 = int(GF256(9) * GF256(b0)) ^ int(GF256(14) * GF256(b1)) ^ int(GF256(11) * GF256(b2)) ^ int(GF256(13) * GF256(b3))
        d2 = int(GF256(13) * GF256(b0)) ^ int(GF256(9) * GF256(b1)) ^ int(GF256(14) * GF256(b2)) ^ int(GF256(11) * GF256(b3))
        d3 = int(GF256(11) * GF256(b0)) ^ int(GF256(13) * GF256(b1)) ^ int(GF256(9) * GF256(b2)) ^ int(GF256(14) * GF256(b3))
        new_state.append([d0,d1,d2,d3])

    return new_state


def RotWord(word: list) -> list:
    """ 
    The function takes a word [a0,a1,a2,a3] as input, performs a cyclic permutation, and returns the word [a1,a2,a3,a0].

    Params:
    word: 1d array of bytes.

    Return:
    new_word: 1d array of bytes.
    """
    return word[1:] + word[:1]


def SubWord(word: list) -> list:
    """ 
    The function that takes a four-byte input word and applies the S-box to each of the four bytes to produce an output word.

    Params:
    word: 1d array of bytes.

    Return:
    new_word: 1d array of bytes.
    """
    return [SBOX[w] for w in word]


def RCon(i: int) -> list:
    """ 
    The round constant word array, Rcon[i], contains the values given by [x^(i-1),{00},{00},{00}], with x i-1 being powers of x (x is denoted as {02}) in the field GF(2^8), (note that i starts at 1, not 0).
    
    Params:
    i: index.

    Return:
    word: 1d array of bytes.
    """
    return [ROUND_CONSTANT[i-1], 0x00, 0x00, 0x00]


def XOR_word(word1, word2) -> list:
    """ 
    XOR between two 4-bytes words.

    Params:
    word1: 1d array of bytes.
    word2: 1d array of bytes.

    Return:
    new_word: 1d array of bytes.
    """
    return [word1[0] ^ word2[0], word1[1] ^ word2[1], word1[2] ^ word2[2], word1[3] ^ word2[3]]


def KeyExpansion(key: list, n_rounds: int) -> list:
    """ 
    The Key Expansion generates a total of Nb (Nr + 1) words: the algorithm requires
    an initial set of Nb words, and each of the Nr rounds requires Nb words of key data.

    Params:
    key: 1d-array key
    n_rounds: amount of rounds

    Return:
    expanded_key: list of keys for each round BUT with WORDS IN ROWS (not columns)
    """
    nk = len(key)//4
    nb = 4

    w = array_to_matrix(key)
    for i in range(nk, nb * (n_rounds + 1)):
        temp = w[i-1]
        if i % nk == 0:
            temp = XOR_word(SubWord(RotWord(temp)), RCon(i // nk))
        elif nk > 6 and i % nk == 4:
            temp = SubWord(temp)
        w.append(XOR_word(w[i - nk], temp))

    expanded_key = array_to_matrix(w)
    return expanded_key


def encrypt(plaintext: list, key: list) -> list:
    """ 
    AES cipher encryption process

    Params:
    plaintext: array of bytes
    key: 1d array of bytes

    Result:
    cryptotext: array of bytes
    """

    keybits = len(key)*8

    if keybits == 128:
        n_rounds = 10
    elif keybits == 192:
        n_rounds = 12
    else:
        n_rounds = 14

    state = array_to_matrix(plaintext)
    expanded_key = KeyExpansion(key, n_rounds)

    state = AddRoundKey(state, expanded_key[0])

    for round in range(1, n_rounds):
        state = SubBytes(state)
        state = ShiftRows(state)
        state = MixColumns(state)
        # print(f'{round=}, {matrix_int_to_hex(state)=}')
        state = AddRoundKey(state, expanded_key[round])

    state = SubBytes(state)
    state = ShiftRows(state)
    state = AddRoundKey(state, expanded_key[n_rounds])

    return matrix_to_array(state)


def decrypt(cryptotext: list, key: list) -> list:
    """ 
    AES cipher decryption process

    Params:
    cryptotext: array of bytes
    key: 1d array of bytes

    Result:
    plaintext: array of bytes
    """

    keybits = len(key)*8

    if keybits == 128:
        n_rounds = 10
    elif keybits == 192:
        n_rounds = 12
    else:
        n_rounds = 14

    state = array_to_matrix(cryptotext)
    expanded_key = KeyExpansion(key, n_rounds)

    state = AddRoundKey(state, expanded_key[n_rounds])

    for round in range(n_rounds-1,0,-1):
        state = InvShiftRows(state)
        state = InvSubBytes(state)
        state = AddRoundKey(state, expanded_key[round])
        state = InvMixColumns(state)

    state = InvShiftRows(state)
    state = InvSubBytes(state)
    state = AddRoundKey(state, expanded_key[0])

    return matrix_to_array(state)


def matrix_int_to_hex(matrix: list) -> list:
    """Helper function to display matrix elements in hexadecimal form"""
    new_state = []
    state_len = len(matrix)
    for i in range(state_len):
        new_row = []
        for j in range(state_len):
            new_row.append(hex(matrix[i][j]))
        new_state.append(new_row)
    return new_state


def word_int_to_hex(word: list) -> list:
    """Helper function to display word elements in hexadecimal form"""
    return [hex(w) for w in word ]


def array_to_matrix(arr: bytearray) -> list:
    """Function converts bytearray to matrix with row-words"""
    return [arr[i*4:(i+1)*4] for i in range(len(arr) // 4)]


def matrix_to_array(matrix: list) -> list:
    """Function converts matrix with row-words to one bytearray"""
    return bytearray(matrix[0] + matrix[1] + matrix[2] + matrix[3])


if __name__=="__main__":
    # Example Vectors were taken from FIPS 197, Advanced Encryption Standard (AES): Appendix C
    
    example = 256   # choose a number according to the cryptosystem AES-128, AES-192, AES-256

    PLAINTEXT = bytearray.fromhex('00112233445566778899aabbccddeeff')
    
    if example == 128:
        KEY = bytearray.fromhex('000102030405060708090a0b0c0d0e0f')
        # round[10].output 69c4e0d86a7b0430d8cdb78070b4c55a
    elif example == 192:
        KEY = bytearray.fromhex('000102030405060708090a0b0c0d0e0f1011121314151617')
        # round[12].output dda97ca4864cdfe06eaf70a0ec0d7191
    elif example == 256:
        KEY = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        # round[14].output 8ea2b7ca516745bfeafc49904b496089

    print(f"PLAINTEXT={word_int_to_hex(PLAINTEXT)}\nKEY={word_int_to_hex(KEY)}")
    encrypt_res = encrypt(PLAINTEXT, KEY)
    print(f'Encryption results= {word_int_to_hex(encrypt_res)}')
    decrypt_res = decrypt(encrypt_res, KEY)
    print(f'Decription results= {word_int_to_hex(decrypt_res)}')

