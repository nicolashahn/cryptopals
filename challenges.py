#!/usr/bin/env python


from random import randint
from itertools import cycle, combinations
from collections import Counter
from urlparse import parse_qs
from urllib import urlencode, unquote

from tqdm import tqdm
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor


# average distribution of letters in English text (in %)
LETTER_FREQ = {
    'E': 12.0,
    'T': 9.10,
    'A': 8.12,
    'O': 7.68,
    'I': 7.31,
    'N': 6.95,
    'S': 6.28,
    'R': 6.02,
    'H': 5.92,
    'D': 4.32,
    'L': 3.98,
    'U': 2.88,
    'C': 2.71,
    'M': 2.61,
    'F': 2.30,
    'Y': 2.11,
    'W': 2.09,
    'G': 2.03,
    'P': 1.82,
    'B': 1.49,
    'V': 1.11,
    'K': 0.69,
    'X': 0.17,
    'Q': 0.11,
    'J': 0.10,
    'Z': 0.07
}

# default AES blocksize
AES_BSZ = 16

# default hardcoded 128 bit key
DEFAULT_KEY = b'\x13\xef\xab"\x96S\xa9\x9a\xb2(;\x04\xb7V\xbc^'


# Challenge 1


def hex_to_b64(hex_str):
    return hex_str.decode("hex").encode("base64").strip()


def challenge1():
    hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    b64_str = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert hex_to_b64(hex_str) == b64_str


# Challenge 2


def xor_bufs(buf1, buf2, encoding="hex"):
    decoded_buf1 = [ord(x) for x in buf1.decode(encoding)]
    decoded_buf2 = [ord(x) for x in buf2.decode(encoding)]
    res = bytearray()
    for i in range(len(decoded_buf1)):
        res.append(decoded_buf1[i] ^ decoded_buf2[i])
    return str(res).encode(encoding)


def challenge2():
    buf1 = "1c0111001f010100061a024b53535009181c"
    buf2 = "686974207468652062756c6c277320657965"
    res = "746865206b696420646f6e277420706c6179"
    xored = xor_bufs(buf1, buf2)
    assert xored == res


# Challenge 3


def make_lf_norm(lf_dict):
    lf_total = sum(lf_dict.values())
    lf_norm = {k: lf_dict[k] / lf_total for k in lf_dict}
    return lf_norm


lf_norm = make_lf_norm(LETTER_FREQ)


def score_str(string):
    score = 0
    bad_chars = [c.upper() for c in string if
                 (ord(c) < 32 and ord(c) not in [0,9,10]) or ord(c) >= 128]
    if len(bad_chars):
        return 0
    uppers = [c.upper() for c in string]
    chars = [c for c in uppers if c in LETTER_FREQ]
    str_lf = Counter(chars)
    str_lf_norm = make_lf_norm(str_lf)
    for k in str_lf_norm:
        c_score = ((str_lf_norm[k] - lf_norm[k])**2)/lf_norm[k]
        score += c_score
    return score


def best_guess_decryption_ords(ords):
    triples = []
    for i in range(256):
        xors = [o^i for o in ords]
        string = ''.join([chr(x) for x in xors])
        score = score_str(string)
        triples.append((score, string, i))
    s_triples = reversed(sorted(triples, key=lambda k: k[0]))
    return s_triples.next()


def best_guess_decryption_hex_str(buf):
    ords = [ord(i) for i in buf.decode("hex")]
    return best_guess_decryption_ords(ords)


def challenge3():
    message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    decrypted = "Cooking MC's like a pound of bacon"
    assert best_guess_decryption_hex_str(message)[1] == decrypted


# Challenge 4


def challenge4():
    with open('4.txt', 'r') as f:
        lines = f.readlines()
        decrypts = []
        for line in tqdm(lines):
            decrypts.append(best_guess_decryption_hex_str(line.strip()))

        s_decrypts = reversed(sorted(decrypts, key=lambda k: k[0]))

        assert s_decrypts.next()[1] == 'Now that the party is jumping\n'


# Challenge 5


def repeating_key_xor(string, key="ICE", hex_encode=False):
    key_cycle = cycle([ord(c) for c in key])
    ords = [ord(x) for x in string]
    res = []
    for o in ords:
        key_char = key_cycle.next()
        xored = o ^ key_char
        res.append(xored)
    if hex_encode:
        chars = [chr(o).encode("hex") for o in res]
    else:
        chars = [chr(o) for o in res]
    return ''.join(chars)


def challenge5():
    string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    res = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"+\
          "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    assert repeating_key_xor(string, hex_encode=True) == res


# Challenge 6


def hamming_dist(bytes1, bytes2):
    """XOR two strings/ord lists and count number of 1s in the binary result."""
    if type(bytes1) == str:
        bytes1 = [ord(c) for c in str1]
    if type(bytes2) == str:
        bytes2 = [ord(c) for c in str2]
    bins = [bin(o1 ^ o2) for o1, o2 in zip(bytes1, bytes2)]
    return len([i for i in ''.join(bins) if i == '1'])


# test hamming_dist()
str1 = "this is a test"
str2 = "wokka wokka!!!"
assert hamming_dist(str1, str2) == 37


def get_keysize(ords, maxlen=41):
    """Use hamming dist to compare first $num_chunks to guess the key length."""
    sz_avgs = []
    for sz in range(2, maxlen):
        num_chunks = 4
        chunks = [ords[i:i + sz] for i in xrange(0, num_chunks*sz, sz)]
        hd_sum = 0.
        combos = combinations(chunks, 2)
        for combo in combos:
            hd_sum += hamming_dist(combo[0], combo[1])
        avg = hd_sum / sz
        sz_avgs.append((sz, avg))
    keysize = list(sorted(sz_avgs, key=lambda k: k[1]))[0][0]
    return keysize


def decrypt_rot_key_xor(ords):
    """List of ints(ord'd chars) -> decrypted string."""
    keysize = get_keysize(ords)
    # split ords into $keysize blocks
    chunks = [ords[i:i + keysize] for i in xrange(0, len(ords), keysize)]
    # blocks = {key char position: [all ords that key char position would encrypt]}
    blocks = {i: [] for i in range(keysize)}
    for chunk in chunks:
        for i in range(len(chunk)):
            blocks[i].append(chunk[i])

    # try to decrypt each chunk using letter frequency
    key_ords = []
    d_blocks = {i: [] for i in range(keysize)}
    for i in sorted(blocks.keys()):
        s_triple = best_guess_decryption_ords(blocks[i])
        d_blocks[i] = list(s_triple[1])
        key_ords.append(s_triple[2])

    key = ''.join([chr(c) for c in key_ords])
    string = ''.join([chr(c) for c in ords])
    return repeating_key_xor(string, key=key)
    # return res


def challenge6():
    with open('6.txt', 'r') as f:
        string = f.read()
        ords = [ord(x) for x in string.decode("base64")]
        print decrypt_rot_key_xor(ords)


# Challenge 7


def decrypt_aes_ecb(ciphertext, key):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.decrypt(ciphertext)


def challenge7():
    with open('7.txt', 'r') as f:
        string7 = f.read().decode('base64')
        key = "YELLOW SUBMARINE"
        print decrypt_aes_ecb(string7, key)


# Challenge 8


def detect_aes_ecb(ciphertexts):
    """ciphertexts: list of hex encoded ciphertext strings"""
    for ciphertext in ciphertexts:
        ords = [ord(x) for x in ciphertext.strip().decode("hex")]
        chunks = [tuple(ords[i:i + AES_BSZ])
                  for i in xrange(0, len(ords), AES_BSZ)]
        chunks_set = set(chunks)
        if len(chunks) != len(chunks_set):
            return ciphertext


def challenge8():
    with open('8.txt', 'r') as f:
        lines = f.readlines()
        print detect_aes_ecb(lines)


#########
# SET 2 #
#########


# Challenge 9


def pad_to_len(string, length, leftpad=False, pad_char=None):
    """
    Pad with byte values equal to the number of characters needed to pad to
    the given length (by default, if pad_char given, use that as the padding
    char instead).

    pad_to_len("abc", 6) -> "abc\x03\x03\x03"
    """
    pad_len = length - len(string)
    if not pad_char:
        pad_char = chr(pad_len)
    pad = pad_char * pad_len
    return pad + string if leftpad else string + pad


def pad_to_blocksize(string, blocksize=AES_BSZ, leftpad=False, pad_char=None):
    """
    Add padding to the string until it fits into even `blocksize` pieces.
    """
    if len(string) % blocksize == 0:
        return string
    length = len(string) + blocksize - (len(string) % blocksize)
    return pad_to_len(string, length, leftpad=leftpad, pad_char=pad_char)


def challenge9():
    assert pad_to_len("YELLOW SUBMARINE", 20) == \
        "YELLOW SUBMARINE\x04\x04\x04\x04"
    assert pad_to_len("YELLOW SUBMARINE", 21) == \
        "YELLOW SUBMARINE\x05\x05\x05\x05\x05"


# is this cheating? Yes
# def decrypt_aes_cbc(ciphertext, key, IV='\x00' * 16):
#     decipher = AES.new(key, AES.MODE_CBC, IV=IV)
#     return decipher.decrypt(ciphertext)


def decrypt_aes_cbc(ciphertext, key, IV=None):
    """ Mimics AES.new(key, AES.MODE_CBC).decrypt() """
    if not IV:
        IV = b'\x00' * AES_BSZ
    padded_ct = pad_to_blocksize(ciphertext)
    res = ''
    prev = IV
    for i in range(0, len(padded_ct), AES_BSZ):
        c_block = padded_ct[i:i + AES_BSZ]
        p_block = strxor(decrypt_aes_ecb(c_block, key), prev)
        res += p_block
        prev = c_block
    return res


def challenge10():
    with open('10.txt', 'r') as f:
        string10 = f.read().decode('base64')
        key = "YELLOW SUBMARINE"
        res = decrypt_aes_cbc(string10, key)
        print res


def randstr(length):
    return ''.join([chr(randint(0, 255)) for _ in range(length)])


def ecb_or_cbc_encrypt(plaintext, mode='random'):
    """
    Encrypts a plaintext using AES with either ECB or CBC mode, chosen at
    random if mode="random", also adding a few random bytes before and after
    the plaintext. Uses a random key and IV (for CBC) as well.
    """
    if mode == 'random':
        mode = 'ECB' if randint(0, 1) == 0 else 'CBC'

    key = randstr(AES_BSZ)
    plaintext = (
        ''.join([randstr(1) for _ in range(randint(5, 10))]) +
        plaintext +
        ''.join([randstr(1) for _ in range(randint(5, 10))])
    )
    plaintext = pad_to_blocksize(plaintext)

    if mode == 'ECB':
        ecb = AES.new(key, AES.MODE_ECB)
        ciphertext = ecb.encrypt(plaintext)
    elif mode == 'CBC':
        iv = randstr(AES_BSZ)
        cbc = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cbc.encrypt(plaintext)
    else:
        raise Exception("invalid mode")

    return ciphertext


def detect_ecb_or_cbc(func):
    """
    Given a function that is either encrypting using ECB or CBC, return True if
    the function is ECB, False if CBC.
    """
    plaintext = b'\x00' * 100
    ciphertext = func(plaintext)
    blocks = [ciphertext[i:i+AES_BSZ]
              for i in range(0, len(ciphertext), AES_BSZ)]
    xor_b0_b1 = strxor(blocks[0], blocks[1])
    xor_b0_b2 = strxor(blocks[0], blocks[2])
    sum_diff = sum(
        [abs(ord(x) - ord(y)) for x, y in zip(xor_b0_b1, xor_b0_b2)]
    )
    return sum_diff == 0


def challenge11():
    rand_res = detect_ecb_or_cbc(ecb_or_cbc_encrypt)
    print rand_res


def encrypt_ecb(plaintext, key=DEFAULT_KEY):
    ecb = AES.new(key, AES.MODE_ECB)
    return ecb.encrypt(plaintext)


def append_unknown_str_and_encrypt_ecb(my_plaintext, unknown_str):
    plaintext = pad_to_blocksize(my_plaintext + unknown_str)
    ciphertext = encrypt_ecb(plaintext) # uses DEFAULT_KEY
    return ciphertext


def decrypt_appended_str_ecb(unknown_str):

    def encryption_func(plaintext):
        return append_unknown_str_and_encrypt_ecb(plaintext, unknown_str)

    # find blocksize
    initial_len = len(encryption_func(""))
    blocksize = None
    i = 1
    while not blocksize:
        my_plaintext = 'a' * i
        curr_len = len(encryption_func(my_plaintext))
        if curr_len != initial_len:
            blocksize = curr_len - initial_len
        i += 1

    # ensure that the function is using ECB
    assert detect_ecb_or_cbc(encryption_func) == True

    known_str = ""
    while unknown_str:

        # craft input block with len + 1 % blocksize == 0
        short_block = 'a' * (blocksize - 1)

        # make dict of every possible last byte and the resulting ciphertext's
        # first block
        possibilities = {
            encryption_func(short_block + chr(x))[:blocksize]: chr(x)
            for x in range(256)
        }

        # match output of the one-byte-short input to one of the dict entries
        match_block = possibilities[ encryption_func(short_block)[:blocksize] ]
        # now we have the next byte of the unknown_str
        next_byte = match_block[-1]
        known_str += next_byte
        # by chopping off first unkown_str byte we can repeat process on the
        # next one
        unknown_str = unknown_str[1:]

    return known_str


def challenge12():
    unknown_str = (
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    ).decode('base64')
    print decrypt_appended_str_ecb(unknown_str)


def decode_cookie(cookie_str):
    raw_obj = parse_qs(cookie_str)
    return {k: v[0] for k, v in raw_obj.items()}


def encode_cookie(cookie_obj):
    return unquote(urlencode(cookie_obj))


def profile_for(user_email):
    user_email = user_email.replace('=', '').replace('&', '')
    user_obj = {
        'email': user_email,
        'uid': 10,
        'role': 'user'
    }
    return encode_cookie(user_obj)


def make_admin_profile(not_admin_profile):
    # TODO
    return not_admin_profile


def encrypt_profile(cookie_str):
    padded_cookie_str = pad_to_blocksize(cookie_str)
    aes = AES.new(DEFAULT_KEY, AES.MODE_ECB)
    encrypted_cookie = aes.encrypt(padded_cookie_str)
    return encrypted_cookie


def remove_padding(padded_str):
    pad_byte = ord(padded_str[-1])
    assert pad_byte <= AES_BSZ
    unpadded = padded_str[:-pad_byte]
    return unpadded


def decrypt_profile(cookie_ciphertext):
    aes = AES.new(DEFAULT_KEY, AES.MODE_ECB)
    padded_cookie_str = aes.decrypt(cookie_ciphertext)
    cookie_str = remove_padding(padded_cookie_str)
    return cookie_str


def challenge13():
    cookie_str = 'foo=bar&baz=qux&zap=zazzle'
    cookie_obj = {
        'foo': 'bar',
        'baz': 'qux',
        'zap': 'zazzle',
    }
    assert decode_cookie(cookie_str) == cookie_obj
    assert encode_cookie(cookie_obj) == cookie_str
    foobar_profile = profile_for('foo@bar.com')
    assert foobar_profile == 'role=user&email=foo@bar.com&uid=10'
    assert remove_padding('asdf\x03\x03\x03') == 'asdf'
    encrypted_profile = encrypt_profile(foobar_profile)
    assert decrypt_profile(encrypted_profile) == foobar_profile
    assert decode_cookie(make_admin_profile(foobar_profile))['role'] == 'admin'


def main():
    # challenge1()
    # challenge2()
    # challenge3()
    # challenge4()
    # challenge5()
    # challenge6()
    # challenge7()
    # challenge8()
    # challenge9()
    # challenge10()
    # challenge11()
    # challenge12()
    challenge13()


if __name__ == '__main__':
    main()
