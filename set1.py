
# Challenge 1

hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
b64_str = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

def hex_to_b64(hex_str):
    return hex_str.decode("hex").encode("base64").strip()

assert hex_to_b64(hex_str) == b64_str


# Challenge 2

buf1 = "1c0111001f010100061a024b53535009181c"
buf2 = "686974207468652062756c6c277320657965"
res  = "746865206b696420646f6e277420706c6179"

import binascii

def xor_bufs(buf1, buf2):
    # print(list(binascii.unhexlify(buf1)))
    # print(list(binascii.unhexlify(buf2)))
    hex_buf1 = [ord(x) for x in binascii.unhexlify(buf1)]
    hex_buf2 = [ord(x) for x in binascii.unhexlify(buf2)]
    res = bytearray()
    for i in range(len(hex_buf1)):
        res.append(hex_buf1[i] ^ hex_buf2[i])
    return str(res).encode("hex")

# xored = xor(buf1, buf2)
# assert xored == res


# Challenge 3

import enchant
d = enchant.Dict("en_US")

message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

def score_str(string):
    score = 0
    for token in string.split():
        token = ''.join([c for c in token if ord(c) > 33 and ord(c) < 123])
        if len(token) > 2:
            if d.check(token):
                score += 1
    return score

def xor_buf_with_char(buf, i):
    ords = [ord(x) for x in binascii.unhexlify(buf)]
    xors = [o^i for o in ords]
    chrs = [chr(c) for c in xors]
    return ''.join(chrs)


def best_guess_decryption(buf):
    triples = []
    for i in range(256):
        string = xor_buf_with_char(buf, i)
        score = score_str(string)
        triples.append((score, string, i))
    s_triples = reversed(sorted(triples, key=lambda k: k[0]))
    return s_triples.next()
    
# print best_guess_decryption(message)


# Challenge 4

from tqdm import tqdm

def challenge4():
    with open('4.txt', 'r') as f:
        lines = f.readlines()
        decrypts = []
        for line in tqdm(lines):
            decrypts.append(best_guess_decryption(line.strip()))

        s_decrypts = reversed(sorted(decrypts, key=lambda k: k[0]))

        print s_decrypts.next()


# Challenge 5

from itertools import cycle

string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
res = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"+\
      "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

def repeating_key_xor(string, key="ICE"):
    ice_cycle = cycle([ord(c) for c in key])
    ords = [ord(x) for x in string]
    res = []
    for o in ords:
        ice_char = ice_cycle.next()
        xored = o ^ ice_char
        res.append(xored)
    res_str = ''.join([chr(o).encode("hex") for o in res])
    return res_str

assert repeating_key_xor(string) == res
