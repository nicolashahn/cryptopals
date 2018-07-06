
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

message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

def score_str(string):
    d = enchant.Dict("en_US")
    score = 0
    for token in string.split():
        token = ''.join([c for c in token if ord(c) > 33 and ord(c) < 123])
        if len(token) > 1:
            if d.check(token):
                score += 1
    return score

def xor_buf_with_char(buf, i):
    ords = [ord(x) for x in binascii.unhexlify(buf)]
    xors = [o^i for o in ords]
    chrs = [chr(c) for c in xors]
    return ''.join(chrs)


def best_guess_decryption(buf, print_all=False):
    triples = []
    for i in range(256):
        string = xor_buf_with_char(buf, i)
        score = score_str(string)
        triples.append((score, string, i))
    s_triples = reversed(sorted(triples, key=lambda k: k[0]))
    return s_triples.next()[1]
    
print best_guess_decryption(message)
