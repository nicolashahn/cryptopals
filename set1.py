
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

from collections import Counter

message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
decrypted = "Cooking MC's like a pound of bacon"

letterFrequency = {'E' : 12.0,
'T' : 9.10,
'A' : 8.12,
'O' : 7.68,
'I' : 7.31,
'N' : 6.95,
'S' : 6.28,
'R' : 6.02,
'H' : 5.92,
'D' : 4.32,
'L' : 3.98,
'U' : 2.88,
'C' : 2.71,
'M' : 2.61,
'F' : 2.30,
'Y' : 2.11,
'W' : 2.09,
'G' : 2.03,
'P' : 1.82,
'B' : 1.49,
'V' : 1.11,
'K' : 0.69,
'X' : 0.17,
'Q' : 0.11,
'J' : 0.10,
'Z' : 0.07 }

def make_lf_norm(lf_dict):
    lf_total = sum(lf_dict.values())
    lf_norm = { k: lf_dict[k]/lf_total for k in lf_dict}
    return lf_norm

lf_norm = make_lf_norm(letterFrequency)

def score_str(string):
    score = 0
    bad_chars = [c.upper() for c in string if 
                 (ord(c) < 32 and ord(c) not in [0,9,10]) or ord(c) >= 128]
    if len(bad_chars):
        return 0
    uppers = [c.upper() for c in string]
    chars = [c for c in uppers if c in letterFrequency]
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
        string = ''.join([chr(i) for i in xors])
        score = score_str(string)
        triples.append((score, string, i))
    s_triples = reversed(sorted(triples, key=lambda k: k[0]))
    return s_triples.next()
    
def best_guess_decryption_hex_str(buf):
    ords = [ord(i) for i in binascii.unhexlify(buf)]
    return best_guess_decryption_ords(ords)

assert best_guess_decryption_hex_str(message)[1] == decrypted

# Challenge 4

from tqdm import tqdm

def challenge4():
    with open('4.txt', 'r') as f:
        lines = f.readlines()
        decrypts = []
        for line in tqdm(lines):
            decrypts.append(best_guess_decryption_hex_str(line.strip()))

        s_decrypts = reversed(sorted(decrypts, key=lambda k: k[0]))

        return s_decrypts.next()[1]

# assert challenge4() == 'Now that the party is jumping\n'


# Challenge 5

from itertools import cycle

string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
res = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"+\
      "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

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

assert repeating_key_xor(string, hex_encode=True) == res


# Challenge 6

from itertools import combinations

str1 = "this is a test"
str2 = "wokka wokka!!!"

def hamming_dist(bytes1, bytes2):
    if type(bytes1) == str:
        bytes1 = [ord(c) for c in str1]
    if type(bytes2) == str:
        bytes2 = [ord(c) for c in str2]
    bins = [bin(o1 ^ o2) for o1, o2 in zip(bytes1, bytes2)]
    return len([i for i in ''.join(bins) if i == '1'])

assert hamming_dist(str1, str2) == 37

def get_keysize(ords):
    sz_avgs = []
    for sz in range(2,41):
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

def challenge6():
    with open('6.txt', 'r') as f:
        string = f.read()
        ords = [ord(x) for x in string.decode("base64")]
        keysize = get_keysize(ords)
        chunks = [ords[i:i + keysize] for i in xrange(0, len(ords), keysize)]
        blocks = {i: [] for i in range(keysize)}
        for chunk in chunks:
            for i in range(len(chunk)):
                blocks[i].append(chunk[i])
        key_ords = []
        d_blocks = {i: [] for i in range(keysize)}
        for i in sorted(blocks.keys()):
            s_triple = best_guess_decryption_ords(blocks[i])
            d_blocks[i] = list(s_triple[1])
            key_ords.append(s_triple[2])
        res = ''
        while d_blocks:
            for i in sorted(d_blocks.keys()):
                res += d_blocks[i].pop(0)
            for i in d_blocks.keys():
                if not d_blocks[i]:
                    del d_blocks[i]
        # key = ''.join([chr(c) for c in key_ords])
        # return repeating_key_xor(string, key=key)
        return res

print challenge6()
