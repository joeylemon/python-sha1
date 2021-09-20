# Size of blocks in SHA1 (FIPS 180-4 1)
BIT_MASK_512 = int("f" * 128, 16)

# Size of words in SHA1 (FIPS 180-4 1)
WORD_BIT_LENGTH = 32
WORD_BIT_MASK = 0xffffffff

# The initial hash value H^0 (FIPS 180-4 5.3.1)
IV = 0x67452301efcdab8998badcfe10325476c3d2e1f0


def ROTL(x, n):
    """
    The rotate left operation, where x is a w=32-bit word
    and n is an integer with 0 <= n < w. (FIPS 180-4 2.2.2)
    """
    return ((x << n)|(x >> (WORD_BIT_LENGTH - n))) & WORD_BIT_MASK
 

def ROTR(x, n):
    """
    The rotate right operation, where x is a w=32-bit word
    and n is an integer with 0 <= n < w. (FIPS 180-4 2.2.2)
    """
    return ((x >> n)|(x << (WORD_BIT_LENGTH - n))) & WORD_BIT_MASK


def ft(t, x, y, z):
    """
    Each function ft operates on three 32-bit words, x, y, and z, 
    and produces a 32-bit word as output. (FIPS 180-4 4.1.1)
    """
    if t >= 0 and t <= 19:
        # Ch(x,y,z)
        return (x & y) ^ (~x & z)
    elif t >= 20 and t <= 39:
        # Parity(x,y,z)
        return x ^ y ^ z
    elif t >= 40 and t <= 59:
        # Maj(x,y,z)
        return (x & y) ^ (x & z) ^ (y ^ z)
    elif t >= 60 and t <= 79:
        # Parity(x,y,z)
        return x ^ y ^ z


def K(t):
    """
    SHA-1 uses a sequence of eighty constant 32-bit words: 
    K0, K1,..., K79. (FIPS 180-4 4.2.1)
    """
    if t >= 0 and t <= 19:
        return 0x5a827999
    elif t >= 20 and t <= 39:
        return 0x6ed9eba1
    elif t >= 40 and t <= 59:
        return 0x8f1bbcdc
    elif t >= 60 and t <= 79:
        return 0xca62c1d6


def pad(msg):
    """
    Pad the ASCII message into a multiple of 512 and return an integer
    equivalent to the bits of the padded message. (FIPS 180-4 5.1.1)
    """

    # Suppose that the length of the message is l bits
    l = len(msg) * 8

    # k zero bits, where k is the smallest, non-negative 
    # solution to the equation l + 1 + k = 448 mod 512
    k = (448 - l - 1) % 512

    # Convert the msg characters to 8-bit binary strings
    bits = int(''.join("{:08b}".format(ord(c)) for c in msg), 2)

    # Put the message to the far left so it can be followed
    # by a 1-bit, k 0-bits, and 64-bits for length
    bits <<= 1 + k + 64

    # Add the 1-bit
    bits |= (1 << (k + 64))

    # Add the 64-bit length to the end
    bits |= l

    return bits


def parse(padded_msg):
    """
    Parse the padded message into 512-bit blocks. (FIPS 180-4 5.2.1)
    """
    num_bits = padded_msg.bit_length()
    num_blocks = num_bits // 512 if num_bits % 512 == 0 else (num_bits + 1) // 512
    blocks = [(padded_msg >> (i * 512) & BIT_MASK_512) for i in range(0, num_blocks)][::-1]
    print(num_blocks)
    for i, block in enumerate(blocks):
        print("\nBLOCK " + str(i))
        print("{:0512b}".format(block))
    return blocks


def extract_hex_words(val, total_bits):
    """
    Given a hex value, extract it into an array of words
    """
    return [(val >> (i * WORD_BIT_LENGTH)) & WORD_BIT_MASK for i in range(0, total_bits // WORD_BIT_LENGTH)][::-1]


def create_hex_value(arr, elem_bit_size):
    """
    Given an array of bit values, combine them into a single integer value.
    """
    total_bits = len(arr) * elem_bit_size
    val = 0
    for i in range(0, len(arr)):
        val |= arr[i] << total_bits - ((i + 1) * elem_bit_size)
    return val


def add(a, b):
    """
    Perform addition (+) modulo 2^32 (FIPS 180-4 6.1.2)
    """
    return (a + b) % 2**32


def schedule(msg_block):
    """
    Build the message schedule for the given block. (FIPS 180-4 6.1.2)
    """
    W = extract_hex_words(msg_block, total_bits=512)
    for t in range(16, 80):
        W.append(ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1))
    return W
    

def hash(iv, msg_block):
    """
    Hash the given block using the given intermediate value (IV).
    (FIPS 180-4 6.1.2)
    """
    h0,h1,h2,h3,h4 = extract_hex_words(msg_block, total_bits=160)
    a,b,c,d,e = h0,h1,h2,h3,h4
    W = schedule(msg_block)

    for t in range(80):
        T = ROTL(a, 5) + ft(t, b, c, d) + e + K(t) + W[t]
        e = d
        d = c
        c = ROTL(b, 30)
        b = a
        a = T

    return create_hex_value([add(a, h0), add(b, h1), add(c, h2), add(d, h3), add(e, h4)], WORD_BIT_LENGTH)


def sha1(msg):
    """
    Pre-process the message with padding, parse it into blocks,
    and hash each block using hash(iv, b) where iv is the previous
    hash value and b is the current block. (FIPS 180-4 6.1)
    """
    blocks = parse(pad(msg))
    cv = IV
    for block in blocks:
        print(hex(cv))
        cv = hash(cv, block)
    return cv

"""
W0, W1, ..., W79        word schedule
a,b,c,d,e               working variables
H^0                     initial hash value
H^i_0, ... H^i_4        words of ith hash value
T                       temp word
M                       message
N                       number of blocks
ROTL^n(x)               circular left shift
"""


if __name__ == "__main__":
    padded_msg = pad("a" * 131)
    blocks = parse(padded_msg)
    print(hex(blocks[0]))
    print(hex(hash(IV, blocks[0])))
    print(hex(sha1("abc")))
    print(hex(add(0xffffffff, 0x00000002)))