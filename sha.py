"""
This module provides methods to hash string values using SHA1.
It also provides the intermediate hashing function hash() which
can be used to perform a message extension attack.
"""

# Size of blocks in SHA1 (FIPS 180-4 1)
BIT_MASK_512 = int("f" * 128, 16)

# Size of words in SHA1 (FIPS 180-4 1)
WORD_BIT_LENGTH = 32
WORD_BIT_MASK = 0xffffffff

# The initial hash value H^0 (FIPS 180-4 5.3.1)
IV = 0x67452301efcdab8998badcfe10325476c3d2e1f0

# Print intermediate values if verbose is enabled
VERBOSE = False


def sha1(msg: str) -> str:
    """
    Pre-process the message with padding, parse it into blocks,
    and hash each block using hash(iv, b) where iv is the previous
    hash value and b is the current block. (FIPS 180-4 6.1)
    """
    blocks = parse(pad(msg))
    cv = IV
    for block in blocks:
        cv = hash(cv, block)
    return "{:040x}".format(cv)


def hash(iv: int, msg_block: int) -> int:
    """
    Hash the given block using the given intermediate value (IV).
    (FIPS 180-4 6.1.2)
    """
    h0, h1, h2, h3, h4 = extract_words(iv, total_bits=160)
    a, b, c, d, e = h0, h1, h2, h3, h4
    W = schedule(msg_block)

    __print_schedule(W)
    __print_round_header()
    for t in range(80):
        T = add(ROTL(a, 5), ft(t, b, c, d), e, K(t), W[t])
        e = d
        d = c
        c = ROTL(b, 30)
        b = a
        a = T
        __print_round(t, a, b, c, d, e, ft(t, b, c, d), K(t), W[t])

    return combine_words(add(a, h0), add(b, h1), add(c, h2), add(d, h3), add(e, h4))


def pad(msg: str) -> int:
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
    # by a 1-bit, k 0-bits, and 64 bits for length
    bits <<= 1 + k + 64

    # Add the 1-bit
    bits |= (1 << (k + 64))

    # Add the 64-bit length to the end
    bits |= l

    return bits


def parse(padded_msg: int) -> list:
    """
    Parse the padded message into 512-bit blocks. (FIPS 180-4 5.2.1)
    """
    num_bits = padded_msg.bit_length()

    # Round num_bits to the nearest 512, then divide by 512
    num_blocks = (512 * round(num_bits / 512)) // 512

    # The blocks are the 512-bit sections of the padded message
    return [(padded_msg >> (i * 512) & BIT_MASK_512)
            for i in range(0, num_blocks)][::-1]


def schedule(msg_block: int):
    """
    Build the message schedule for the given block. (FIPS 180-4 6.1.2)
    """
    W = extract_words(msg_block, total_bits=512) + [0] * 64
    for t in range(16, 80):
        W[t] = ROTL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1)
    return W


def ROTL(x: int, n: int) -> int:
    """
    The rotate left operation, where x is a w=32-bit word
    and n is an integer with 0 <= n < w. (FIPS 180-4 2.2.2)
    """
    return ((x << n) | (x >> (WORD_BIT_LENGTH - n))) & WORD_BIT_MASK


def ft(t: int, x: int, y: int, z: int) -> int:
    """
    Each function ft operates on three 32-bit words, x, y, and z, 
    and produces a 32-bit word as output. (FIPS 180-4 4.1.1)
    """
    if 0 <= t <= 19:
        return (x & y) ^ (~x & z)
    elif 20 <= t <= 39:
        return x ^ y ^ z
    elif 40 <= t <= 59:
        return (x & y) ^ (x & z) ^ (y & z)
    elif 60 <= t <= 79:
        return x ^ y ^ z


def K(t: int) -> int:
    """
    SHA-1 uses a sequence of eighty constant 32-bit words: 
    K0, K1,..., K79. (FIPS 180-4 4.2.1)
    """
    if 0 <= t <= 19:
        return 0x5a827999
    elif 20 <= t <= 39:
        return 0x6ed9eba1
    elif 40 <= t <= 59:
        return 0x8f1bbcdc
    elif 60 <= t <= 79:
        return 0xca62c1d6


def extract_words(val: int, total_bits: int) -> list[int]:
    """
    Given an integer, extract it into an array of words.
    """
    return [(val >> (i * WORD_BIT_LENGTH)) & WORD_BIT_MASK for i in range(0, total_bits // WORD_BIT_LENGTH)][::-1]


def combine_words(*args: list[int]) -> int:
    """
    Given an array of word values, combine them into a single integer value.
    """
    total_bits = len(args) * WORD_BIT_LENGTH
    val = 0
    for i in range(0, len(args)):
        val |= args[i] << total_bits - ((i + 1) * WORD_BIT_LENGTH)
    return val


def add(*args: list[int]) -> int:
    """
    Perform addition (+) modulo 2^32. (FIPS 180-4 6.1.2)
    """
    return sum(args) & WORD_BIT_MASK


def __print_round(t: int, a: int, b: int, c: int, d: int, e: int, ft: int, Kt: int, Wt: int) -> None:
    """ Print the current round's values if verbose is enabled. """
    if VERBOSE:
        print(
            f"{t:<3}  {a:<08x}  {b:<08x}  {c:<08x}  {d:<08x}  {e:<08x}  {ft:<08x}  {Kt:<08x}  {Wt:<08x}")


def __print_round_header() -> None:
    """ Print the round header if verbose is enabled. """
    if VERBOSE:
        print(
            f"\n{'t':<3}  {'a':<8}  {'b':<8}  {'c':<8}  {'d':<8}  {'e':<8}  {'f(t)':<8}  {'K(t)':<8}  {'W[t]':<8}")


def __print_schedule(W: list[int]) -> None:
    """ Print the message schedule values if verbose is enabled. """
    if VERBOSE:
        for i in range(0, 80, 10):
            vals = '  '.join("{:08x}".format(w) for w in W[i:i+10])
            W_range = f"[{i}...{i+9}]"
            print(f"W{W_range:<9} = {vals}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="sha",
        description="Hash values using the SHA1 algorithm")
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="enable verbose logging")
    parser.add_argument("value",
                        type=str,
                        help="the value to hash")
    args = parser.parse_args()
    VERBOSE = args.verbose

    print(sha1(args.value))
