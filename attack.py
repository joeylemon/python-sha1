"""
Perform a message extension attack using our SHA-1 implementation
that allows for hashing of intermediate values.
"""

import sha


# Size of the secret key (in bytes)
KEY_SIZE = 128 // 8

VERBOSE = False


def slice_bytes(val: int, n: int) -> int:
    """ Slice the first n bytes off of val. """
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    return int.from_bytes(val_bytes[n:], byteorder="big")


def concatenate(a: int, b: int) -> int:
    """ Concatenate b to the end of a. """
    a_bytes = a.to_bytes((a.bit_length() + 7) // 8, byteorder="big")
    b_bytes = b.to_bytes((b.bit_length() + 7) // 8, byteorder="big")
    return int.from_bytes(a_bytes + b_bytes, byteorder="big")


def extend(m: str, m_malicious: str, MAC: int):
    """
    Perform a message extension attack on the given message. Use the
    MAC as the initial value for SHA-1 since it has the secret baked in.
    """

    # Use sha.pad to automatically pad m for us.
    # Use "x" * KEY_SIZE as placeholder for the secret.
    padded_m = sha.pad(sha.encode_string("x"*KEY_SIZE + m))
    num_blocks = len(sha.parse(padded_m))

    # m' = m || padding || K || m_malicious
    m_prime = concatenate(padded_m, sha.encode_string(m_malicious))
    __debug_print("Mallory's calculated m_prime:")
    __print_hex_chars(m_prime)

    blocks = sha.parse(sha.pad(m_prime))

    # Compute the new MAC' by using the original MAC as the first IV
    cv = MAC
    for block in blocks[num_blocks:]:
        cv = sha.hash(cv, block)

    # Remove the "x" * KEY_SIZE placeholder secret
    return (slice_bytes(m_prime, KEY_SIZE), f"{cv:040x}")


def run(S: str, m: str, m_malicious: str, MAC: str = None):
    """
    Perform a test run by comparing the HMAC of the original message m
    (e.g. HMAC(S, m) = SHA1(S || m)) with the MAC of the extended message
    using m_malicious as the extension. Return the MAC' and HMAC(S, m').
    """
    # Create the secret as a 16-byte string. Pad as necessary.
    S = (S + "pad"*16)[:16]

    # Alice calculates MAC = SHA1(S || m)
    MAC_a = int(sha.sha1(sha.encode_string(S + m)), 16)
    if MAC:
        MAC_a = int(MAC, 16)

    # Mallory extends the message m and sends Bob m' and MAC'
    m_prime, MAC_prime = extend(m, m_malicious, MAC_a)

    # Bob calculates MAC = SHA1(S || m')
    MAC_b = sha.sha1(concatenate(sha.encode_string(S), m_prime))

    __debug_print("Bob will calculate SHA1 of:")
    __print_hex_chars(concatenate(sha.encode_string(S), m_prime))

    # MAC' should be equal to Bob's MAC
    return m_prime, MAC_prime, MAC_b


def __print_hex_chars(val: int) -> None:
    """
    Print a value in hexadecimal with ASCII characters printed only if
    verbose logging is enabled.
    """
    if VERBOSE:
        val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
        for b in val_bytes:
            if 0x20 <= b <= 0x7E:
                print(chr(b), end=" ")
            else:
                print(f"0x{b:x}", end=" ")
        print("\n")


def __get_hex(val: str) -> None:
    """ Get the hex representation of the given string. """
    return "".join(f'{ord(c):02x}' for c in val) + f' ("{val}")'


def __debug_print(*args):
    """ Print the given values only if verbose logging is enabled. """
    if VERBOSE:
        print(*args)


def __print(*args, color="0"):
    """ Print the values with the given color code. """
    print(f"\033[{color}m", end='')
    print(*args)
    print("\033[0m", end='')


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="sha",
        description="Hash values using the SHA1 algorithm")
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="enable verbose logging")
    parser.add_argument("secret",
                        type=str,
                        help="the secret to use for HMAC")
    parser.add_argument("message",
                        type=str,
                        help="the original message from Alice")
    parser.add_argument("malicious",
                        type=str,
                        help="the malicious message from Mallory")
    parser.add_argument("--mac",
                        type=str,
                        help="the MAC value for the given message")
    args = parser.parse_args()
    VERBOSE = args.verbose

    MAC = sha.sha1(sha.encode_string(args.secret + args.message))
    if args.mac:
        MAC = args.mac

    m_prime, MAC_prime, HMAC = run(args.secret, args.message, args.malicious, args.mac)

    __print("Alice calculates MAC as SHA1(S || m)", color="1;33")
    if not args.mac:
        __print(f"S=   0x{__get_hex(args.secret)}")
    __print(f"m=   0x{__get_hex(args.message)}")
    __print(f"MAC= 0x{MAC}")

    __print("\nMallory extends m to create m' = m || padding || K || malicious text", color="1;33")
    __print(f"malicious text= 0x{__get_hex(args.malicious)}")
    __print(f"m'= 0x{m_prime:x}")

    __print("\nMallory calculates a new MAC' using Alice's MAC as the intermediate value to SHA1:", color="1;33")
    __print(f"MAC'= 0x{MAC_prime}")

    __print("\nMallory sends m' and MAC' to Bob", color="1;33")

    if not args.mac:
        __print("Bob calculates the MAC of m' and compares it to Mallory's MAC:", color="1;33")
        __print(f"MAC= 0x{HMAC}")
