import unittest
import hashlib
import random
import string
import sha


class TestUtilities(unittest.TestCase):
    def test_create_hex_value(self):
        self.assertEqual(
            sha.create_hex_value([0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc], 32),
            0xaaaaaaaabbbbbbbbcccccccc)
        self.assertEqual(
            sha.create_hex_value([0x00010000, 0xbbbbbbbb, 0x00001000], 32),
            0x00010000bbbbbbbb00001000)
        self.assertEqual(
            sha.create_hex_value([0xaa, 0xbb, 0xcc], 8),
            0xaabbcc)
        self.assertNotEqual(
            sha.create_hex_value([0xaa, 0xbb, 0xcc], 32),
            0xaabbcc)

    def test_extract_hex_words(self):
        self.assertEqual(
            sha.extract_hex_words(0xaabbccddeeffaabb, total_bits=64),
            [0xaabbccdd, 0xeeffaabb])
        self.assertEqual(
            sha.extract_hex_words(
                0xaaaaaaaabbbbbbbbccccccccdddddddd, total_bits=128),
            [0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd])
        self.assertEqual(
            sha.extract_hex_words(
                0x67452301efcdab8998badcfe10325476c3d2e1f0, total_bits=160),
            [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0])

    def test_ROTL(self):
        self.assertEqual(sha.ROTL(0xaabbccdd, 4), 0xabbccdda)
        self.assertEqual(sha.ROTL(0xdeadbeef, 4), 0xeadbeefd)
        self.assertEqual(
            sha.ROTL(0b10100000000000000000000000000001, 1),
            0b01000000000000000000000000000011)


class TestSHA(unittest.TestCase):
    def get_bin(self, string):
        """
        Get the binary representation of the given string.
        e.g. get_bin("ab") => "0110000101100010"
        """
        return ''.join(["{:08b}".format(ord(c)) for c in string])

    def rand_str(self, n):
        """ Get a random string of size n. """
        return ''.join(random.choice(string.printable) for _ in range(n))

    def test_pad(self):
        msg = self.get_bin("a")
        self.assertEqual(
            sha.pad("a"),
            int(msg + '1' + '0' * (512 - len(msg) - 65) + "{:064b}".format(len(msg)), 2))

        msg = self.get_bin("abc")
        self.assertEqual(
            sha.pad("abc"),
            int(msg + '1' + '0' * (512 - len(msg) - 65) + "{:064b}".format(len(msg)), 2))

        # Since message is > 447, there should be 2 blocks of 512 bits
        msg = self.get_bin("abc" * 19)
        self.assertEqual(
            sha.pad("abc" * 19),
            int(msg + '1' + '0' * (1024 - len(msg) - 65) + "{:064b}".format(len(msg)), 2))

        # Since message is > 447*2, there should be 3 blocks of 512 bits
        msg = self.get_bin("teststring" * 12)
        self.assertEqual(
            sha.pad("teststring" * 12),
            int(msg + '1' + '0' * (1536 - len(msg) - 65) + "{:064b}".format(len(msg)), 2))

    def test_parse(self):
        msg = self.get_bin("abc" * 19)
        padded_str = msg + '1' + '0' * \
            (1024 - len(msg) - 65) + "{:064b}".format(len(msg))
        self.assertEqual(
            sha.parse(int(padded_str, 2)),
            [int(padded_str[:512], 2), int(padded_str[512:], 2)])

        msg = self.get_bin("teststring" * 12)
        padded_str = msg + '1' + '0' * \
            (1536 - len(msg) - 65) + "{:064b}".format(len(msg))
        self.assertEqual(
            sha.parse(int(padded_str, 2)),
            [int(padded_str[:512], 2), int(padded_str[512:1024], 2), int(padded_str[1024:], 2)])

    def test_sha1(self):
        for _ in range(100):
            rand_msg = self.rand_str(100)
            self.assertEqual(hashlib.sha1(
                rand_msg.encode()).hexdigest(), sha.sha1(rand_msg))


if __name__ == "__main__":
    unittest.main()
