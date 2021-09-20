import unittest
import sha

class TestUtilities(unittest.TestCase):
    def test_create_hex_value(self):
        self.assertEqual(
            sha.create_hex_value([0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc], 32), 
            0xaaaaaaaabbbbbbbbcccccccc)
        self.assertEqual(
            sha.create_hex_value([0xaa, 0xbb, 0xcc], 8), 
            0xaabbcc)
        self.assertNotEqual(
            sha.create_hex_value([0xaa, 0xbb, 0xcc], 32), 
            0xaabbcc)


    def test_extract_hex_words(self):
        self.assertEqual(
            sha.extract_hex_words(0xaabbccddeeffaabb, 64),
            [0xaabbccdd, 0xeeffaabb])
        self.assertEqual(
            sha.extract_hex_words(0xaaaaaaaabbbbbbbbccccccccdddddddd, 128),
            [0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0xdddddddd])


    def test_ROTL(self):
        self.assertEqual(sha.ROTL(0xaabbccdd, 4), 0xabbccdda)
        self.assertEqual(sha.ROTL(0xdeadbeef, 4), 0xeadbeefd)
        self.assertEqual(
            sha.ROTL(0b10100000000000000000000000000001, 1), 
            0b01000000000000000000000000000011)


    def test_ROTR(self):
        self.assertEqual(sha.ROTR(0xaabbccdd, 4), 0xdaabbccd)
        self.assertEqual(sha.ROTR(0xdeadbeef, 4), 0xfdeadbee)
        self.assertEqual(
            sha.ROTR(0b01111111111111111111111111111010, 1), 
            0b00111111111111111111111111111101)


class TestSHA(unittest.TestCase):
    def test_pad(self):
        self.assertEqual(
            sha.pad("a"),
            int('01100001' + '1' + '0' * 439 + '0' * 60 + '1000', 2))
        self.assertEqual(
            sha.pad("abc"),
            int('011000010110001001100011' + '1' + '0' * 423 + '0' * 59 + '11000', 2))


if __name__ == "__main__":
    unittest.main()