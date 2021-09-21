import unittest
import random
import string
import attack


class TestAttack(unittest.TestCase):
    def rand_str(self, n):
        """ Get a random string of size n. """
        return ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(n))

    def test_runs(self):
        """ Ensure messages are extended correctly by comparing MAC' with HMAC(S, m') """
        for _ in range(100):
            S = self.rand_str(16)
            m = self.rand_str(random.randint(1, 100))
            m_malicious = self.rand_str(random.randint(1, 100))
            _, MAC_prime, HMAC = attack.run(S, m, m_malicious)
            self.assertEqual(MAC_prime, HMAC)


if __name__ == "__main__":
    unittest.main()
