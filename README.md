# python-sha1
![Test](https://github.com/joeylemon/python-sha1/workflows/Test/badge.svg)

An implementation of the SHA-1 algorithm in Python, following the Federal Information Processing Standards Publication 180-4 ([FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)) specification sheet.

## Motivation

As students in COSC483: Applied Cryptography at the [University of Tennessee Knoxville](https://utk.edu/), we were tasked with implementing a modified version of the SHA-1 algorithm in any programming language of our choice. This modified SHA-1 implementation would allow users to start in the middle of a SHA-1 hashing operation given a previous intermediate value. This functionality allows adversaries to carry out a [length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack). Therefore, using our SHA-1 implementation, we were then tasked with carrying out such an attack in a simulated environment.

## How to Hash

This program requires [Python3](https://www.python.org/downloads/). It was specifically tested with Python v3.9.0.

To hash a given string, run the command:
```sh
> python sha.py mystring
```

To observe the intermediate values for each round of SHA-1, enable verbose logging:
```sh
> python sha.py -v mystring
```

## How to Perform MAC Attack

Given a message `No one has completed Project #3 so give them all a 0.` and its accompanying MAC `d907cdfc9f6107b8180ef703517944280478f178`, you can perform the length extension attack with the following command:
```sh
> python attack.py --mac d907cdfc9f6107b8180ef703517944280478f178 "No one has completed Project #3 so give them all a 0." "P.S. Except for Joey Lemon, go ahead and give him the full points."
```

## How to Test

This program is accompanied by a suite of unit tests designed to ensure the correct functionality of every routine involved in the SHA-1 algorithm. To execute the unit tests, run the command:

```sh
> python -m unittest
```
