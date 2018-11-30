import logging
import os
import math
import pdb
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import _modinv

# to do ceil() of large divisions
def ceildiv(a, b):
    return -(-a // b)

# helper
def get_byte_length(message):
    res = 0
    if (len(bin(message)) - 2) % 8 != 0:
        res += 1
    res += (len(bin(message)) - 2) // 8
    return res


# pad plaintext [00, 02, randoms, 00, messsage] of len target_length
def padding(message, target_length):
    # 02
    res = 0x02 << 8 * (target_length - 2)
    # random
    random_pad = os.urandom(target_length - 3 - get_byte_length(message))
    for idx, val in enumerate(random_pad):
        if val == 0:
            val = 1
        res += val << (len(random_pad) - idx + get_byte_length(message)) * 8
    # 00
    # message
    res += message

    return res


# a length oracle
def oracle_length(c, d, N):
    p = pow(c, d, N)
    return get_byte_length(p)

# our attack with Manger
def Benor(key_size, logging):
    # setup 1
    e = 65537
    priv = rsa.generate_private_key(
     public_exponent=e,
     key_size=key_size,
     backend=default_backend()
    )
    d = priv.private_numbers().d
    pub = priv.public_key()
    N = pub.public_numbers().n

    # setup 2
    N_size = ceildiv(priv.key_size, 8)
    plaintext = 0x6c6f6c  # "lol"
    padded = padding(plaintext, N_size)
    logging.info("to find: %d" % padded)
    ciphertext = pow(padded, e, N)

    # setup 3
    t = upper(N_size-1) # we choose t+1 = N/256
    total_msg = 0

    # full attack
    while True:
        # setup attack
        # note: we're starting with `i` = 1, which will always work (as the first
        #   byte of a padded message is set to 0).
        #   perhaps a random value is better here? Not sure...
        i = 1 
        leak = 0
        coeffs = []
        # step 1
        logging.info("step 1.")
        # finding i, j
        while True:
            c2 = (ciphertext * pow(i, e, N)) % N
            total_msg += 1
            leak = oracle_length(c2, d, N)
            if leak < N_size:
                logging.info("found one i such that i*m <= t")
                logging.info(str(i))
                coeffs.append(i)
                if len(coeffs) == 2:
                    break
            # note: I use a random value here so that the algorithm doesn't always choose
            #   the same `i` and `j`. (Although remember, `i` is always 1).
            i += random.randint(1, 100000) 

        logging.info(str(total_msg) + " messages")

        # Step 2. figure out which one is larger
        logging.info("Step 2. gcd(b, c)")
        i = coeffs[0] # b = i * m mod N
        j = coeffs[1] # c = j * m mod N
        # checks
        assert((i * padded) % N < t)
        assert((j * padded) % N < t)

        # gcd algorithm
        while True:
            logging.info("trying to sort b and c")
            c2 = (ciphertext * pow(j - i, e, N)) % N # E(j*m - i*m mod N)
            total_msg += 1
            leak = oracle_length(c2, d, N)
            if leak == N_size: # c < b
                i, j = j, i # now b < c
            # checks
            b = (padded * i) % N # c mod N
            c = (padded * j) % N # k*b mod N
            assert(b < c) # b < c

            logging.info("find largest k s.t. kb < c")
            """ Unfortunately this doesn't work because I don't know a good range
            k_min = 1
            k_max = t # is there a better range?
            k = 1
            while True:
                if k_max == k_min + 1:
                    k = k_max # the largest of the two
                else:
                    k = (k_max + k_min) // 2 # right in the middle
                c2 = (ciphertext * pow(j - k * i, e, N)) % N # E(j*m - k*i*m mod N)
                total_msg += 1
                leak = oracle_length(c2, d, N)
                if leak < N_size: # <= t
                    k_min = k
                else:
                    k_max = k-1
                if k_min == k_max:
                    k = k_min
                    logging.info("found it:" + str(k))
                    # let's still verify that (we're cheating)
                    c = (padded * j) % N # c mod N
                    kb = (padded * i*k) % N # k*b mod N
                    b = (padded * i) % N # b mod N
                    kp1b = (padded * i*(k+1)) % N # (k+1)*b mod N
                    assert(kb < c) # kb < c
                    assert(kp1b >= c) # (k+1)b > c
                    r = c - kb
                    assert(r < b)
                    assert(c == r + kb)
                    break
     #           logging.info("range of k: [" + str(k_min) + "," + str(k_max) + "]")
            """
            k = 1
            # finding k
            # note: the paper talks about a binary search,
            #   but to do one, we need an upperbound, which I don't think we have
            #   so I take the naive approach of incrementing `k`, starting from 1.
            #   this works well in practice because `k` seems to always be < 50
            while True:
                c2 = (ciphertext * pow(j - k * i, e, N)) % N # E(j*m - k*i*m mod N)
                total_msg += 1
                leak = oracle_length(c2, d, N)
                if leak >= N_size: # <= t
                    k -= 1
                    logging.info("found it:" + str(k))
                    # let's still verify that (we're cheating)
                    c = (padded * j) % N # c mod N
                    b = (padded * i) % N # b mod N
                    kb = (padded * i*k) % N # k*b mod N
                    kp1b = (padded * i*(k+1)) % N # (k+1)*b mod N
                    assert(kb <= c) # kb < c
                    assert(kp1b >= c) # (k+1)b > c
                    r = c - kb
                    logging.info("r:" + str(r))
                    assert(r < b)
                    assert(c == r + kb)
                    break
                k += 1

            logging.info("c <- b, b <- r") # with r = r_i * m = j*m - r_i * i * m mod N
            r_i = j - k * i
            j = i
            i = r_i

            logging.info("checking if we found the solution")
            c2 = (ciphertext * pow(i, e, N)) % N # E(d)
            if c2 == 0:
                logging.info("c2 == 0")
#                input("press a key")
                break
            if c2 == 1:
                logging.info("computing answer")
                solution = _modinv(i, N)
                assert(solution == padded)
                logging.info("found the plaintext")
                logging.info(str(total_msg) + " messages")
                return total_msg


# for N_size = 2:
# m_max = 11111111 11111111
def upper(num):
    return 2**(num*8) - 1

# for N_size = 2:
# m_min = 1 00000000
def lower(num):
    return 2**((num-1)*8) 

#
if __name__ == "__main__":
    logging.basicConfig()
    logger = logging.getLogger()
#    logger.setLevel(logging.DEBUG)
    print(Benor(1024, logger))
