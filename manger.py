import logging
import os
import math

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

# setup
def generate_keypair(size_N_in_bits):
    size_prime = 1 << (size_N_in_bits / 2)
    while True:
        p = random_prime(size_prime)
        q = random_prime(size_prime)
        N = p * q
        phi = (p-1)*(q-1)
        e = 17
        if gcd(e, phi) != 1:
            continue
        # will sometimes not work, generate another setup?
        d = inverse_mod(e, phi)
        break
    return e, d, N

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
def Manger(key_size, logging):
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
    #ciphertext = pub.encrypt(b"lol", PKCS1v15())
    padded = padding(plaintext, N_size)
    logging.info("to find: %d" % padded)
    ciphertext = pow(padded, e, N)
    # setup 3
    B = lower(N_size)
    total_msg = 0

    # setup attack
    N_bit_length = (N_size - 2) * 8

    # attack
    f1 = 2
    leak = 0

    # step 1
    logging.info("step 1.")
    while True:
        c2 = (ciphertext * pow(f1, e, N)) % N
        total_msg += 1
        leak = oracle_length(c2, d, N)
        if leak == N_size:
            logging.info("step 1.3b")
            break
        logging.info("step 1.3a")
        f1 = 2 * f1

    logging.info(str(total_msg) + " messages")

    # Step 2.
    logging.info("Step 2.")
    f2 = (N+B) // B
    f2 = f2 * (f1 // 2)
    while True:
        c2 = (ciphertext * pow(f2, e, N)) % N
        total_msg += 1
        leak = oracle_length(c2, d, N)
        if leak < N_size:
            logging.info("step 2.3b")
            break
        logging.info("step 2.3a")
        f2 = f2 + (f1//2)
    logging.info(str(total_msg) + " messages")
    
    # step 3.
    logging.info("Step 3.")
    m_min = ceildiv(N, f2)
    m_max = (N+B) // f2
    logging.info("\n- m_min: %d\n- m_max: %d\n" % (m_min, m_max))
    m = [m_min, m_max]
    while True:
        # find good f3
        f_tmp = 2*B // (m_max - m_min)
        i = f_tmp * m_min // N
        f3 = ceildiv(i * N, m_min)
        # try the oracle
        c2 = (ciphertext * pow(f3, e, N)) % N
        total_msg += 1
        leak = oracle_length(c2, d, N)
        # branch
        if leak < N_size:
            logging.info("step 3.5b")
            m_max = (i * N + B) // f3
        else:
            logging.info("3.5a")
            m_min = ceildiv(i * N + B, f3)
        logging.info("\n- m_min: %d\n- m_max: %d\n" % (m_min, m_max))
        if m_min == m_max:
            break

    if m_min != padded:
        logging.fatal("algorithm did not work")
        exit(1)
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
    logger.setLevel(logging.DEBUG)
    Manger(512, logger)
