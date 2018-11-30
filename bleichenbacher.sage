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
        d = inverse_mod(e, phi) # will sometimes not work, generate another setup?
        break
    return e, d, N

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
        res += ord(val) << (len(random_pad) - idx + get_byte_length(message)) * 8
    # 00
    # message
    res += message

    return res

# a length oracle
def oracle_length(c, d, N):
    p = power_mod(c, d, N)
    return get_byte_length(p)

# a padding oracle
def oracle_padding(c, d, N):
    p = power_mod(c, d, N)
    if get_byte_length(p) != get_byte_length(N) - 1:
        return False
    if p >> ((get_byte_length(p) -1)) * 8 != 0x02: # this is not correct
        return False
    return True


def bleichenbacher_padding():
    # time
    import time
    start_time = time.time()
    # setup
    e, d, N = generate_keypair(1024)
    N_size = get_byte_length(N)
    plaintext = 0x6c6f6c # "lol"
    padded = padding(plaintext, N_size)
    print "to find:", padded
    ciphertext = power_mod(padded, e, N)

    # setup attack
    N_bit_length = (get_byte_length(N) - 2) * 8
    B = 1 << N_bit_length
    print hex(padded)
    print hex(B)
    
    # attack
    previous_steps = [(2*B, 3*B-1)]
    mult = ceil(N / (3 * B)) - 1
    i = 1
    while True:
        # debug
        print "Entering step", i
        # find a valid padding
        c2 = 0
        if i > 1 and len(previous_steps) == 1:
            previous_mult = mult
            ri = floor(2 * (previous_steps[0][1]*previous_mult - 2 * B) / N)
            found = False
            while True:
                mult = ceil((2*B+ri*N) / previous_steps[0][1]) - 1
                mult_max = ceil((3*B+ri*N)/previous_steps[0][0])
                while mult < mult_max:
                    mult += 1
                    c2 = (ciphertext * power_mod(mult, e, N)) % N
                    if oracle_padding(c2, d, N):
                        found = True
                        break
                if found:
                    break
                ri += 1
                
        else:
            while not oracle_padding(c2, d, N):
                mult += 1 
                c2 = (ciphertext * power_mod(mult, e, N)) % N
        # debug
        print "found a valid padding", c2
        # compute the new set of intervals
        new_interval = []
        for interval in previous_steps:
            min_range = (interval[0] * mult - 3 * B + 1) // N
            max_range = (interval[1] * mult - 2 * B) // N
            print max_range + 1 - min_range, "possible r's"
            print interval[0]
            print interval[1]
            possible_r = min_range
            print max_range + 1
            while possible_r < max_range + 1:
                new_min = max(interval[0], ceil((2*B+possible_r*N)/mult))
                new_max = min(interval[1], floor((3*B-1+possible_r*N)/mult))
                if new_min > interval[1] or new_max < interval[0]:
                    possible_r += 1
                    continue
                # found?
                if new_max == new_min:
                    print "found!"
                    print new_min
                    print "did we find that?"
                    print padded
                    print "took", time.time() - start_time, "seconds"
                    return
                # nope
                new_interval.append((new_min, new_max))
                print ""
                possible_r += 1
        previous_steps = new_interval
        i += 1
        # debug
        print "\n"
        print len(previous_steps), "potential intervals left:"
        for interval in previous_steps:
            print " - [", interval[0], ",", interval[1], "]"
        print "\n"

def bleichenbacher_length():
    # time
    import time
    start_time = time.time()
    # setup
    e, d, N = generate_keypair(2048)
    N_size = get_byte_length(N)
    plaintext = 0x6c6f6c # "lol"
    padded = padding(plaintext, N_size)
    print "to find:", padded
    ciphertext = power_mod(padded, e, N)

    # setup attack
    N_byte_length = get_byte_length(N)
    N_bit_length = (N_byte_length - 2) * 8
    B = 1 << N_bit_length
    print hex(padded)
    print hex(B)
    
    # attack
    previous_steps = [(2*B, 3*B-1)]
    mult = ceil(N / (3 * B)) - 1 # TODO: find a more relevant range
    i = 1
    while True:
        # debug
        print "Entering step", i
        # find a valid padding
        c2 = 0
        if i > 1 and len(previous_steps) == 1:
            print "entering step 2c."
            nn = N_byte_length - 2 # set it like that ...
            previous_mult = mult
            ri = floor(2 * (previous_steps[0][1]*previous_mult - 2^(8*(nn-1))) / N)
            found = False
            while True:
                mult = ceil((2^(8*(nn-1))+ri*N) / previous_steps[0][1]) - 1
                mult_max = ceil((2^(8*nn)-1+ri*N)/previous_steps[0][0])
                while mult < mult_max:
                    mult += 1
                    c2 = (ciphertext * power_mod(mult, e, N)) % N
                    if oracle_length(c2, d, N) == nn:
                        found = True
                        break
                if found:
                    break
                ri += 1
                
        else:
            print "entering step 2a or 2b."
            nn = N_byte_length + 10
            while not(nn < N_byte_length - 1):
                mult += 1 
                c2 = (ciphertext * power_mod(mult, e, N)) % N
                nn = oracle_length(c2, d, N)
        # debug
        print "found a valid padding", c2
        # compute the new set of intervals
        new_interval = []
        for interval in previous_steps:
            min_range = (interval[0]*mult - 2^(8*nn) - 1) // N
            max_range = (interval[1]*mult - 2^(8*(nn-1))) // N
            print "min, max range for r:", min_range, max_range + 1
            print max_range + 1 - min_range, "possible r's"
            print interval[0]
            print interval[1]
            possible_r = min_range

            while possible_r < max_range + 1:
                new_min = max(interval[0], ceil((2^(8*(nn-1))+possible_r*N)/mult))
                new_max = min(interval[1], floor((2^(8*nn)-1+possible_r*N)/mult))
                # if intersection of range doesn't exist, skip the new range
                if new_min > interval[1] or new_max < interval[0]:
                    possible_r += 1
                    continue
                # found?
                if new_max == new_min:
                    print "found!"
                    print new_min
                    print "did we find that?"
                    print padded
                    print "took", time.time() - start_time, "seconds"
                    return
                # nope
                new_interval.append((new_min, new_max))
                possible_r += 1
        previous_steps = new_interval
        i += 1
        # debug
        print "\n"
        print len(previous_steps), "potential intervals left:"
        for interval in previous_steps:
            print " - [", interval[0], ",", interval[1], "]"
        print "\n"


#    
if __name__ == "__main__":
    bleichenbacher_length()
    #bleichenbacher_padding()
