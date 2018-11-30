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

import sys

def print_meta(text):
    sys.stdout.write("=============== ")
    sys.stdout.write(text)
    sys.stdout.write(" ================")
    sys.stdout.write('\n')
    sys.stdout.flush()

def print_line(min, max, m, ranges):
#    print min, max, m, ranges
    # init
    to_draw = {}

    # - min -> 0
    # - max -> 100
    dist = max - min
    # calculate where ranges are
    l = ord('a')
    for r in ranges:
        down = round((r[0]-min)*100/dist)
        up = round((r[1]-min)*100/dist)
        for i in range(down, up+1):
            if i == down:
                to_draw[i] = "["
            elif i == up:
                to_draw[i] = "]"
            else:
                to_draw[i] = chr(l)
        l += 1
    # m
    pos_m = round((m-min)*100/dist)
    to_draw[pos_m-1] = "["
    to_draw[pos_m] = "m"
    to_draw[pos_m+1] = "]"
    # print
    for i in range(100):
        if i in to_draw:
           sys.stdout.write(to_draw[i])
        else:
            sys.stdout.write('-')
    sys.stdout.write('\n')
    sys.stdout.flush()

def bleichenbacher_padding():
    # time
    import time
    start_time = time.time()
    # setup
    e, d, N = generate_keypair(512)
    N_size = get_byte_length(N)
    plaintext = 0x6c6f6c # "lol"
    padded = padding(plaintext, N_size)
    print "to find:", padded
    ciphertext = power_mod(padded, e, N)

    # setup attack
    N_bit_length = (get_byte_length(N) - 2) * 8
    B = 1 << N_bit_length

    # debug
    print_meta("start")
    min_n = 0
    max_n = N
    print_line(min_n, max_n, padded, [])
    
    # attack
    previous_steps = [(2*B, 3*B-1)]
    mult = ceil(N / (3 * B)) - 1
    i = 1
    number_msg = 0

    while True:
        # debug
        print_meta("message #" + str(i))
        print_meta("zooming in")

        min_n = previous_steps[0][0]
        max_n = previous_steps[0][1]
        for r in previous_steps: # min_n, max_n based on previous step
            if r[0] < min_n:
                min_n = r[0]
            if r[1] > max_n:
                max_n = r[1]

        print_line(min_n, max_n, padded, previous_steps)

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
                    number_msg += 1
                    if oracle_padding(c2, d, N):
                        found = True
                        break
                if found:
                    break
                ri += 1
                
        else:
            while not oracle_padding(c2, d, N):
                number_msg += 1
                mult += 1 
                c2 = (ciphertext * power_mod(mult, e, N)) % N
        # debug
#        print "found a valid padding", c2
#        raw_input("press a key to enter next step...\n")
        # compute the new set of intervals
        new_interval = []
        for interval in previous_steps:
            min_range = (interval[0] * mult - 3 * B + 1) // N
            max_range = (interval[1] * mult - 2 * B) // N
#            print max_range + 1 - min_range, "possible r's"
#            print interval[0]
#            print interval[1]
            possible_r = min_range
#            print max_range + 1
            while possible_r < max_range + 1:
                new_min = max(interval[0], ceil((2*B+possible_r*N)/mult))
                new_max = min(interval[1], floor((3*B-1+possible_r*N)/mult))
                if new_min > interval[1] or new_max < interval[0]:
                    possible_r += 1
                    continue
                # found?
                if new_max == new_min:
#                    print "found!"
#                    print new_min
#                    print "did we find that?"
#                    print padded
#                    print "took", time.time() - start_time, "seconds"
                    return
                # nope
                new_interval.append((new_min, new_max))
#                print ""
                possible_r += 1
        # debug
        print_meta("reducing range")
        print_line(min_n, max_n, padded, new_interval)

        #
        previous_steps = new_interval
        i += 1
        # debug
#        print "\n"
#        print len(previous_steps), "potential intervals left:"
#        for interval in previous_steps:
#            print " - [", interval[0], ",", interval[1], "]"
#        print "\n"

if __name__ == "__main__":
    bleichenbacher_padding()
