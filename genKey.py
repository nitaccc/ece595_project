# Generate public keys to use in DRE machine

from sympy import isprime
from random import randint
from math import gcd



def find_generator(q, factors):
    while True:
        g = randint(100, q-1)
        # check gcd(g, p) == 1
        if gcd(g, q) != 1:
            continue
        # cal g^((q-1)/factor) mod q, if result == 1, then g is not a generator
        for i in factors:
            if pow(g, int((q-1)/i), q) == 1:
                continue
        break
    return g



def key_generation(question_num):
    c = []
    d = []
    h = []
    q = []
    g1 = []
    g2 = []
    for i in range(question_num):
        # Find a cyclic group Zq
        q_tmp = randint(10000, 100000)
        while not isprime(q_tmp):
            q_tmp = randint(10000, 100000)
        q.append(q_tmp)
        # find p-1 prime factorization
        n = q_tmp-1
        i = 2
        factors = []
        while i * i <= n:
            if n % i:
                i += 1
            else:
                n //= i
                factors.append(i)
        if n > 1:
            factors.append(n)
        # Find two generators g1, g2
        tmp = find_generator(q_tmp, factors)
        g1.append(tmp)
        tmp = find_generator(q_tmp, factors)
        while tmp == g1[-1]:
            tmp = find_generator(q_tmp, factors)
        g2.append(tmp)
        # Chooses five random values (x1, x2, y1, y2, z) from 0~q-1
        private_list = [] 
        for i in range(5):
            private_list.append(randint(1, q_tmp-1))
        # Compute c, d, h
        c.append(g1[-1]^private_list[0] * g2[-1]^private_list[1])
        d.append(g1[-1]^private_list[2] * g2[-1]^private_list[3])
        h.append(g1[-1]^private_list[4])
        # (c, d, h) is published along with the description of q, g1, g2 as its public key

    f = open("publicKey.txt", "w")
    f.write("c: " + str(c))
    f.write("\nd: " + str(d))
    f.write("\nh: " + str(h))
    f.write("\nq: " + str(q))
    f.write("\ng1: " + str(g1))
    f.write("\ng2: " + str(g2))
    f.close()

    return c, d, h, q, g1, g2



if __name__ == '__main__':
    c, d, h, q, g1, g2 = key_generation(2)
    print("(c, d, h): ", c, d, h)
    print("q = ", q)
    print("g1 = ", g1)
    print("g2 = ", g2)