# Generate public keys to use in DRE machine
# They can be used in verification phase

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



def key_generation():
    # Find a cyclic group Zq
    q = randint(10000, 100000)
    while not isprime(q):
        q = randint(10000, 100000)
    # find p-1 prime factorization
    n = q-1
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
    g1 = find_generator(q, factors)
    g2 = find_generator(q, factors)
    while g2 == g1:
        g2 = find_generator(q)
    # Chooses five random values (x1, x2, y1, y2, z) from 0~q-1
    private_list = [] 
    for i in range(5):
        private_list.append(randint(1, q-1))
    # Compute c, d, h
    c = g1^private_list[0] * g2^private_list[1]
    d = g1^private_list[2] * g2^private_list[3]
    h = g1^private_list[4]
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
    c, d, h, q, g1, g2 = key_generation_modify()
    print("(c, d, h): ", c, d, h)
    print("q = ", q)
    print("g1 = ", g1)
    print("g2 = ", g2)



# def key_generation():
#     # 1. Find a cyclic group Z*p
#     #       find a prime p and q such that p = q*k + 1
#     q = 99377
#     k = 1
#     while not isprime(q * k + 1):
#         k = k + 1
#     p = q*k+1

#     # 2. Find the generator Gq
#     #       find g that is relatively prime to p, and be a generator of the Z*p
#     #       geneator criteria:
#     #           since p-1 = 298131 * 10, so pow(g, 298131, p) != 1 and pow(g, 10, p) != 1
#     g = find_generator(p)
#     gq = pow(g, k, p)
#     if pow(g, q*k, p) == 1:
#         print("Gq passed.")
#     else:
#         print("Gq failed.")

#     # 3. Find g1 and g2 from Gq
#     #       a, b should be relatively prime to q
#     #       g1 = pow(gq, a, p), g2 = pow(gq, b, p)
#     a = randint(100, q-1)
#     while not isprime(a):
#         a = randint(100, q-1)

#     b = randint(100, q-1)
#     while not isprime(b) or b == a:
#         b = randint(100, q-1)

#     g1 = pow(gq, a, p)
#     g2 = pow(gq, b, p)

#     # generate c, d, h
#     # private_list = [x1, x2, y1, y2, z]
#     private_list = [] 
#     for i in range(5):
#         private_list.append(randint(1, q-1))

#     c = g1^private_list[0] * g2^private_list[1]
#     d = g1^private_list[2] * g2^private_list[3]
#     h = g1^private_list[4]

#     return c, d, h, gq, q, g1, g2
