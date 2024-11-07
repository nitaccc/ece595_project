# Generate public keys to use in DRE machine
# They can be used in verification phase

from sympy import isprime
from random import randint



def find_generator(p):
    g = randint(10000, p-1)
    while True:
        g = randint(1000, p-1)
        if isprime(g) and pow(g, 298131, p)!=1 and pow(g, 10, p) != 1:
            return g



def key_generation():
    # 1. Find a cyclic group Z*p
    #       find a prime p and q such that p = q*k + 1
    q = 99377
    k = 1
    while not isprime(q * k + 1):
        k = k + 1
    p = q*k+1

    # 2. Find the generator Gq
    #       find g that is relatively prime to p, and be a generator of the Z*p
    #       geneator criteria:
    #           since p-1 = 298131 * 10, so pow(g, 298131, p) != 1 and pow(g, 10, p) != 1
    g = find_generator(p)
    gq = pow(g, k, p)
    if pow(g, q*k, p) == 1:
        print("Gq passed.")
    else:
        print("Gq failed.")

    # 3. Find g1 and g2 from Gq
    #       a, b should be relatively prime to q
    #       g1 = pow(gq, a, p), g2 = pow(gq, b, p)
    a = randint(100, q-1)
    while not isprime(a):
        a = randint(100, q-1)

    b = randint(100, q-1)
    while not isprime(b) or b == a:
        b = randint(100, q-1)

    g1 = pow(gq, a, p)
    g2 = pow(gq, b, p)

    # generate c, d, h
    # private_list = [x1, x2, y1, y2, z]
    private_list = [] 
    for i in range(5):
        private_list.append(randint(1, q-1))

    c = g1^private_list[0] * g2^private_list[1]
    d = g1^private_list[2] * g2^private_list[3]
    h = g1^private_list[4]

    return c, d, h, gq, q, g1, g2



if __name__ == '__main__':
    c, d, h, gq, q, g1, g2 = key_generation()
    print("(c, d, h): ", c, d, h)
    print("Gq = ", gq)
    print("q = ", q)
    print("g1 = ", g1)
    print("g2 = ", g2)