from random import randint
import hashlib
from genKey import key_generation





def DRE_receipt(i, c, d, h, gq, q, g1, g2, s1, n1):
    vi = input("Type 0 or 1: ")
    ri = randint(1, q-1)
    Ui = g1^ri
    Vi = g2^ri
    Ei = (h^ri) * (g1^vi)
    tmp = str(Ui) + str(Vi) + str(Ei)
    alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    alpha = int(alpha, 16)
    Wi = (c^ri) * (d^(ri*alpha))
    
    # needs to be modified
    Pwf = (Ui & Vi & Ei & Wi) | (Ui & Vi & (h^ri) & Wi)
    s1 = s1 + ri
    n1 = n1 * Ui
    Pk = pow(g1, s1)

    # first half of the receipt
    receipt = {"id": i, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk": Pk}

    # to check their decision
    while True:
        decision = input("To confirm your choice, type 1. Otherwise, type 0: ")

        # audit receipt: (i : (Ui, Vi, Ei, Wi, Pwf{Ei}, PK{s1}), (audited, ri, vi)
        # confirm receipt: (i : (Ui, Vi, Ei, Wi, PWF{Ei}, PK{s1}), (confirmed, PK{s})
        if decision == "0":
            receipt["status"] = "audit"
            receipt["ballot"] = vi
            receipt["ri"] = ri
            break
        elif decision == "1":
            receipt["status"] = "confirm"

    return receipt




if __name__ == '__main__':
    c, d, h, gq, q, g1, g2 = key_generation()

    t = 0
    s = 0
    s1 = 0
    m = 0
    n = 1
    n1 = 1

    audit = []
    confirm = []
    count = 0

    while True: 
        count += 1
        if count > 10: # change it after testing
            break
        
        receipt = DRE_receipt(count, c, d, h, gq, q, g1, g2, s1, n1)

        if "ballot" in receipt:
            # audit
            audit.append(count)
            # creates a block to mine it in the block-chain
            # send the transaction to the BB
            # make the voter to vote again
        else:
            # confirm
            confirm.append(count)
            # delete them from hash? -> prevent double voting

            