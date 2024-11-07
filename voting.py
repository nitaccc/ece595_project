import hashlib
import string 
import secrets
from random import randint
from genHashID import gen_voterHash
from merkleTree import construct_MerkleTree, verify_hash
from genKey import key_generation
from zkp import genProof_s1, genProof_Ei, printReceipt


def register(mtree):
    while True:
        studentID = input("Please enter 10 digits student ID: ")
        if len(studentID) == 10:
            secretKey = input("Please enter the secret key: ")
            ID32 = bytes(studentID + secretKey, 'utf-8')
            test = hashlib.sha256(ID32).hexdigest()
            if verify_hash(mtree, test):
                print("Passed.")
                return test
            else:
                print(test)
                print("Failed.")



def DRE_receipt(i, c, d, h, gq, q, g1, g2, s1, n1, t, m, s, n):
    vi = input("Type 0 or 1: ")
    vi = int(vi)
    ri = randint(1, q-1)
    Ui = g1^ri
    Vi = g2^ri
    Ei = (h^ri) * (g1^vi)
    tmp = str(Ui) + str(Vi) + str(Ei)
    alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    alpha = int(alpha, 16)
    Wi = (c^ri) * (d^(ri*alpha))

    Pwf = genProof_Ei(ri, g1, g2, c, d, h, Ui, Vi, Ei, Wi, q)
    s1 = s1 + ri
    n1 = n1 * Ui
    Pk_s1 = genProof_s1(n1, g1, s1, q)

    # first half of the receipt
    receipt = {"id": i, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1}

    # check their decision
    while True:
        decision = input("Confirm (y/n): ")
        # audit receipt: (i : (Ui, Vi, Ei, Wi, Pwf{Ei}, PK{s1}), (audited, ri, vi)
        # confirm receipt: (i : (Ui, Vi, Ei, Wi, PWF{Ei}, PK{s1}), (confirmed, PK{s})
        if decision == "y":
            receipt["status"] = "audit"
            receipt["ballot"] = vi
            receipt["ri"] = ri
            break
        elif decision == "n":
            receipt["status"] = "confirm"
            t = t + vi
            m = m + ri * alpha
            s = s + ri
            n = n * Ui
            Pk_s = genProof_s1(n, g1, s, q)
            receipt["Pk_s"] = Pk_s
            break

    return t, m, s, s1, n, n1, receipt



if __name__ == '__main__':
    # Construct Merkle Tree 
    f = open("hashList.txt", "r")
    hash_list = f.readlines()
    f.close()
    for i in range(len(hash_list)):
        hash_list[i] = hash_list[i][:-1]
    mtree = construct_MerkleTree(hash_list)

    # Initialize
    c, d, h, gq, q, g1, g2 = key_generation()
    t = 0
    m = 0
    s = 0
    s1 = 0
    n = 1
    n1 = 1
    audit = []
    confirm = []
    count = 0

    # Voting
    while True: 
        if count > 2: # change it after testing
            break
        hashValue = register(mtree)
        count += 1
        
        t, m, s, s1, n, n1, receipt = DRE_receipt(count, c, d, h, gq, q, g1, g2, s1, n1, t, m, s, n)
        tmp = printReceipt(receipt)
        print(tmp, "is generated. \n")

        if "ballot" in receipt:
            # audit
            audit.append(count)
            # creates a block to mine it in the block-chain
            # send the transaction to the BB
            # TODO
        else:
            # confirm
            confirm.append(count)
            # update Merkle Tree -> prevent double voting
            idx = hash_list.index(hashValue)
            studentID = ''.join(secrets.choice(string.digits) for i in range(10))
            hash_list[idx] = gen_voterHash(studentID, False)
            mtree = construct_MerkleTree(hash_list)
            # creates a block to mine it in the block-chain
            # send the transaction to the BB
            # TODO


    # Tally
    print("\nTally")
    print("(c, d, h): ", c, d, h)
    print("Gq = ", gq)
    print("q = ", q)
    print("g1 = ", g1)
    print("g2 = ", g2)

    print("t = ", t)
    print("s = ", s)
    print("m = ", m)
