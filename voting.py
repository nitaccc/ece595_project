import hashlib
import string 
import secrets
from random import randint
from genHashID import gen_voterHash
from merkleTree import construct_MerkleTree, verify_hash
from genKey import key_generation
from zkp import printReceipt, DRE_receipt
from verify import verifyPWF, auditVerify
from blockChain import Blockchain

NUM_CANDIDATES = 5

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



if __name__ == '__main__':
    # Construct Merkle Tree 
    f = open("hashList.txt", "r")
    hash_list = f.readlines()
    f.close()
    for i in range(len(hash_list)):
        hash_list[i] = hash_list[i][:-1]
    mtree = construct_MerkleTree(hash_list)

    # Initialize
    c, d, h, q, g1, g2 = key_generation()
    t = [[0 for _ in range(NUM_CANDIDATES)] for _ in range(NUM_CANDIDATES)]
    m = 0
    s = 0
    s1 = 0
    n = 1
    n1 = 1
    audit = []
    confirm = []
    count = 0
    blockchain = Blockchain()

    # Voting
    while True: 
        if count > 2: # change it after testing
            break
        hashValue = register(mtree)
        count += 1
        
        t, m, s, s1, n, n1, receipt = DRE_receipt(count, c, d, h, q, g1, g2, s1, n1, t, m, s, n)
        tmp = printReceipt(receipt)
        print(tmp, "is generated.")

        if receipt["status"] != "confirm":
            # audit
            audit.append(count)
            # creates a block and mines it in the block-chain
            block_success = blockchain.add_block(receipt, tmp, n1, g1, q, n, s, c)
            if not block_success:
                print("Receipt failed blockchain verification. Not added to chain. \n")
            else:
                print(f"Blockchain is valid: {blockchain.is_chain_valid()} \n")
        else:
            # confirm
            confirm.append(count)
            # update Merkle Tree -> prevent double voting
            idx = hash_list.index(hashValue)
            studentID = ''.join(secrets.choice(string.digits) for i in range(10))
            hash_list[idx] = gen_voterHash(studentID, False)
            mtree = construct_MerkleTree(hash_list)
            # creates a block and mines it in the block-chain
            block_success = blockchain.add_block(receipt, tmp, n1, g1, q, n, s, c)
            if not block_success:
                print("Receipt failed blockchain verification. Not added to chain. \n")
            else:
                print(f"Blockchain is valid: {blockchain.is_chain_valid()} \n")

    # Tally
    print("\nTally")
    print("(c, d, h): ", c, d, h)
    print("q = ", q)
    print("g1 = ", g1)
    print("g2 = ", g2)
    # These are posted to the public
    print("t = ", t)
    print("s = ", s)
    print("m = ", m)
    
    # Verify tally w/ blockchain
    Ei_tally = 1
    Vi_tally = 1
    Wi_tally = 1
    Ui_tally = 1
    n1_tally = 1

    for block in blockchain.chain:
        

        if block.receipt == "Genesis Block":
            continue
        
        block_receipt = block.receipt
        block_receipt_file = block.file

        n1_tally = n1_tally * block_receipt["Ui"] % q

        # Public verifies PWF
        if not verifyPWF(block_receipt_file):
            print("There has been an error in the vote while verifying PWFs. Insecure!")
            exit()

        # Public verifies vi and ri for audited ballots
        if block_receipt["status"] != "confirm":
            if not auditVerify(block_receipt_file, n1_tally):
                print("There has been an error in an audited ballot. Insecure!")
                exit()
        else:
            Ui_tally = (Ui_tally * block_receipt["Ui"]) % q
            Ei_tally = (Ei_tally * block_receipt["Ei"]) % q
            Vi_tally = (Vi_tally * block_receipt["Vi"]) % q
            Wi_tally = (Wi_tally * block_receipt["Wi"]) % q
    
    # Public verifies the tally equations
    if (Ui_tally != pow(g1, s, q)):
        print("There has been an error in the vote tallying of Ui's. Insecure!")
        print(str(Ui_tally))
        print(str(pow(g1, s, q)))
    elif (Vi_tally != pow(g2, s, q)):
        print("There has been an error in the vote talling of Vi's. Insecure!")
    elif (Ei_tally != (pow(h, s, q) * pow(g1, t, q)) % q):
        print("There has been an error in the vote tallying of Ei's. Insecure!")
    elif (Wi_tally != (pow(c, s, q) * pow(d, m, q)) % q):
        print("There has been an error in the vote tallying of Wi's. Insecure!")
    else:
        print("All tally verifications have passed! Course evaluation complete and secure!")