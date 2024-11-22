import socket
import pickle
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



if __name__ == '__main__':
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('localhost', 8070))
    serversocket.listen(5)
    connection, address = serversocket.accept()

    # Registration
    hash_list = []
    while True:
        tmp = connection.recv(512)
        if len(tmp) > 0:
            data = pickle.loads(tmp)
            if data[0] == "E":
                break
            hash_list.append(data[0])
            print("Registered!")
    mtree = construct_MerkleTree(hash_list)
    print("End of Registration\n\n\n")
    # Finish Registration
        
    # Initialize
    c, d, h, q, g1, g2 = key_generation()
    t = 0
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
        # Verify identity
        while True:
            verifyID = connection.recv(512)
            if len(verifyID) > 0:
                if verifyID == bytes("E", 'utf-8'): break
                check = verify_hash(mtree, verifyID.hex())
                if not check: check += 2
                connection.send(bytes(check))
                break
        if verifyID == bytes("E", 'utf-8'): break
        if check == 2: 
            print("Failed")
            continue
        count += 1
        print("Verified.")
        
        # receive ballot, send first half of the receipt
        # then receive decision, send rest of the receipt
        t, m, s, s1, n, n1, receipt = DRE_receipt(connection, count, c, d, h, q, g1, g2, s1, n1, t, m, s, n)
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
            idx = hash_list.index(verifyID.hex())
            studentID = ''.join(secrets.choice(string.digits) for i in range(10))
            hash_list[idx] = gen_voterHash(studentID, False)
            mtree = construct_MerkleTree(hash_list)
            # creates a block and mines it in the block-chain
            block_success = blockchain.add_block(receipt, tmp, n1, g1, q, n, s, c)
            if not block_success:
                print("Receipt failed blockchain verification. Not added to chain. \n")
            else:
                print(f"Blockchain is valid: {blockchain.is_chain_valid()} \n")
    print("Voting End\n\n\n")


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
            if not auditVerify(block_receipt_file, n1_tally): # TODO how do we get n1
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