import socket
import pickle
import string 
import secrets
from genHashID import gen_voterHash
from merkleTree import construct_MerkleTree, verify_hash
from genKey import key_generation
from zkp import DRE_receipt
from verify import verifyPWF, auditVerify
from blockChain import Blockchain
from util import printReceipt



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
    print("End of Registration. \n\n\n")
    connection.send('E'.encode(encoding='utf-8'))
    # Finish Registration
        
    # Initialize
    while True:
        tmp = connection.recv(512)
        if tmp:
            question_len = int(tmp.decode())
            break
    c, d, h, q, g1, g2 = key_generation(question_len)
    t = [0 for _ in range(question_len)]
    m = [0 for _ in range(question_len)]
    s = [0 for _ in range(question_len)]
    s1 = [0 for _ in range(question_len)]
    n = [1 for _ in range(question_len)]
    n1 = [1 for _ in range(question_len)]
    count = 0
    blockchain = Blockchain()
    print("Start Voting...")
    
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
        t, m, s, s1, n, n1, receipt = DRE_receipt(connection, count, question_len, c, d, h, q, g1, g2, s1, n1, t, m, s, n)
        tmp = printReceipt(receipt, question_len)
        print(tmp, "is generated.")

        if receipt["status"] != "confirm":
            # audit
            # creates a block and mines it in the block-chain
            block_success = blockchain.add_block(receipt, tmp, n1, g1, q, n, s, c)
            if not block_success:
                print("Receipt failed blockchain verification. Not added to chain. \n")
            else:
                print(f"Blockchain is valid: {blockchain.is_chain_valid()} \n")
        else:
            # confirm
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
    print("End of Voting.\n\n\n")


    # Tally
    print("\nTally:")
    print("t:", t)
    print("s:", s)
    print("m:", m, "\n")
    for i in range(2):
        print("Question", i+1, ":", t[i]/question_len, "agree. ")
    publicKey = {"c": c, "d": d, "h": h, "q": q, "g1": g1, "g2": g2, "t": t, "s": s, "m": m}
    connection.send(pickle.dumps(publicKey))


    # Verify tally w/ blockchain
    Ei_tally = [1 for _ in range(question_len)]
    Vi_tally = [1 for _ in range(question_len)]
    Wi_tally = [1 for _ in range(question_len)]
    Ui_tally = [1 for _ in range(question_len)]
    n1_tally = [1 for _ in range(question_len)]

    for block in blockchain.chain:
        
        if block.receipt == "Genesis Block":
            continue
        
        block_receipt = block.receipt
        block_receipt_file = block.file

        for i in range(question_len):
            n1_tally[i] = n1_tally[i] * block_receipt["Ui"][i] % q[i]

        # Public verifies PWF
        if not verifyPWF(block_receipt_file):
            print("There has been an error in the vote while verifying PWFs. Insecure!")
            exit()

        # Public verifies vi and ri for audited ballots
        if block_receipt["status"] != "confirm":
            if not auditVerify(block_receipt_file, n1_tally): # TODO how do we get n1
                print("There has been an error in fan audited ballot. Insecure!")
                exit()
        else:
            for i in range(question_len):
                Ui_tally[i] = (Ui_tally[i] * block_receipt["Ui"][i]) % q[i]
                Ei_tally[i] = (Ei_tally[i] * block_receipt["Ei"][i]) % q[i]
                Vi_tally[i] = (Vi_tally[i] * block_receipt["Vi"][i]) % q[i]
                Wi_tally[i] = (Wi_tally[i] * block_receipt["Wi"][i]) % q[i]
    
    # Public verifies the tally equations
    for i in range(question_len):
        if (Ui_tally[i] != pow(g1[i], s[i], q[i])):
            print("There has been an error in the vote tallying of Ui's. Insecure!")
            exit()
        elif (Vi_tally[i] != pow(g2[i], s[i], q[i])):
            print("There has been an error in the vote talling of Vi's. Insecure!")
            exit()
        elif (Ei_tally[i] != (pow(h[i], s[i], q[i]) * pow(g1[i], t[i], q[i])) % q[i]):
            print("There has been an error in the vote tallying of Ei's. Insecure!")
            exit()
        elif (Wi_tally[i] != (pow(c[i], s[i], q[i]) * pow(d[i], m[i], q[i])) % q[i]):
            print("There has been an error in the vote tallying of Wi's. Insecure!")
            exit()
    print("All tally verifications have passed! Course evaluation complete and secure!")