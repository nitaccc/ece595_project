from collections import Counter
import linecache
import os
import tracemalloc
import string 
import secrets
import hashlib
import time
from random import randint
from random import random
from genHashID import gen_voterHash
from merkleTree import construct_MerkleTree, verify_hash
from genKey import key_generation
from zkp import encode_vote, update_tally_matrix, calculate_Ei_matrix, genProof_s1, genProof_Ei
from verify import verifyPWF, auditVerify
from blockChain import Blockchain
from util import printReceipt, mergeReceipt

NUM_CANDIDATES = 5

def DRE_receipt(i, question_len, c, d, h, q, g1, g2, s1, n1, t, m, s, n, ACCEPT_RATE):
    merge_r = {"id": i, "Ui": [], "Vi": [], "Ei": [], "Wi": [], "Pwf": [], "Pk_s1": []}
    all_vi = []
    all_ri = []
    all_alpha = []
    for question_idx in range(question_len):
        vi = randint(1, 5)
        vote_matrix = encode_vote(vi)
        ri = randint(1, q[question_idx]-1)
        Ui = pow(g1[question_idx], ri, q[question_idx])
        Vi = pow(g2[question_idx], ri, q[question_idx])
        Ei = calculate_Ei_matrix(vote_matrix, g1[question_idx], q[question_idx], h[question_idx], ri)
        tmp = str(Ui) + str(Vi) + str(Ei)
        alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
        alpha = int(alpha, 16) % q[question_idx]
        Wi = pow(c[question_idx], ri, q[question_idx]) * pow(d[question_idx], (ri*alpha), q[question_idx]) % q[question_idx]

        Pwf = genProof_Ei(ri, g1[question_idx], g2[question_idx], c[question_idx], d[question_idx], h[question_idx], Ui, Vi, Ei, Wi, q[question_idx])
        s1[question_idx] = s1[question_idx] + ri
        n1[question_idx] = n1[question_idx] * Ui % q[question_idx]
        Pk_s1 = genProof_s1(n1[question_idx], g1[question_idx], s1[question_idx], q[question_idx])

        # first half of the receipt
        receipt = {"id": i, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1}
        merge_r = mergeReceipt(merge_r, receipt)
        all_vi.append(vote_matrix)
        all_ri.append(ri)
        all_alpha.append(alpha)
    
    while True:
        decision = 1 if i <= ACCEPT_RATE else 0
        # audit receipt: (i : (Ui, Vi, Ei, Wi, Pwf{Ei}, PK{s1}), (audited, ri, vi)
        # confirm receipt: (i : (Ui, Vi, Ei, Wi, PWF{Ei}, PK{s1}), (confirmed, PK{s})
        if decision == 0:
            merge_r["status"] = "audit"
            merge_r["ballot"] = all_vi
            merge_r["ri"] = all_ri
            last_receipt = ["audit", all_vi, all_ri]
            break
        else:
            merge_r["status"] = "confirm"
            Pk_s = []
            for i in range(question_len):
                t[i] = update_tally_matrix(t[i], all_vi[i])
                m[i] = m[i] + all_ri[i] * all_alpha[i]
                s[i] = s[i] + all_ri[i]
                n[i] = n[i] * merge_r['Ui'][i] % q[i]
                Pk_s.append(genProof_s1(n[i], g1[i], s[i], q[i]))
            merge_r["Pk_s"] = Pk_s
            last_receipt = ["confirm", Pk_s]
            break
    return t, m, s, s1, n, n1, merge_r, last_receipt

def voting(NUM_STUDENT, ACCEPT_RATE):
    tracemalloc.start()
    # Registration
    studentID_list = []
    studentPassword_list = []
    studenthash_list = []
    for i in range(NUM_STUDENT):
        studentID = ''.join(secrets.choice(string.digits) for i in range(10))
        hash_value, password = gen_voterHash(studentID, False, True)
        studentID_list.append(studentID)
        studenthash_list.append(hash_value)
        studentPassword_list.append(password)
    
    max_leaf_node = 1
    while max_leaf_node < NUM_STUDENT:
        max_leaf_node = max_leaf_node * 2

    while len(studenthash_list) < max_leaf_node:
        tmpID = ''.join(secrets.choice(string.digits) for i in range(10))
        studenthash_list.append(gen_voterHash(tmpID, False))

    mtree = construct_MerkleTree(studenthash_list)
    # print("End of Registration. \n\n\n")
    # Finish Registration
        
    # Initialize
    question_len = 2
    c, d, h, q, g1, g2 = key_generation(question_len)
    
    t = [[[0 for _ in range(NUM_CANDIDATES)] for _ in range(NUM_CANDIDATES)] for _ in range(question_len)]
    m = [0 for _ in range(question_len)]
    s = [0 for _ in range(question_len)]
    s1 = [0 for _ in range(question_len)]
    n = [1 for _ in range(question_len)]
    n1 = [1 for _ in range(question_len)]
    count = 0
    blockchain = Blockchain()
    # print("Start Voting...")
    
    # Voting
    for student_idx in range(NUM_STUDENT):
        studentID = studentID_list[student_idx]
        password = studentPassword_list[student_idx]
        verifyID = bytes(studentID + password, 'utf-8')
        verifyID = hashlib.sha256(verifyID).digest()
        check = verify_hash(mtree, verifyID.hex())
        if not check: continue
        count += 1
        # print("Verified.")
        
        # receive ballot, send first half of the receipt
        # then receive decision, send rest of the receipt
        t, m, s, s1, n, n1, receipt, last_receipt = DRE_receipt(count, question_len, c, d, h, q, g1, g2, s1, n1, t, m, s, n, ACCEPT_RATE)
        # tmp = printReceipt(receipt, question_len)
        tmp = "Receipt" + str(receipt["id"]) + ".txt"
        # print(tmp, "is generated.")

        if receipt["status"] != "confirm":
            # audit
            # creates a block and mines it in the block-chain
            block_success = blockchain.add_block(receipt, tmp, n1, g1, q, n, s, c)
            if not block_success:
                print("Receipt failed blockchain verification. Not added to chain. \n")
            # else:
                # print(f"Blockchain is valid: {blockchain.is_chain_valid()} \n")
        else:
            # confirm
            # creates a block and mines it in the block-chain
            block_success = blockchain.add_block(receipt, tmp, n1, g1, q, n, s, c)
            if not block_success:
                print("Receipt failed blockchain verification. Not added to chain. \n")
            else:
                # print(f"Blockchain is valid: {blockchain.is_chain_valid()} \n")
                # update Merkle Tree -> prevent double voting
                idx = studenthash_list.index(verifyID.hex())
                studentID = ''.join(secrets.choice(string.digits) for i in range(10))
                studenthash_list[idx] = gen_voterHash(studentID, False)
                mtree = construct_MerkleTree(studenthash_list)
    # print("End of Voting.\n\n\n")


    # Tally
    # print("\nTally:")
    # print("t:", t)
    # print("s:", s)
    # print("m:", m, "\n")
    # publicKey = {"c": c, "d": d, "h": h, "q": q, "g1": g1, "g2": g2, "t": t, "s": s, "m": m}
    # question = ["You learn a lot from this course. ", "You prefer take this course in person. "]
    # for i in range(2):
    #     print("Question: ", question[i])
    #     print("Strongly Agree: " + str(sum(t[i][4])))
    #     print("Slightly Agree: " + str(sum(t[i][3])))
    #     print("Neutral: " + str(sum(t[i][2])))
    #     print("Slightly Disagree: " + str(sum(t[i][1])))
    #     print("Strongly Disagree: " + str(sum(t[i][0])))
    #     print("\n")
                
    
    start_time = time.time()


    # Verify tally w/ blockchain
    Ei_tally = [[[1 for _ in range(NUM_CANDIDATES)] for _ in range(NUM_CANDIDATES)] for _ in range(question_len)]
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
        if not verifyPWF(block_receipt_file, block_receipt):
            print("There has been an error in the vote while verifying PWFs. Insecure!")
            exit()

        # Public verifies vi and ri for audited ballots
        if block_receipt["status"] != "confirm":
            if not auditVerify(block_receipt_file, n1_tally, block_receipt):
                print("There has been an error in fan audited ballot. Insecure!")
                exit()
        else:
            for i in range(question_len):
                Ui_tally[i] = (Ui_tally[i] * block_receipt["Ui"][i]) % q[i]
                Vi_tally[i] = (Vi_tally[i] * block_receipt["Vi"][i]) % q[i]
                Wi_tally[i] = (Wi_tally[i] * block_receipt["Wi"][i]) % q[i]
                Ei_matrix = block_receipt["Ei"][i]
                for k in range(len(Ei_matrix)):
                    for j in range(len(Ei_matrix[k])):
                        Ei_tally[i][k][j] = (Ei_tally[i][k][j] * Ei_matrix[k][j]) % q[i]
    
    # Public verifies the tally equations
    for i in range(question_len):
        if (Ui_tally[i] != pow(g1[i], s[i], q[i])):
            print("There has been an error in the vote tallying of Ui's. Insecure!")
            exit()
        elif (Vi_tally[i] != pow(g2[i], s[i], q[i])):
            print("There has been an error in the vote talling of Vi's. Insecure!")
            exit()
        elif (Wi_tally[i] != (pow(c[i], s[i], q[i]) * pow(d[i], m[i], q[i])) % q[i]):
            print("There has been an error in the vote tallying of Wi's. Insecure!")
            exit()
        expected_Ei_tally = [
            [pow(h[i], s[i], q[i]) * pow(g1[i], t[i][row][col], q[i]) % q[i] for col in range(len(Ei_tally[i][0]))]
            for row in range(len(Ei_tally[i]))
        ]
        for k in range(len(Ei_tally[i])):
            for j in range(len(Ei_tally[i][k])):
                if Ei_tally[i][k][j] != expected_Ei_tally[k][j]:
                  print(f"There has been an error in the vote tallying of Ei[{k}][{j}]. Insecure!")
                  exit()
    print("All tally verifications have passed! Course evaluation complete and secure!\n")
    
    snapshot = tracemalloc.take_snapshot()
    tracemalloc.stop()
    total_time = time.time() - start_time
    return total_time, snapshot



def display_top(snapshot, key_type='lineno', limit=3):
    snapshot = snapshot.filter_traces((
        tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
        tracemalloc.Filter(False, "<unknown>"),
    ))
    top_stats = snapshot.statistics(key_type)
    total = sum(stat.size for stat in top_stats)
    print("Total allocated size: %.1f KiB\n\n" % (total / 1024))

    return total / 1024



if __name__ == '__main__':
    NUM_STUDENT = 5
    ACCEPT_RATE = [0, 0.2, 0.4, 0.6, 0.8, 1]
    iter = 5
    tally_time = [0, 0, 0, 0, 0, 0]
    runtime = [0, 0, 0, 0, 0, 0]
    mem = [0, 0, 0, 0, 0, 0]
    for j in range(iter):
        for i in range(len(ACCEPT_RATE)):
            start_time = time.time()
            tally_t, snapshot = voting(NUM_STUDENT, ACCEPT_RATE[i]*NUM_STUDENT)
            total_time = time.time() - start_time
            print("Total Voters:", NUM_STUDENT)
            print("Confirmed Rate:", ACCEPT_RATE[i])
            print("Total running time: %.1f s" % total_time)
            print("Total tally time: %.1f s" % tally_t)
            memory = display_top(snapshot)
            runtime[i] += total_time
            tally_time[i] += tally_t
            mem[i] += memory
    
    for i in range(len(ACCEPT_RATE)):
        print("Total Voters:", NUM_STUDENT)
        print("Confirmed Rate:", ACCEPT_RATE[i])
        print("Average running time: %.1f s" % (runtime[i]/iter))
        print("Average running time of tally: %.1f s" % (tally_time[i]/iter))
        print("Average allocated size: %.1f KiB\n\n" % (mem[i]/iter))