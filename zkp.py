# Some functions used in DRE
#       - calculate zkp of s1 and s and Pwf
#       - generate receipt file


import hashlib
import pickle
from random import randint
from util import mergeReceipt

NUM_CANDIDATES = 5

def genProof_s1(n1, g1, s1, q):
    v = randint(1, q-1)
    t = pow(g1, v, q)
    tmp = str(g1) + str(n1) + str(t)
    c = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    c = int(c, 16)
    r = (v - c*s1) % (q-1)

    return (t, r)

def genProof_Ei(ri, g1, g2, c, d, h, Ui, Vi, Ei_matrix, Wi, q):
    num_rows = len(Ei_matrix)
    num_cols = len(Ei_matrix[0])

    proofs = [[None for _ in range(num_cols)] for _ in range(num_rows)]

    for r in range(num_rows):
        for col in range(num_cols):
            Ei = Ei_matrix[r][col]

            tmp = str(Ui) + str(Vi) + str(Ei_matrix)
            alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
            alpha = int(alpha, 16) % q

            r1 = randint(1, q - 1)
            t1_U = pow(g1, r1, q)
            t1_V = pow(g2, r1, q)
            t1_E = pow(h, r1, q)
            t1_W = (pow(c, r1, q) * pow(d, (r1 * alpha), q)) % q

            r2 = randint(1, q - 1)
            t2_U = pow(g1, r2, q)
            t2_V = pow(g2, r2, q)
            t2_E = pow(h, r2, q)
            t2_W = (pow(c, r2, q) * pow(d, (r2 * alpha), q)) % q

            tmp = f"{g1}{g2}{c}{d}{h}{Ui}{Vi}{Ei}{Wi}{t1_U}{t1_V}{t1_E}{t1_W}{t2_U}{t2_V}{t2_E}{t2_W}"
            c_hash = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
            c_hash = int(c_hash, 16) % q

            v1 = (r1 - c_hash * ri) % (q - 1)
            v2 = (r2 - c_hash * ri) % (q - 1)

            # Store proof for the current element
            proofs[r][col] = {
                "r": [v1, v2],
                "U": [t1_U, t2_U],
                "V": [t1_V, t2_V],
                "E": [t1_E, t2_E],
                "W": [t1_W, t2_W],
            }

    return proofs



# mark vote in a matrix of form [0 0 0 0 0]
# _____________________________ [0 1 0 0 0]
# _____________________________ [0 0 0 0 0]
# _____________________________ [0 0 0 0 0]
# _____________________________ [0 0 0 0 0]
def encode_vote(candidate):
    candidate_index = int(candidate) - 1 
    vote_matrix = [[0 for _ in range(NUM_CANDIDATES)] for _ in range(NUM_CANDIDATES)]
    vote_matrix[candidate_index][candidate_index] = 1
    return vote_matrix



def update_tally_matrix(tally_matrix, vote_matrix):
    for i in range(NUM_CANDIDATES):
        for j in range(NUM_CANDIDATES):
            tally_matrix[i][j] += vote_matrix[i][j]
    return tally_matrix



def calculate_Ei_matrix(vote_matrix, g1, q, h, ri):
    num_rows = len(vote_matrix)
    num_cols = len(vote_matrix[0])
    
    # Initialize Ei matrix with the same dimensions as vote_matrix
    Ei_matrix = [[0 for _ in range(num_cols)] for _ in range(num_rows)]
    
    # Perform element-wise exponentiation
    for r in range(num_rows):
        for c in range(num_cols):
            Ei_matrix[r][c] = (pow(h, ri, q) * pow(g1, vote_matrix[r][c], q)) % q
    
    return Ei_matrix



def DRE_receipt(connection, i, question_len, c, d, h, q, g1, g2, s1, n1, t, m, s, n):
    merge_r = {"id": i, "Ui": [], "Vi": [], "Ei": [], "Wi": [], "Pwf": [], "Pk_s1": []}
    all_vi = []
    all_ri = []
    all_alpha = []
    for question_idx in range(question_len):
        while True:
            tmp = connection.recv(1024)
            if len(tmp) > 0:
                break
        vi = int(tmp.decode())
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
        connection.send(pickle.dumps(receipt))
        merge_r = mergeReceipt(merge_r, receipt)
        all_vi.append(vote_matrix)
        all_ri.append(ri)
        all_alpha.append(alpha)
    
    while True:
        while True:
            tmp = connection.recv(512)
            if len(tmp) > 0:
                break
        decision = tmp.decode()
        # audit receipt: (i : (Ui, Vi, Ei, Wi, Pwf{Ei}, PK{s1}), (audited, ri, vi)
        # confirm receipt: (i : (Ui, Vi, Ei, Wi, PWF{Ei}, PK{s1}), (confirmed, PK{s})
        
        if decision == "n":
            merge_r["status"] = "audit"
            merge_r["ballot"] = all_vi
            merge_r["ri"] = all_ri
            last_receipt = ["audit", all_vi, all_ri]
            break
        elif decision == "y":
            merge_r["status"] = "confirm"
            Pk_s = []
            for i in range(question_len):
                # t[i] = t[i] + all_vi[i]
                t[i] = update_tally_matrix(t[i], all_vi[i])
                m[i] = m[i] + all_ri[i] * all_alpha[i]
                s[i] = s[i] + all_ri[i]
                n[i] = n[i] * merge_r['Ui'][i] % q[i]
                Pk_s.append(genProof_s1(n[i], g1[i], s[i], q[i]))
            merge_r["Pk_s"] = Pk_s
            last_receipt = ["confirm", Pk_s]
            break
    return t, m, s, s1, n, n1, merge_r, last_receipt