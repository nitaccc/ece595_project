# Some functions used in DRE
#       - calculate zkp of s1 and s and Pwf
#       - generate receipt file

from random import randint
import hashlib
import socket
import pickle

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

            #tmp = str(g1) + str(g2) + str(c) + str(d) + str(h) + str(Ui) + str(Vi) + str(Ei) + str(Wi) + str(t1_U) + str(t1_V) + str(t1_E) + str(t1_W) + str(t2_U) + str(t2_V) + str(t2_E) + str(t2_W)
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

def DRE_receipt(i, c, d, h, q, g1, g2, s1, n1, t, m, s, n):
    vi = input("Rank 1-5: ")
    # while True:
    #     tmp = connection.recv(512)
    #     if len(tmp) > 0:
    #         break
    # vi = int(tmp.decode())
    vote_matrix = encode_vote(vi)

    ri = randint(1, q-1)
    Ui = pow(g1, ri, q)
    Vi = pow(g2, ri, q)
    Ei = calculate_Ei_matrix(vote_matrix, g1, q, h, ri)
    tmp = str(Ui) + str(Vi) + str(Ei)
    alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    alpha = int(alpha, 16) % q
    Wi = pow(c, ri, q) * pow(d, (ri*alpha), q) % q

    Pwf = genProof_Ei(ri, g1, g2, c, d, h, Ui, Vi, Ei, Wi, q)
    s1 = s1 + ri
    n1 = n1 * Ui % q
    Pk_s1 = genProof_s1(n1, g1, s1, q)

    # first half of the receipt
    receipt = {"id": i, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1}
    #connection.send(pickle.dumps(receipt))

    # check their decision
    while True:
        decision = input("Confirm (y/n): ")
        # while True:
        #     tmp = connection.recv(512)
        #     if len(tmp) > 0:
        #         break
        # decision = tmp.decode()
        # audit receipt: (i : (Ui, Vi, Ei, Wi, Pwf{Ei}, PK{s1}), (audited, ri, vi)
        # confirm receipt: (i : (Ui, Vi, Ei, Wi, PWF{Ei}, PK{s1}), (confirmed, PK{s})
        if decision == "n":
            receipt["status"] = "audit"
            receipt["ballot"] = vote_matrix
            receipt["ri"] = ri
            break
        elif decision == "y":
            receipt["status"] = "confirm"
            t = update_tally_matrix(t, vote_matrix)
            m = m + ri * alpha
            s = s + ri
            n = n * Ui % q
            Pk_s = genProof_s1(n, g1, s, q)
            receipt["Pk_s"] = Pk_s
            break
    
    #connection.send(pickle.dumps(receipt))
    return t, m, s, s1, n, n1, receipt



def printReceipt(receipt, opt = False):
    if opt: 
        filename = "VoterReceipt" + str(receipt["id"]) + ".txt"
    else:
        filename = "Receipt" + str(receipt["id"]) + ".txt"
    f = open(filename, "w")
    if receipt["status"] == "confirm":
        f.write("This ballot is counted.")
    else:
        f.write("This ballot did not count.")

    f.write("\nBallot ID: " + str(receipt["id"]))
    f.write("\nUi: " + str(receipt["Ui"]))
    f.write("\nVi: " + str(receipt["Vi"]))
    f.write("\nEi: \n")
    for row in receipt["Ei"]:
        f.write(str(row) + "\n")
    f.write("Wi: " + str(receipt["Wi"]))
    
    for row_idx, row in enumerate(receipt["Pwf"]):
        f.write(f"\nPWF_Ei Row {row_idx + 1}:")

        # Iterate through columns of the row
        for col_idx, proof in enumerate(row):
            f.write(f"\n  Proof for element ({row_idx + 1}, {col_idx + 1}):")
            tmp = "".join([
                "\n    r = ", str(proof["r"]),
                "\n    U = ", str(proof["U"]),
                "\n    V = ", str(proof["V"]),
                "\n    E = ", str(proof["E"]),
                "\n    W = ", str(proof["W"])
            ])
            f.write(tmp)
    tmp = "".join([
        "\nPk_s1: ",
        "\n  t = ", str(receipt["Pk_s1"][0]),
        "\n  r = ", str(receipt["Pk_s1"][1])
    ])
    f.write(tmp)

    if receipt["status"] == "confirm":
        tmp = "".join([
            "\nPk_s: ",
            "\n  t = ", str(receipt["Pk_s"][0]),
            "\n  r = ", str(receipt["Pk_s"][1])
        ])
        f.write(tmp)
    else:
        f.write("\nBallot: " + str(receipt["ballot"]))
        f.write("\nri: " + str(receipt["ri"]))

    f.close()
    return filename