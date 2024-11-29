import hashlib
from util import readPublicKey, readReceipt
# from util import readPublicKey

# def readReceipt(filename):
#     f = open(filename, "r")
#     lines = f.readlines()
#     f.close()
#     id = int(lines[1][11:-1])
#     Ui = int(lines[2][4:-1])
#     Vi = int(lines[3][4:-1])

#     Ei = []
#     ei_start_idx = 5
#     while lines[ei_start_idx].startswith("["):  # Check if line starts with a matrix row
#         Ei.append(eval(lines[ei_start_idx].strip()))  # Strip any leading/trailing whitespace and convert the string representation to a list
#         ei_start_idx += 1

#     Wi = int(lines[ei_start_idx][4:-1])

#     Pwf = []
#     row_idx = ei_start_idx + 1
#     while row_idx < len(lines) and lines[row_idx].startswith("PWF_Ei Row"):
#         current_row = []  # Temporary storage for proofs in the current row
        
#         # Process proofs in the current row
#         proof_idx = row_idx + 1
#         while proof_idx < len(lines) and lines[proof_idx].startswith("  Proof for element"):
#             proof = {}

#             # Extract values for r, U, V, E, W
#             proof["r"] = [int(x) for x in lines[proof_idx + 1].split("=")[1].strip(" []\n").split(",")]
#             proof["U"] = [int(x) for x in lines[proof_idx + 2].split("=")[1].strip(" []\n").split(",")]
#             proof["V"] = [int(x) for x in lines[proof_idx + 3].split("=")[1].strip(" []\n").split(",")]
#             proof["E"] = [int(x) for x in lines[proof_idx + 4].split("=")[1].strip(" []\n").split(",")]
#             proof["W"] = [int(x) for x in lines[proof_idx + 5].split("=")[1].strip(" []\n").split(",")]
            
#             current_row.append(proof)
#             proof_idx += 6  # Move to the next proof element

#         Pwf.append(current_row)  # Append the completed row to Pwf
#         row_idx = proof_idx  # Move to the next row

#     idx = row_idx + 1
#     t = int(lines[idx][5:-1])
#     r = int(lines[idx + 1][5:-1])
#     Pk_s1 = (t, r)

#     if len(lines) > idx + 4:  # confirmed ballots
#         t = int(lines[idx + 3][5:-1])
#         r = int(lines[idx + 4][5:])
#         Pk_s = (t, r)
#         receipt = {
#             "status": "confirm",
#             "id": id,
#             "Ui": Ui,
#             "Vi": Vi,
#             "Ei": Ei,
#             "Wi": Wi,
#             "Pwf": Pwf,
#             "Pk_s1": Pk_s1,
#             "Pk_s": Pk_s
#         }
#     else:  # audited ballots
#         matrix_string = lines[idx+2].split("Ballot:")[1].strip()
#         ballot = eval(matrix_string)
#         ri = int(lines[idx + 3][4:])
#         receipt = {
#             "status": "audit",
#             "id": id,
#             "Ui": Ui,
#             "Vi": Vi,
#             "Ei": Ei,
#             "Wi": Wi,
#             "Pwf": Pwf,
#             "Pk_s1": Pk_s1,
#             "ballot": ballot,
#             "ri": ri
#         }

#     return receipt


# find the modular multiplicative inverse of bb of Z_aa
def multiplicativeInverse(aa, bb):
    a = aa
    b = bb
    r = a%b
    q = (a-r)//b
    t1 = 0
    t2 = 1
    t3 = t1 - q*t2
    while r!=0:
        a = b
        b = r
        r = a%b
        q = (a-r)//b
        t1 = t2
        t2 = t3
        t3 = t1 - q*t2
    if t2 < 0:
        t2 = aa + t2
    else:
        t2 = t2 % aa
    return t2
    

def verifySingleProof(v1, tu1, g1, u, c, q):
    check_t = pow(g1, v1, q) * pow(u, c, q)
    check_t = check_t % q
    if check_t == tu1:
        return True
    else:
        return False

    
def verifyPWF(filename):
    receipt = readReceipt(filename)
    c, d, h, q, g1, g2 = readPublicKey()

    for i in range(len(c)):
        for row_idx, row in enumerate(receipt["Ei"][i]):
            for col_idx, element in enumerate(row):
                # retrieve the proof for the current element
                proof = receipt["Pwf"][i][row_idx][col_idx]
                tr = proof["r"]
                tU = proof["U"]
                tV = proof["V"]
                tE = proof["E"]
                tW = proof["W"]

                tmp = f"{g1[i]}{g2[i]}{c[i]}{d[i]}{h[i]}{receipt['Ui'][i]}{receipt['Vi'][i]}{element}{receipt['Wi'][i]}{tU[0]}{tV[0]}{tE[0]}{tW[0]}{tU[1]}{tV[1]}{tE[1]}{tW[1]}"
                c_hash = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
                c_hash = int(c_hash, 16) % q[i]

                tmp = str(receipt["Ui"][i]) + str(receipt["Vi"][i]) + str(receipt["Ei"][i])
                alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
                alpha = int(alpha, 16) % q[i]

                valid_first_r = (
                    verifySingleProof(tr[0], tU[0], g1[i], receipt["Ui"][i], c_hash, q[i]) and
                    verifySingleProof(tr[0], tV[0], g2[i], receipt["Vi"], c_hash, q[i]) and
                    verifySingleProof(tr[0], tE[0], h[i], element, c_hash, q[i]) and
                    verifySingleProof(tr[0], tW[0], (c[i] * pow(d[i], alpha, q[i]) % q[i]), receipt["Wi"][i], c_hash, q[i])
                )

                valid_second_r = (
                    verifySingleProof(tr[1], tU[1], g1[i], receipt["Ui"][i], c_hash, q[i]) and
                    verifySingleProof(tr[1], tV[1], g2[i], receipt["Vi"][i], c_hash, q[i]) and
                    verifySingleProof(tr[1], tE[1], h[i], (element * multiplicativeInverse(q[i], g1[i])) % q[i], c_hash, q[i]) and
                    verifySingleProof(tr[1], tW[1], (c[i] * pow(d[i], alpha, q[i]) % q[i]), receipt["Wi"][i], c_hash, q[i])
                )

                # if neither proof passes, the verification fails
                if not (valid_first_r or valid_second_r):
                    return False

    return True
#     flag = 0
#     for i in range(len(c)):

#         tr = receipt["Pwf"][i]["r"]
#         tU = receipt["Pwf"][i]["U"]
#         tV = receipt["Pwf"][i]["V"]
#         tE = receipt["Pwf"][i]["E"]
#         tW = receipt["Pwf"][i]["W"]

#         tmp = str(g1[i]) + str(g2[i]) + str(c[i]) + str(d[i]) + str(h[i]) + str(receipt["Ui"][i]) + str(receipt["Vi"][i]) + str(receipt["Ei"][i]) + str(receipt["Wi"][i]) + str(tU[0]) + str(tV[0]) + str(tE[0]) + str(tW[0]) + str(tU[1]) + str(tV[1]) + str(tE[1]) + str(tW[1])
#         c_hash = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
#         c_hash = int(c_hash, 16)

#         tmp = str(receipt["Ui"][i]) + str(receipt["Vi"][i]) + str(receipt["Ei"][i])
#         alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
#         alpha = int(alpha, 16)

#         if verifySingleProof(tr[0], tU[0], g1[i], receipt["Ui"][i], c_hash, q[i]) and verifySingleProof(tr[0], tV[0], g2[i], receipt["Vi"][i], c_hash, q[i]):
#             if verifySingleProof(tr[0], tE[0], h[i], receipt["Ei"][i], c_hash, q[i]) and verifySingleProof(tr[0], tW[0], (c[i] * pow(d[i], alpha, q[i]) % q[i]), receipt["Wi"][i], c_hash, q[i]):
#                 flag += 1
        
#         if verifySingleProof(tr[1], tU[1], g1[i], receipt["Ui"][i], c_hash, q[i]) and verifySingleProof(tr[1], tV[1], g2[i], receipt["Vi"][i], c_hash, q[i]):
#             tmp = multiplicativeInverse(q[i], g1[i])
#             if verifySingleProof(tr[1], tE[1], h[i], receipt["Ei"][i]*tmp%q[i], c_hash, q[i]) and verifySingleProof(tr[1], tW[1], (c[i] * pow(d[i], alpha, q[i]) % q[i]), receipt["Wi"][i], c_hash, q[i]):
#                 flag += 1

#     if flag == len(c):
#         return True
#     return False


def auditVerify(filename, n1):
    receipt = readReceipt(filename)
    c, d, h, q, g1, g2 = readPublicKey()
    if receipt["status"] == "confirm":
        print("This is not audit ballot.")
        return False
    
    for i in range(len(c)):
        ri = receipt["ri"][i]
        vi = receipt["ballot"][i]
        
        if pow(g1[i], ri, q[i]) != receipt["Ui"][i]:
            return False
        
        if pow(g2[i], ri, q[i]) != receipt["Vi"][i]:
            return False
        
        if pow(h[i], ri, q[i]) * pow(g1[i], vi, q[i]) != receipt["Ei"][i]:
            return False
        
        tmp = str(receipt["Ui"][i]) + str(receipt["Vi"][i]) + str(receipt["Ei"][i])
        alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
        alpha = int(alpha, 16)
        if pow(c[i], ri, q[i]) * pow(d[i], (ri*alpha), q[i]) % q[i] != receipt["Wi"][i]:
            return False

        if not verifyPWF(filename):
            return False
        
        # obtain hash c
        tmp = str(g1[i]) + str(n1[i]) + str(receipt["Pk_s1"][i][0])
        hash_c = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
        hash_c = int(hash_c, 16)    
        if not verifySingleProof(receipt["Pk_s1"][i][1], receipt["Pk_s1"][i][0], g1[i], n1[i], hash_c, q[i]):
            return False
    
    return True



if __name__ == '__main__':
    print(verifyPWF("Receipt1.txt"))
    print(verifyPWF("Receipt2.txt"))

    # print(readReceipt("Receipt1.txt"))
    # print(readReceipt("Receipt2.txt"))