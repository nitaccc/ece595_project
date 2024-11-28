import hashlib

def readReceipt(filename):
    f = open(filename, "r")
    lines = f.readlines()
    f.close()
    id = int(lines[1][11:-1])
    Ui = int(lines[2][4:-1])
    Vi = int(lines[3][4:-1])

    Ei = []
    ei_start_idx = 5
    while lines[ei_start_idx].startswith("["):  # Check if line starts with a matrix row
        Ei.append(eval(lines[ei_start_idx][1:-2]))  # Convert the string representation of the list to a list
        ei_start_idx += 1

    Wi = int(lines[ei_start_idx][4:-1])

    Pwf = []
    row_idx = ei_start_idx + 1
    while row_idx < len(lines) and lines[row_idx].startswith("PWF_Ei Row"):
        current_row = []  # Temporary storage for proofs in the current row
        
        # Process proofs in the current row
        proof_idx = row_idx + 1
        while proof_idx < len(lines) and lines[proof_idx].startswith("  Proof for element"):
            proof = {}

            # Extract values for r, U, V, E, W
            proof["r"] = [int(x) for x in lines[proof_idx + 1].split("=")[1].strip(" []\n").split(",")]
            proof["U"] = [int(x) for x in lines[proof_idx + 2].split("=")[1].strip(" []\n").split(",")]
            proof["V"] = [int(x) for x in lines[proof_idx + 3].split("=")[1].strip(" []\n").split(",")]
            proof["E"] = [int(x) for x in lines[proof_idx + 4].split("=")[1].strip(" []\n").split(",")]
            proof["W"] = [int(x) for x in lines[proof_idx + 5].split("=")[1].strip(" []\n").split(",")]
            
            current_row.append(proof)
            proof_idx += 6  # Move to the next proof element

        Pwf.append(current_row)  # Append the completed row to Pwf
        row_idx = proof_idx  # Move to the next row

    idx = row_idx + 1
    t = int(lines[idx][5:-1])
    r = int(lines[idx + 1][5:-1])
    Pk_s1 = (t, r)

    if len(lines) > idx + 4:  # confirmed ballots
        t = int(lines[idx + 3][5:-1])
        r = int(lines[idx + 4][5:])
        Pk_s = (t, r)
        receipt = {
            "status": "confirm",
            "id": id,
            "Ui": Ui,
            "Vi": Vi,
            "Ei": Ei,
            "Wi": Wi,
            "Pwf": Pwf,
            "Pk_s1": Pk_s1,
            "Pk_s": Pk_s
        }
    else:  # audited ballots
        matrix_string = lines[idx+2].split("Ballot:")[1].strip()
        ballot = eval(matrix_string)
        ri = int(lines[idx + 3][4:])
        receipt = {
            "status": "audit",
            "id": id,
            "Ui": Ui,
            "Vi": Vi,
            "Ei": Ei,
            "Wi": Wi,
            "Pwf": Pwf,
            "Pk_s1": Pk_s1,
            "ballot": ballot,
            "ri": ri
        }

    return receipt

def readPublicKey():
    f = open("publicKey.txt", "r")
    lines = f.readlines()
    c = int(lines[0][3:-1])
    d = int(lines[1][3:-1])
    h = int(lines[2][3:-1])
    q = int(lines[3][3:-1])
    g1 = int(lines[4][4:-1])
    g2 = int(lines[5][4:])
    f.close()
    return c, d, h, q, g1, g2



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
    print(f"left: {check_t}, t (right): {tu1}")
    if check_t == tu1:
        return True
    else:
        return False
    

    
def verifyPWF(filename):
    receipt = readReceipt(filename)
    c, d, h, q, g1, g2 = readPublicKey()

    for row_idx, row in enumerate(receipt["Ei"]):
        for col_idx, element in enumerate(row):
            # retrieve the proof for the current element
            proof = receipt["Pwf"][row_idx][col_idx]
            tr = proof["r"]
            tU = proof["U"]
            tV = proof["V"]
            tE = proof["E"]
            tW = proof["W"]

            tmp = (
                str(g1) + str(g2) + str(c) + str(d) + str(h) +
                str(receipt["Ui"]) + str(receipt["Vi"]) + 
                str(element) + str(receipt["Wi"]) +
                str(tU[0]) + str(tV[0]) + str(tE[0]) + str(tW[0]) +
                str(tU[1]) + str(tV[1]) + str(tE[1]) + str(tW[1])
            )
            c_hash = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
            c_hash = int(c_hash, 16)

            tmp = str(receipt["Ui"]) + str(receipt["Vi"]) + str(element)
            alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
            alpha = int(alpha, 16)

            valid_first_r = (
                verifySingleProof(tr[0], tU[0], g1, receipt["Ui"], c_hash, q) and
                verifySingleProof(tr[0], tV[0], g2, receipt["Vi"], c_hash, q) and
                verifySingleProof(tr[0], tE[0], h, element, c_hash, q) and
                verifySingleProof(tr[0], tW[0], (c * pow(d, alpha, q) % q), receipt["Wi"], c_hash, q)
            )
            print("valid first r: " + str(valid_first_r))

            valid_second_r = (
                verifySingleProof(tr[1], tU[1], g1, receipt["Ui"], c_hash, q) and
                verifySingleProof(tr[1], tV[1], g2, receipt["Vi"], c_hash, q) and
                verifySingleProof(tr[1], tE[1], h, element, c_hash, q) and
                verifySingleProof(tr[1], tW[1], (c * pow(d, alpha, q) % q), receipt["Wi"], c_hash, q)
            )
            print("valid first r: " + str(valid_second_r))

            # if neither proof passes, the verification fails
            if not (valid_first_r or valid_second_r):
                return False

    return True



def auditVerify(filename, n1):
    receipt = readReceipt(filename)
    c, d, h, q, g1, g2 = readPublicKey()
    if receipt["status"] == "confirm":
        print("This is not audit ballot.")
        return False
    
    ri = receipt["ri"]
    vi = receipt["ballot"]
    
    if pow(g1, ri, q) != receipt["Ui"]:
        return False
    
    if pow(g2, ri, q) != receipt["Vi"]:
        return False
    
    if pow(h, ri, q) * pow(g1, vi, q) != receipt["Ei"]:
        return False
    
    tmp = str(receipt["Ui"]) + str(receipt["Vi"]) + str(receipt["Ei"])
    alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    alpha = int(alpha, 16)
    if pow(c, ri, q) * pow(d, (ri*alpha), q) % q != receipt["Wi"]:
        return False

    if not verifyPWF(filename):
        return False
    
    # obtain hash c
    tmp = str(g1) + str(n1) + str(receipt["Pk_s1"][0])
    hash_c = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    hash_c = int(hash_c, 16)    
    if not verifySingleProof(receipt["Pk_s1"][1], receipt["Pk_s1"][0], g1, n1, hash_c, q):
        return False
    
    return True



if __name__ == '__main__':
    # receipt = readReceipt("Receipt1.txt")
    # print(receipt)
    # receipt = readReceipt("Receipt2.txt")
    # print(receipt)

    print(verifyPWF("Receipt1.txt"))
    print(verifyPWF("Receipt2.txt"))
    print(verifyPWF("Receipt3.txt"))

    print(auditVerify("Receipt1.txt"))
    print(auditVerify("Receipt2.txt"))