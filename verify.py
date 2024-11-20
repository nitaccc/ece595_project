import hashlib

def readReceipt(filename):
    f = open(filename, "r")
    lines = f.readlines()
    f.close()
    id = int(lines[1][11:-1])
    Ui = int(lines[2][4:-1])
    Vi = int(lines[3][4:-1])
    Ei = int(lines[4][4:-1])
    Wi = int(lines[5][4:-1])

    idx = lines[7].find(',')
    r = [int(lines[7][7:idx]), int(lines[7][idx+1:-2])]
    idx = lines[8].find(',')
    U = [int(lines[8][7:idx]), int(lines[8][idx+1:-2])]
    idx = lines[9].find(',')
    V = [int(lines[9][7:idx]), int(lines[9][idx+1:-2])]
    idx = lines[10].find(',')
    E = [int(lines[10][7:idx]), int(lines[10][idx+1:-2])]
    idx = lines[11].find(',')
    W = [int(lines[11][7:idx]), int(lines[11][idx+1:-2])]
    Pwf = {"r": r, "U": U, "V": V, "E": E, "W": W}
    t = int(lines[13][5:-1])
    r = int(lines[14][5:-1])
    Pk_s1 = (t, r)
    
    if len(lines) > 17:
        t = int(lines[16][5:-1])
        r = int(lines[17][5:])
        Pk_s = (t, r)
        receipt = {"status": "confirm", "id": id, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1, "Pk_s": Pk_s}
        receipt["Pk_s"] = Pk_s
    else:
        ballot = int(lines[15][-2])
        ri = int(lines[16][4:])
        receipt = {"status": "audit", "id": id, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1, "ballot": ballot, "ri": ri}

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
    if check_t == tu1:
        return True
    else:
        return False
    

    
def verifyPWF(filename):
    receipt = readReceipt(filename)
    c, d, h, q, g1, g2 = readPublicKey()

    tr = receipt["Pwf"]["r"]
    tU = receipt["Pwf"]["U"]
    tV = receipt["Pwf"]["V"]
    tE = receipt["Pwf"]["E"]
    tW = receipt["Pwf"]["W"]

    tmp = str(g1) + str(g2) + str(c) + str(d) + str(h) + str(receipt["Ui"]) + str(receipt["Vi"]) + str(receipt["Ei"]) + str(receipt["Wi"]) + str(tU[0]) + str(tV[0]) + str(tE[0]) + str(tW[0]) + str(tU[1]) + str(tV[1]) + str(tE[1]) + str(tW[1])
    c_hash = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    c_hash = int(c_hash, 16)

    tmp = str(receipt["Ui"]) + str(receipt["Vi"]) + str(receipt["Ei"])
    alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    alpha = int(alpha, 16)

    if verifySingleProof(tr[0], tU[0], g1, receipt["Ui"], c_hash, q) and verifySingleProof(tr[0], tV[0], g2, receipt["Vi"], c_hash, q):
        if verifySingleProof(tr[0], tE[0], h, receipt["Ei"], c_hash, q) and verifySingleProof(tr[0], tW[0], (c * pow(d, alpha, q) % q), receipt["Wi"], c_hash, q):
            return True
    
    if verifySingleProof(tr[1], tU[1], g1, receipt["Ui"], c_hash, q) and verifySingleProof(tr[1], tV[1], g2, receipt["Vi"], c_hash, q):
        tmp = multiplicativeInverse(q, g1)
        if verifySingleProof(tr[1], tE[1], h, receipt["Ei"]*tmp%q, c_hash, q) and verifySingleProof(tr[1], tW[1], (c * pow(d, alpha, q) % q), receipt["Wi"], c_hash, q):
            return True
        
    return False



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
    
    # verify pk_s1, but how to obtain n1?
    if not verifySingleProof(receipt["Pk_s1"][1], receipt["Pk_s1"][0], g1, n1, c, q):
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

    # print(auditVerify("Receipt1.txt"))
    # print(auditVerify("Receipt2.txt"))