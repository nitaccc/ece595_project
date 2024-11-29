import hashlib
from util import readPublicKey, readReceipt


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

    flag = 0
    for i in range(len(c)):

        tr = receipt["Pwf"][i]["r"]
        tU = receipt["Pwf"][i]["U"]
        tV = receipt["Pwf"][i]["V"]
        tE = receipt["Pwf"][i]["E"]
        tW = receipt["Pwf"][i]["W"]

        tmp = str(g1[i]) + str(g2[i]) + str(c[i]) + str(d[i]) + str(h[i]) + str(receipt["Ui"][i]) + str(receipt["Vi"][i]) + str(receipt["Ei"][i]) + str(receipt["Wi"][i]) + str(tU[0]) + str(tV[0]) + str(tE[0]) + str(tW[0]) + str(tU[1]) + str(tV[1]) + str(tE[1]) + str(tW[1])
        c_hash = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
        c_hash = int(c_hash, 16)

        tmp = str(receipt["Ui"][i]) + str(receipt["Vi"][i]) + str(receipt["Ei"][i])
        alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
        alpha = int(alpha, 16)

        if verifySingleProof(tr[0], tU[0], g1[i], receipt["Ui"][i], c_hash, q[i]) and verifySingleProof(tr[0], tV[0], g2[i], receipt["Vi"][i], c_hash, q[i]):
            if verifySingleProof(tr[0], tE[0], h[i], receipt["Ei"][i], c_hash, q[i]) and verifySingleProof(tr[0], tW[0], (c[i] * pow(d[i], alpha, q[i]) % q[i]), receipt["Wi"][i], c_hash, q[i]):
                flag += 1
        
        if verifySingleProof(tr[1], tU[1], g1[i], receipt["Ui"][i], c_hash, q[i]) and verifySingleProof(tr[1], tV[1], g2[i], receipt["Vi"][i], c_hash, q[i]):
            tmp = multiplicativeInverse(q[i], g1[i])
            if verifySingleProof(tr[1], tE[1], h[i], receipt["Ei"][i]*tmp%q[i], c_hash, q[i]) and verifySingleProof(tr[1], tW[1], (c[i] * pow(d[i], alpha, q[i]) % q[i]), receipt["Wi"][i], c_hash, q[i]):
                flag += 1

    if flag == len(c):
        return True
    return False


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