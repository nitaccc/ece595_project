# Some functions used in DRE
#       - calculate zkp of s1 and s and Pwf
#       - generate receipt file


import hashlib
import pickle
from random import randint
from util import mergeReceipt


def genProof_s1(n1, g1, s1, q):
    v = randint(1, q-1)
    t = pow(g1, v, q)
    tmp = str(g1) + str(n1) + str(t)
    c = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    c = int(c, 16)
    r = (v - c*s1) % (q-1)

    return (t, r)



def genProof_Ei(ri, g1, g2, c, d, h, Ui, Vi, Ei, Wi, q):
    tmp = str(Ui) + str(Vi) + str(Ei)
    alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    alpha = int(alpha, 16)

    r1 = randint(1, q-1)
    t1_U = pow(g1, r1, q)
    t1_V = pow(g2, r1, q)
    t1_E = pow(h, r1, q)
    # tmp = str(t1_U) + str(t1_V) + str(t1_E)
    # t1_alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    # t1_alpha = int(t1_alpha, 16)
    t1_W = pow(c, r1, q) * pow(d, (r1*alpha), q) % q

    r2 = randint(1, q-1)
    t2_U = pow(g1, r2, q)
    t2_V = pow(g2, r2, q)
    t2_E = pow(h, r2, q)# * g1 % q
    # tmp = str(t2_U) + str(t2_V) + str(t2_E)
    # t2_alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    # t2_alpha = int(t2_alpha, 16)
    t2_W = pow(c, r2, q) * pow(d, (r2*alpha), q) % q

    tmp = str(g1) + str(g2) + str(c) + str(d) + str(h) + str(Ui) + str(Vi) + str(Ei) + str(Wi) + str(t1_U) + str(t1_V) + str(t1_E) + str(t1_W) + str(t2_U) + str(t2_V) + str(t2_E) + str(t2_W)
    c_hash = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    c_hash = int(c_hash, 16)
    v1 = (r1 - c_hash*ri) % (q-1)
    v2 = (r2 - c_hash*ri) % (q-1)

    proof = {"r": [v1, v2],
             "U": [t1_U, t2_U], 
             "V": [t1_V, t2_V], 
             "E": [t1_E, t2_E], 
             "W": [t1_W, t2_W]}

    return proof



def DRE_receipt(connection, i, question_len, c, d, h, q, g1, g2, s1, n1, t, m, s, n):
    merge_r = {"id": i, "Ui": [], "Vi": [], "Ei": [], "Wi": [], "Pwf": [], "Pk_s1": []}
    all_vi = []
    all_ri = []
    all_alpha = []
    for question_idx in range(question_len):
        while True:
            tmp = connection.recv(512)
            if len(tmp) > 0:
                break
        vi = int(tmp.decode())
        ri = randint(1, q[question_idx]-1)
        Ui = pow(g1[question_idx], ri, q[question_idx])
        Vi = pow(g2[question_idx], ri, q[question_idx])
        Ei = pow(h[question_idx], ri, q[question_idx]) * pow(g1[question_idx], vi, q[question_idx])
        tmp = str(Ui) + str(Vi) + str(Ei)
        alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
        alpha = int(alpha, 16)
        Wi = pow(c[question_idx], ri, q[question_idx]) * pow(d[question_idx], (ri*alpha), q[question_idx]) % q[question_idx]

        Pwf = genProof_Ei(ri, g1[question_idx], g2[question_idx], c[question_idx], d[question_idx], h[question_idx], Ui, Vi, Ei, Wi, q[question_idx])
        s1[question_idx] = s1[question_idx] + ri
        n1[question_idx] = n1[question_idx] * Ui % q[question_idx]
        Pk_s1 = genProof_s1(n1[question_idx], g1[question_idx], s1[question_idx], q[question_idx])

        # first half of the receipt
        receipt = {"id": i, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1}
        connection.send(pickle.dumps(receipt))
        merge_r = mergeReceipt(merge_r, receipt)
        all_vi.append(vi)
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
            connection.send(pickle.dumps(["audit", all_vi, all_ri]))
            break
        elif decision == "y":
            merge_r["status"] = "confirm"
            Pk_s = []
            for i in range(question_len):
                t[i] = t[i] + all_vi[i]
                m[i] = m[i] + all_ri[i] * all_alpha[i]
                s[i] = s[i] + all_ri[i]
                n[i] = n[i] * merge_r['Ui'][i] % q[i]
                Pk_s.append(genProof_s1(n[i], g1[i], s[i], q[i]))
            merge_r["Pk_s"] = Pk_s
            connection.send(pickle.dumps(["confirm", Pk_s]))
            break
    
    return t, m, s, s1, n, n1, merge_r