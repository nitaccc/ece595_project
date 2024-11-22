# Some functions used in DRE
#       - calculate zkp of s1 and s and Pwf
#       - generate receipt file

from random import randint
import hashlib
import socket
import pickle


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



def DRE_receipt(connection, i, c, d, h, q, g1, g2, s1, n1, t, m, s, n):
    # vi = input("Type 0 or 1: ")
    while True:
        tmp = connection.recv(512)
        if len(tmp) > 0:
            break
    vi = int(tmp.decode())
    ri = randint(1, q-1)
    Ui = pow(g1, ri, q)
    Vi = pow(g2, ri, q)
    Ei = pow(h, ri, q) * pow(g1, vi, q)
    tmp = str(Ui) + str(Vi) + str(Ei)
    alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    alpha = int(alpha, 16)
    Wi = pow(c, ri, q) * pow(d, (ri*alpha), q) % q

    Pwf = genProof_Ei(ri, g1, g2, c, d, h, Ui, Vi, Ei, Wi, q)
    s1 = s1 + ri
    n1 = n1 * Ui % q
    Pk_s1 = genProof_s1(n1, g1, s1, q)

    # first half of the receipt
    receipt = {"id": i, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1}
    connection.send(pickle.dumps(receipt))

    # check their decision
    while True:
        # decision = input("Confirm (y/n): ")
        while True:
            tmp = connection.recv(512)
            if len(tmp) > 0:
                break
        decision = tmp.decode()
        # audit receipt: (i : (Ui, Vi, Ei, Wi, Pwf{Ei}, PK{s1}), (audited, ri, vi)
        # confirm receipt: (i : (Ui, Vi, Ei, Wi, PWF{Ei}, PK{s1}), (confirmed, PK{s})
        if decision == "n":
            receipt["status"] = "audit"
            receipt["ballot"] = vi
            receipt["ri"] = ri
            break
        elif decision == "y":
            receipt["status"] = "confirm"
            t = t + vi
            m = m + ri * alpha
            s = s + ri
            n = n * Ui % q
            Pk_s = genProof_s1(n, g1, s, q)
            receipt["Pk_s"] = Pk_s
            break
    
    connection.send(pickle.dumps(receipt))
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
    f.write("\nEi: " + str(receipt["Ei"]))
    f.write("\nWi: " + str(receipt["Wi"]))
    tmp = "".join([
        "\nPWF: ",
        "\n  r = ", str(receipt["Pwf"]["r"]),
        "\n  U = ", str(receipt["Pwf"]["U"]),
        "\n  V = ", str(receipt["Pwf"]["V"]),
        "\n  E = ", str(receipt["Pwf"]["E"]),
        "\n  W = ", str(receipt["Pwf"]["W"])
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
