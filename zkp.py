# Some functions used in DRE
#       - calculate zkp of s1 and s and Pwf
#       - generate receipt file

from random import randint
import hashlib


def genProof_s1(n1, g1, s1, q):
    v = randint(1, q-1)
    t = g1^v
    tmp = str(g1) + str(n1) + str(t)
    c = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    c = int(c, 16)
    r = (v - c*s1) % (q-1)

    return (t, r)



def genProof_Ei(ri, g1, g2, c, d, h, Ui, Vi, Ei, Wi, q):
    r1 = randint(1, q-1)
    t1_U = g1^r1
    t1_V = g2^r1
    t1_E = (h^r1)
    tmp = str(t1_U) + str(t1_V) + str(t1_E)
    t1_alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    t1_alpha = int(t1_alpha, 16)
    t1_W = (c^r1) * (d^(r1*t1_alpha))

    r2 = randint(1, q-1)
    t2_U = g1^r2
    t2_V = g2^r2
    t2_E = (h^r2) * g1
    tmp = str(t2_U) + str(t2_V) + str(t2_E)
    t2_alpha = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    t2_alpha = int(t2_alpha, 16)
    t2_W = (c^r2) * (d^(r2*t2_alpha))

    tmp = str(g1) + str(g2) + str(c) + str(d) + str(h) + str(Ui) + str(Vi) + str(Ei) + str(Wi) + str(t1_U) + str(t1_V) + str(t1_E) + str(t1_W) + str(t2_U) + str(t2_V) + str(t2_E) + str(t2_W)
    c = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
    c = int(c, 16)
    v1 = (r1 - c*ri) % (q-1)
    v2 = (r2 - c*ri) % (q-1)

    proof = {"r": [v1, v2],
             "U": [t1_U, t2_U], 
             "V": [t1_V, t2_V], 
             "E": [t1_E, t2_E], 
             "W": [t1_W, t2_W]}
    
    return proof


def printReceipt(receipt):
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
        "\n  W = ", str(receipt["Pwf"]["W"]),
    ])
    f.write(tmp)
    f.write("\nPK_s1(t, r): " + str(receipt["Pk_s1"]))

    if receipt["status"] == "confirm":
        f.write("\nPK_s(t, r): " + str(receipt["Pk_s"]))
    else:
        f.write("\n\nThis ballot did not count")

    f.close()
    return filename