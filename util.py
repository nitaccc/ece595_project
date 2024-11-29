# return a list from a string
def removeList(s):
    s = s.split(":")[1].strip("[] \n")
    result = [int(num) for num in s.split(",")]
    return result


def readPublicKey():
    f = open("publicKey.txt", "r")
    lines = f.readlines()
    c = removeList(lines[0])
    d = removeList(lines[1])
    h = removeList(lines[2])
    q = removeList(lines[3])
    g1 = removeList(lines[4])
    g2 = removeList(lines[5])
    f.close()
    return c, d, h, q, g1, g2


def printReceipt(receipt, question_len, opt = False):
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
    for i in range(question_len):
        f.write("\nUi: " + str(receipt["Ui"][i]))
        f.write("\nVi: " + str(receipt["Vi"][i]))
        f.write("\nEi: " + str(receipt["Ei"][i]))
        f.write("\nWi: " + str(receipt["Wi"][i]))
        tmp = "".join([
            "\nPWF: ",
            "\n  r: ", str(receipt["Pwf"][i]["r"]),
            "\n  U: ", str(receipt["Pwf"][i]["U"]),
            "\n  V: ", str(receipt["Pwf"][i]["V"]),
            "\n  E: ", str(receipt["Pwf"][i]["E"]),
            "\n  W: ", str(receipt["Pwf"][i]["W"])
        ])
        f.write(tmp)
        tmp = "".join([
            "\nPk_s1: ",
            "\n  t: ", str(receipt["Pk_s1"][i][0]),
            "\n  r: ", str(receipt["Pk_s1"][i][1])
        ])
        f.write(tmp)

        if receipt["status"] == "confirm":
            tmp = "".join([
                "\nPk_s: ",
                "\n  t: ", str(receipt["Pk_s"][i][0]),
                "\n  r: ", str(receipt["Pk_s"][i][1])
            ])
            f.write(tmp)
        else:
            f.write("\nBallot: " + str(receipt["ballot"][i]))
            f.write("\nri: " + str(receipt["ri"][i]))
        f.write("\n\n")

    f.close()
    return filename


def readReceipt(filename):
    f = open(filename, "r")
    lines = f.readlines()
    f.close()
    id = int(lines[1][11:-1])
    t = 0
    if len(lines) > 36: t = 1
    Ui = [int(lines[2][4:-1]), int(lines[19+t][4:-1])]
    Vi = [int(lines[3][4:-1]), int(lines[20+t][4:-1])]
    Ei = [int(lines[4][4:-1]), int(lines[21+t][4:-1])]
    Wi = [int(lines[5][4:-1]), int(lines[22+t][4:-1])]

    r = removeList(lines[7])
    U = removeList(lines[8])
    V = removeList(lines[9])
    E = removeList(lines[10])
    W = removeList(lines[11])
    Pwf = [{"r": r, "U": U, "V": V, "E": E, "W": W}]
    r = removeList(lines[24+t])
    U = removeList(lines[25+t])
    V = removeList(lines[26+t])
    E = removeList(lines[27+t])
    W = removeList(lines[28+t])
    Pwf.append({"r": r, "U": U, "V": V, "E": E, "W": W})

    tt = int(lines[13][5:-1])
    r = int(lines[14][5:-1])
    Pk_s1 = [(tt, r)]
    tt = int(lines[30+t][5:-1])
    r = int(lines[31+t][5:-1])
    Pk_s1.append((tt, r))
    
    if len(lines) > 36:
        tt = int(lines[16][5:-1])
        r = int(lines[17][5:-1])
        Pk_s = [(tt, r)]
        tt = int(lines[34][5:-1])
        r = int(lines[35][5:-1])
        Pk_s.append((tt, r))
        receipt = {"status": "confirm", "id": id, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1, "Pk_s": Pk_s}
    else:
        ballot = [int(lines[15][-2]), int(lines[32][-2])]
        ri = [int(lines[16][4:-1]), int(lines[33][4:-1])]
        receipt = {"status": "audit", "id": id, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1, "ballot": ballot, "ri": ri}

    return receipt


# combine two receipts
def mergeReceipt(r1, r2):
    r1["Ui"].append(r2["Ui"])
    r1["Vi"].append(r2["Vi"])
    r1["Ei"].append(r2["Ei"])
    r1["Wi"].append(r2["Wi"])
    r1["Pwf"].append(r2["Pwf"])
    r1["Pk_s1"].append(r2["Pk_s1"])
    return r1