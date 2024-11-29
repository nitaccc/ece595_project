# return a list from a string
def removeList(s, flag = True):
    if flag: s = s.split(":")[1].strip("[] \n")
    else: s = s.strip("[] \n")
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
        f.write("\n\nQuestion " + str(i+1))
        f.write("\nUi: " + str(receipt["Ui"][i]))
        f.write("\nVi: " + str(receipt["Vi"][i]))
        f.write("\nWi: " + str(receipt["Wi"][i]))
        f.write("\nEi: \n")
        for row in receipt["Ei"][i]:
            f.write(str(row) + "\n")
        for row_idx, row in enumerate(receipt["Pwf"][i]):
            f.write(f"\nPWF_Ei Row {row_idx + 1}:")
            # Iterate through columns of the row
            for col_idx, proof in enumerate(row):
                f.write(f"\n  Proof for element ({row_idx + 1}, {col_idx + 1}):")
                tmp = "".join([
                    "\n    r: ", str(proof["r"]),
                    "\n    U: ", str(proof["U"]),
                    "\n    V: ", str(proof["V"]),
                    "\n    E: ", str(proof["E"]),
                    "\n    W: ", str(proof["W"])
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
    if len(lines) < 350: t = -1
    Ui = [int(lines[4][4:-1]), int(lines[179+t][4:-1])]
    Vi = [int(lines[5][4:-1]), int(lines[180+t][4:-1])]
    Wi = [int(lines[6][4:-1]), int(lines[181+t][4:-1])]
    Ei = []
    tmp_Ei = []
    ei_start_idx = 8
    while lines[ei_start_idx].startswith("["):  # Check if line starts with a matrix row
        tmp_Ei.append(eval(lines[ei_start_idx].strip()))  # Strip any leading/trailing whitespace and convert the string representation to a list
        ei_start_idx += 1
    Ei.append(tmp_Ei)
    tmp_Ei = []
    ei_start_idx = 183+t
    while lines[ei_start_idx].startswith("["):  # Check if line starts with a matrix row
        tmp_Ei.append(eval(lines[ei_start_idx].strip()))  # Strip any leading/trailing whitespace and convert the string representation to a list
        ei_start_idx += 1
    Ei.append(tmp_Ei)

    Pwf = []
    start_idx = [14, 189+t]
    for question in range(2):
        tmp_Pwf = []
        row_idx = start_idx[question]
        while row_idx < len(lines) and lines[row_idx].startswith("PWF_Ei Row"):
            current_row = []  # Temporary storage for proofs in the current row
            
            # Process proofs in the current row
            proof_idx = row_idx + 1
            while proof_idx < len(lines) and lines[proof_idx].startswith("  Proof for element"):
                proof = {}

                # Extract values for r, U, V, E, W
                proof["r"] = [int(x) for x in lines[proof_idx + 1].split(":")[1].strip(" []\n").split(",")]
                proof["U"] = [int(x) for x in lines[proof_idx + 2].split(":")[1].strip(" []\n").split(",")]
                proof["V"] = [int(x) for x in lines[proof_idx + 3].split(":")[1].strip(" []\n").split(",")]
                proof["E"] = [int(x) for x in lines[proof_idx + 4].split(":")[1].strip(" []\n").split(",")]
                proof["W"] = [int(x) for x in lines[proof_idx + 5].split(":")[1].strip(" []\n").split(",")]
                
                current_row.append(proof)
                proof_idx += 6  # Move to the next proof element

            tmp_Pwf.append(current_row)  # Append the completed row to Pwf
            row_idx = proof_idx  # Move to the next row
        Pwf.append(tmp_Pwf)

    tt = int(lines[170][5:-1])
    r = int(lines[171][5:-1])
    Pk_s1 = [(tt, r)]
    tt = int(lines[345+t][5:-1])
    r = int(lines[346+t][5:-1])
    Pk_s1.append((tt, r))
    
    if len(lines) > 349:
        tt = int(lines[173][5:-1])
        r = int(lines[174][5:-1])
        Pk_s = [(tt, r)]
        tt = int(lines[348][5:-1])
        r = int(lines[349][5:-1])
        Pk_s.append((tt, r))
        receipt = {"status": "confirm", "id": id, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1, "Pk_s": Pk_s}
    else:
        ballot = [eval(lines[172][8:]), eval(lines[346][8:])]
        ri = [int(lines[173][4:-1]), int(lines[347][4:-1])]
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