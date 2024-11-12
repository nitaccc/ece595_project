
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

    if len(lines) > 15:
        t = int(lines[13][5:-1])
        r = int(lines[14][5:-1])
        Pk_s1 = (t, r)
        receipt = {"id": id, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1}

        t = int(lines[16][5:-1])
        r = int(lines[17][5:])
        Pk_s = (t, r)
        receipt["Pk_s"] = Pk_s
    else:
        t = int(lines[13][5:-1])
        r = int(lines[14][5:])
        Pk_s1 = (t, r)
        receipt = {"id": id, "Ui": Ui, "Vi": Vi, "Ei": Ei, "Wi": Wi, "Pwf": Pwf, "Pk_s1": Pk_s1}

    return receipt



if __name__ == '__main__':
    receipt = readReceipt("Receipt1.txt")
    print(receipt)