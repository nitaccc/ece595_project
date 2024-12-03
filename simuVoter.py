import socket
import pickle
import string
import secrets
import hashlib
from genHashID import gen_voterHash
from verify import verifyPWF, auditVerify
from util import printReceipt, readReceipt


NUM_CANDIDATES = 5


def mergeReceipt(r1, r2):
    r1["id"] = r2["id"]
    r1["Ui"].append(r2["Ui"])
    r1["Vi"].append(r2["Vi"])
    r1["Ei"].append(r2["Ei"])
    r1["Wi"].append(r2["Wi"])
    r1["Pwf"].append(r2["Pwf"])
    r1["Pk_s1"].append(r2["Pk_s1"])
    return r1



if __name__ == '__main__':
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.connect(('localhost', 8070))

    while True:
        studentID = input("Please enter your 10 digits student ID or enter E to end registration: ")
        if len(studentID) == 10:
            hash_value = gen_voterHash(studentID)
            clientsocket.send(pickle.dumps([hash_value]))
        if studentID == "E":
            clientsocket.send(pickle.dumps(["E"]))
            break
    print("End of Registration. \n\n\n")

    while True:
        tmp = clientsocket.recv(512)
        if len(tmp) > 0:
            break
    question_set = ["You learn a lot from this course. ", "You prefer take this course in person. "]
    clientsocket.send(str(len(question_set)).encode(encoding='utf-8'))
    receipt_name = []

    while True:
        # Verify identity
        studentID = input("Please enter your 10 digits student ID or enter E to end voting: ")
        if studentID == "E": break
        elif len(studentID) != 10: continue

        secretKey = input("Please enter the secret key: ")
        verifyID = bytes(studentID + secretKey, 'utf-8')
        clientsocket.send(hashlib.sha256(verifyID).digest())
        while True:
            tmp = clientsocket.recv(512)
            if len(tmp) > 0:
                break
        if tmp == bytes(2): 
            print("Identity Verification Failed. ")
            continue
        print("Identity Verification Passed.")

        # send choice, then receive the first part of the receipt
        print("*****\nEnter 5 if STRONGLY AGREE the statement")
        print("Enter 4 if slightly agree the statement")
        print("Enter 3 if neutral")
        print("Enter 2 if slightly disagree the statement")
        print("Enter 1 if STRONGLY DISAGREE the statement\n*****")
        merge_r = {"id": 0, "Ui": [], "Vi": [], "Ei": [], "Wi": [], "Pwf": [], "Pk_s1": []}
        for question in question_set:
            while True:
                vi = input(question + "Enter 1~5: ")
                if vi == '1' or vi == '2' or vi == '3' or vi == '4' or vi == '5':
                    break
            clientsocket.send(vi.encode(encoding='utf-8'))
            while True:
                tmp = clientsocket.recv(4096)
                if len(tmp) > 0:
                    receipt = pickle.loads(tmp)
                    break
            merge_r = mergeReceipt(merge_r, receipt)
        # send decision, then receive the rest of the receipt
        while True:
            decision = input("Confirm (y/n): ")
            if decision == 'y' or decision == 'n':
                break
        clientsocket.send(decision.encode(encoding='utf-8'))
        while True:
            tmp = clientsocket.recv(4096)
            if len(tmp) > 0:
                receipt = pickle.loads(tmp)
                if receipt[0] == "E":
                    print("Receipt failed blockchain verification. Please vote again. \n")
                else:
                    merge_r['status'] = receipt[0]
                    if receipt[0] == "audit":
                        merge_r['ballot'] = receipt[1]
                        merge_r["ri"] = receipt[2]
                    elif receipt[0] == "confirm":
                        merge_r["Pk_s"] = receipt[1]
                    tmp = printReceipt(merge_r, len(question_set), True)
                    receipt_name.append(tmp)
                    print(tmp, "is generated.\n\n\n\n\n\n\n")
                break
        
    # End Voting
    clientsocket.send(bytes("E", 'utf-8'))
    print("End of Voting.\n\n\n")

    # Tally
    print("\nTally:")
    while True:
        tmp = clientsocket.recv(512)
        if len(tmp) > 0:
            publicKey = pickle.loads(tmp)
            break
    clientsocket.send(pickle.dumps(question_set))
    print("c:", publicKey["c"])
    print("d:", publicKey["d"])
    print("h:", publicKey["h"])
    print("q:", publicKey["q"])
    print("g1:", publicKey["g1"])
    print("g2:", publicKey["g2"])
    print("t:", publicKey["t"])
    print("s:", publicKey["s"])
    print("m:", publicKey["m"])
    Ei_tally = [[[1 for _ in range(NUM_CANDIDATES)] for _ in range(NUM_CANDIDATES)] for _ in range(len(question_set))]
    Vi_tally = [1 for _ in range(len(question_set))]
    Wi_tally = [1 for _ in range(len(question_set))]
    Ui_tally = [1 for _ in range(len(question_set))]
    n1_tally = [1 for _ in range(len(question_set))]

    for filename in receipt_name:

        receipt = readReceipt(filename)

        for i in range(len(question_set)):
            n1_tally[i] = n1_tally[i] * receipt["Ui"][i] % publicKey['q'][i]

        if not verifyPWF(filename):
            print("There has been an error in the vote while verifying PWFs. Insecure!")
            exit()
        
        if receipt['status'] == "audit":
            if not auditVerify(filename, n1_tally):
                print("There has been an error in an audited ballot. Insecure!")
                exit()
        else: 
            for i in range(len(question_set)):
                Ui_tally[i] = (Ui_tally[i] * receipt["Ui"][i]) % publicKey['q'][i]
                Vi_tally[i] = (Vi_tally[i] * receipt["Vi"][i]) % publicKey['q'][i]
                Wi_tally[i] = (Wi_tally[i] * receipt["Wi"][i]) % publicKey['q'][i]
                Ei_matrix = receipt["Ei"][i]
                # multiply matrices element-wise modulo q
                for k in range(len(Ei_matrix)):
                    for j in range(len(Ei_matrix[k])):
                        Ei_tally[i][k][j] = (Ei_tally[i][k][j] * Ei_matrix[k][j]) % publicKey['q'][i]

    
    # Public verifies the tally equations
    for i in range(len(question_set)):
        if (Ui_tally[i] != pow(publicKey['g1'][i], publicKey['s'][i], publicKey['q'][i])):
            print("There has been an error in the vote tallying of Ui's. Insecure!")
            exit()
        elif (Vi_tally[i] != pow(publicKey['g2'][i], publicKey['s'][i], publicKey['q'][i])):
            print("There has been an error in the vote talling of Vi's. Insecure!")
            exit()
        elif (Wi_tally[i] != (pow(publicKey['c'][i], publicKey['s'][i], publicKey['q'][i]) * pow(publicKey['d'][i], publicKey['m'][i], publicKey['q'][i])) % publicKey['q'][i]):
            print("There has been an error in the vote tallying of Wi's. Insecure!")
            exit()
        expected_Ei_tally = [
            [pow(publicKey['h'][i], publicKey['s'][i], publicKey['q'][i]) * pow(publicKey['g1'][i], publicKey['t'][i][row][col], publicKey['q'][i]) % publicKey['q'][i] for col in range(len(Ei_tally[i][0]))]
            for row in range(len(Ei_tally[i]))
        ]
        for k in range(len(Ei_tally[i])):
            for j in range(len(Ei_tally[i][k])):
                if Ei_tally[i][k][j] != expected_Ei_tally[k][j]:
                  print(f"There has been an error in the vote tallying of Ei[{k}][{j}]. Insecure!")
                  exit()
    print("All tally verifications have passed! Course evaluation complete and secure!")

            