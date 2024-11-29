import socket
import pickle
import string
import secrets
import hashlib
from genHashID import gen_voterHash
from verify import verifyPWF, auditVerify
from util import printReceipt, readReceipt


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

    # Registration
    # maximun voter is 32 since the number of student does not exceed 32
    studentID_hashList = []
    for i in range(32):
        studentID = ''.join(secrets.choice(string.digits) for i in range(10))
        studentID_hashList.append(gen_voterHash(studentID, False))

    count = 0
    while count < 32:
        studentID = input("Please enter your 10 digits student ID or enter E to end registration: ")
        if len(studentID) == 10:
            hash_value = gen_voterHash(studentID)
            studentID_hashList[count] = hash_value
            clientsocket.send(pickle.dumps([hash_value]))
            count += 1
        if studentID == "E":
            clientsocket.send(pickle.dumps(["E"]))
            break
    print("End of Registration. \n\n\n")

    while True:
        tmp = clientsocket.recv(512)
        if len(tmp) > 0:
            break
    question_set = ["You learn a lot from this course. Strongly Agree(5) ~ Strongly Disagree(1): ", "You prefer take this course in person. Strongly Agree(5) ~ Strongly Disagree(1): "]
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
        print("Identity Verification Passed. \n")

        # send choice, then receive the first part of the receipt
        merge_r = {"id": 0, "Ui": [], "Vi": [], "Ei": [], "Wi": [], "Pwf": [], "Pk_s1": []}
        for question in question_set:
            while True:
                vi = input(question)
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
                merge_r['status'] = receipt[0]
                if receipt[0] == "audit":
                    merge_r['ballot'] = receipt[1]
                    merge_r["ri"] = receipt[2]
                elif receipt[0] == "confirm":
                    merge_r["Pk_s"] = receipt[1]
                break
        
        tmp = printReceipt(merge_r, len(question_set), True)
        receipt_name.append(tmp)
        print(tmp, "is generated.\n\n\n\n\n\n\n")
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
    print("c:", publicKey["c"])
    print("d:", publicKey["d"])
    print("h:", publicKey["h"])
    print("q:", publicKey["q"])
    print("g1:", publicKey["g1"])
    print("g2:", publicKey["g2"])
    print("t:", publicKey["t"])
    print("s:", publicKey["s"])
    print("m:", publicKey["m"])
    Ei_tally = [1 for _ in range(len(question_set))]
    Vi_tally = [1 for _ in range(len(question_set))]
    Wi_tally = [1 for _ in range(len(question_set))]
    Ui_tally = [1 for _ in range(len(question_set))]
    n1_tally = [1 for _ in range(len(question_set))]
    n1_tally = [1 for _ in range(len(question_set))]
    for filename in receipt_name:
        if not verifyPWF(filename):
            print("There has been an error in the vote while verifying PWFs. Insecure!")
            exit()
        receipt = readReceipt(filename)
        for i in range(len(question_set)):
            n1_tally[i] = n1_tally[i] * receipt["Ui"][i] % publicKey['q'][i]
        if receipt['status'] == "audit":
            if not auditVerify(filename, n1_tally):
                print("There has been an error in an audited ballot. Insecure!")
                exit()
        else: 
            for i in range(len(question_set)):
                Ui_tally[i] = (Ui_tally[i] * receipt["Ui"][i]) % publicKey['q'][i]
                Ei_tally[i] = (Ei_tally[i] * receipt["Ei"][i]) % publicKey['q'][i]
                Vi_tally[i] = (Vi_tally[i] * receipt["Vi"][i]) % publicKey['q'][i]
                Wi_tally[i] = (Wi_tally[i] * receipt["Wi"][i]) % publicKey['q'][i]
    
    # Public verifies the tally equations
    for i in range(len(question_set)):
        if (Ui_tally[i] != pow(publicKey['g1'][i], publicKey['s'][i], publicKey['q'][i])):
            print("There has been an error in the vote tallying of Ui's. Insecure!")
            exit()
        elif (Vi_tally[i] != pow(publicKey['g2'][i], publicKey['s'][i], publicKey['q'][i])):
            print("There has been an error in the vote talling of Vi's. Insecure!")
            exit()
        elif (Ei_tally[i] != (pow(publicKey['h'][i], publicKey['s'][i], publicKey['q'][i]) * pow(publicKey['g1'][i], publicKey['t'][i], publicKey['q'][i])) % publicKey['q'][i]):
            print("There has been an error in the vote tallying of Ei's. Insecure!")
            exit()
        elif (Wi_tally[i] != (pow(publicKey['c'][i], publicKey['s'][i], publicKey['q'][i]) * pow(publicKey['d'][i], publicKey['m'][i], publicKey['q'][i])) % publicKey['q'][i]):
            print("There has been an error in the vote tallying of Wi's. Insecure!")
            exit()
    print("All tally verifications have passed! Course evaluation complete and secure!")

            


