import socket
import pickle
import string
import secrets
import hashlib
from genHashID import gen_voterHash
from zkp import printReceipt



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
        studentID = input("Please enter your 10 digits student ID or enter E to end: ")
        if len(studentID) == 10:
            hash_value = gen_voterHash(studentID)
            studentID_hashList[count] = hash_value
            clientsocket.send(pickle.dumps([hash_value]))
            count += 1
        if studentID == "E":
            clientsocket.send(pickle.dumps(["E"]))
            break
    print("End of Registration\n\n\n")

    while True:
        # Verify identity
        studentID = input("Please enter 10 digits student ID or enter E to end: ")
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
        print("Identity Verification Passed. ")

        # send choice, then receive the first part of the receipt
        while True:
            vi = input("Please rank 1-5: ")
            if vi == '1' or vi == '2' or vi == '3' or vi == '4' or vi == '5':
                break
        clientsocket.send(vi.encode(encoding='utf-8'))
        while True:
            tmp = clientsocket.recv(512)
            if len(tmp) > 0:
                receipt = pickle.loads(tmp)
                break
        # send decision, then receive the rest of the receipt
        while True:
            decision = input("Confirm (y/n): ")
            if decision == 'y' or decision == 'n':
                break
        clientsocket.send(decision.encode(encoding='utf-8'))
        while True:
            tmp = clientsocket.recv(512)
            if len(tmp) > 0:
                receipt = pickle.loads(tmp)
                break
        tmp = printReceipt(receipt, True)
        print(tmp, "is generated.\n\n\n")
    # End Voting
    clientsocket.send(bytes("E", 'utf-8'))
    print("Voting End")
            


