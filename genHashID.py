# Voter Registration
#       generate internal nullifier randomly
#       then hash (studentID + internal nullifier)
#       the voter should keep the internal nullifier privately
#       system only receives the hash value 

import hashlib
import string
import secrets



def gen_voterHash(ID, genFile = True, returnPassword = False):
    alphabet = string.ascii_letters + string.digits
    nullifier_internal = ''.join(secrets.choice(alphabet) for i in range(22))
    ID32 = bytes(ID + nullifier_internal, 'utf-8')
    # print("Please remember this secret key: ", nullifier_internal)

    # the generating file is easier for debugging and testing :P
    if genFile:
        f = open(ID + ".txt", "w")
        f.write("Student ID: " + ID)
        f.write("\nSecret key: " + nullifier_internal)
        f.close()

    if returnPassword: return hashlib.sha256(ID32).hexdigest(), nullifier_internal
    return hashlib.sha256(ID32).hexdigest()



if __name__ == '__main__':
    # maximun voter is 32
    studentID_hashList = []
    for i in range(32):
        # studentID = ''.join(secrets.choice(string.digits) for i in range(10))
        if i + 1 > 9:
            studentID = '00000000' + str(i+1)
        else:
            studentID = '000000000' + str(i+1)
        studentID_hashList.append(gen_voterHash(studentID, False))

    count = 0
    while count < 32:
        studentID = input("Please enter 10 digits student ID or E to end: ")
        if len(studentID) == 10:
            hash_value = gen_voterHash(studentID)
            studentID_hashList[count] = hash_value
            count += 1
        if studentID == "E":
            break
    
    f = open("hashList.txt", "w")
    for i in studentID_hashList:
        f.write(i + "\n")
    f.close()