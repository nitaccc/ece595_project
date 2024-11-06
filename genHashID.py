import sys
import hashlib
import string
import secrets
import warnings


# Voter Registration
#       generate internal nullifier randomly
#       then hash (studentID + internal nullifier)
#       the voter should keep the internal nullifier privately
#       system only receives the hash value 


def gen_voterHash(ID):
    alphabet = string.ascii_letters + string.digits
    nullifier_internal = ''.join(secrets.choice(alphabet) for i in range(22))
    ID32 = bytes(ID + nullifier_internal, 'utf-8')
    print("Please remember this confirmation number", nullifier_internal)

    # the generating file is easier for debugging and testing :P
    f = open(ID + ".txt", "w")
    f.write("Student ID: " + ID)
    f.write("Secret key: " + nullifier_internal)
    f.close()

    return hashlib.sha256(ID32).hexdigest()


if __name__ == '__main__':
    # python genHashID.py <studentID>
    if len(sys.argv) == 2:
        studentID = sys.argv[1]
        if len(studentID) != 10:
            warnings.warn('Please enter 10 digits student ID')
        else:
            hash_value = gen_voterHash(studentID)
            print(hash_value)
    else:
        studentID = "0123456789"
        hash_value = gen_voterHash(studentID)
        print(hash_value)