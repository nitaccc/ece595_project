# Construct Merkle Tree
#       since it requires 2^n leaf nodes and we only have 21 students
#       the minimum nodes will be 32
#       construct a list with 32 random hashed value
#       then replace it with real hash
#       if voted, then remove the hash value and construct a new tree

import secrets
import hashlib
from genHashID import gen_voterHash
from class_merkleTree import MerkleTree



def construct_MerkleTree(studentID_hashList):
    mtree = MerkleTree(studentID_hashList)
    return mtree



def verify_hash(mtree, verify_value):
    verify_list, verify_loc = mtree.verify(verify_value)
    verify = hashlib.sha256(verify_value.encode('utf-8')).hexdigest()

    for i in range(len(verify_list)-1, -1, -1):
        if verify_loc[i] == "L":
            verify = verify + verify_list[i]
        else:
            verify = verify_list[i] + verify
        verify = hashlib.sha256(verify.encode('utf-8')).hexdigest()

    if verify == mtree.getRootHash():
        return True
    else:
        return False
    


if __name__ == '__main__':
    studentID_hashList = []
    for i in range(32):
        # studentID = ''.join(secrets.choice(string.digits) for i in range(10))
        # the if-else code is just easier for debug, delete it and use the above code for future
        if i + 1 > 9:
            studentID = '00000000' + str(i+1)
        else:
            studentID = '000000000' + str(i+1)
        
        studentID_hashList.append(gen_voterHash(studentID))

    mtree = construct_MerkleTree(studentID_hashList)

    hash_for_testing = studentID_hashList[29]
    print("Test Hash: ", hash_for_testing)
    if verify_hash(mtree, hash_for_testing):
        print("Passed.")
    else:
        print("Failed.")