# Instruction
1. Run **simuDRE.py** to activate the DRE machine
2. Run **simuVoter.py** to vote
   - Type in student ID to generate secret key file
   - Type in ballot and decision
   - Type E to finish each session

## genHashID.py
 #### gen_voterHash(ID, genFile = True)
 - ID: student's 10-digit ID
 - genFile: generate a file contains student ID and its secret key if True
 - It is used to generate a secret key for each voter
 - It generates a file contains student ID and the secret key
 - Returns the hash value

## merkleTree.py
 #### construct_MerkleTree(studentID_hashList)
 - studentID_hashList: a list of hashed value
 - Returns a merkle tree contructing from studentID_hashList
 #### verify_hash(mtree, verify_value)
 - mtree: merkle tree
 - verify_value: hashed value to be verified
 - It verifies if the voter is legal
 - Returns a bool value

## class_merkleTree.py
It is modified from https://www.geeksforgeeks.org/introduction-to-merkle-tree/
 #### verify(self, hash_value: str) -> Tuple[List[str], List[str]]
 - It is added for verifying the voter
 - Returns a list of required hash values for verifying

## genKey.py
It is used to generate public keys for the DRE machine
 #### key_generation_modify(question_num)
 - question_num: the number of questions
 - It uses El Gamal Encryption Scheme to obtain c, d, h
 - It generates a file contains the public keys
 - Returns <question_num> sets of keys


## zkp.py
It contains functions to use in DRE machine
 #### DRE_receipt(i, c, d, h, gq, q, g1, g2, s1, n1, t, m, s, n)
 - A voting session
 - Return a receipt
 #### genProof_s1(n1, g1, s1, q)
 - A non-interactive proof of knowledge of (a secret) s such that (for publicly-known $g_1$ and s): n = $g_1$ ^ s
 - A non-interactive proof of knowledge of (a secret) $s_1$ such that (for publicly-known $g_1$ and $n_1$): $n_1$ = $g_1$ ^ $s_1$
 #### genProof_Ei(ri, g1, g2, c, d, h, Ui, Vi, Ei, Wi, q)
 - A proof of well-formedness of $E_i$ with respect to $g_1, g_2, c, d, h, U_i, V_i, W_i$
 - Equivalent to a non-interactive proof of knowledge of (a secret) $r_i$


## verify.py
 #### multiplicativeInverse(aa, bb)
 - Find the modular multiplicative inverse of bb of Z_aa
 #### verifySingleProof(v1, tu1, g1, u, c, q)
 - Verify the non-interactive proof of knowledge of (a secret) $s_1$ such that (for publicly-known $g_1$ and $n_1$): $n_1$ = $g_1$ ^ $s_1$
 - Note: c is the hash value
 #### verifyPWF(filename)
 - Verify the proof of well-formedness of $E_i$ with respect to $g_1, g_2, c, d, h, U_i, V_i, W_i$
 #### auditVerify(filename, n1)
 - Verify audit ballot

## util.py
 #### removeList(s)
 - Return a list from the string s
 #### readPublicKey()
 - Read the public key file and return the public keys
 #### printReceipt(receipt)
 - Generate a receipt file
 #### readReceipt(filename)
 - Read the receipt file and return the receipt
 #### mergeReceipt(r1, r2)
 - Merge two receipts r1 and r2
