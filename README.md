## genHashID.py
It is ued to register voters. Once everyone is registered, it generates a file contains all hashed value of every voter.
 #### gen_voterHash(ID, genFile = True)
 - ID = student 10-digit ID
 - genFile: generate a file contains student ID and the secret key if True
 - It is used to generate a secret key for each voter.
 - It generates a file contains student ID and the secret key.
 - Returns the hash value

## merkleTree.py
 #### construct_MerkleTree(studentID_hashList)
 - construct the merkle tree
 #### verify_hash(mtree, verify_value)
 - verify if the voter is legal

## class_merkleTree.py
It is modified from https://www.geeksforgeeks.org/introduction-to-merkle-tree/
 #### verify(self, hash_value: str) -> Tuple[List[str], List[str]]
 - It is added for verifying the voter.
 - It returns a list of required hash values for verifying. 

## genKey.py
It is used to generate public keys for the DRE machine. 

## voting.py
1. It creates a Merkle Tree from the file **hashList.txt** generated from **genHashID.py**.
2. Initialize the DRE machine.
3. Start voting. User may enter their student ID and secret key.
4. If failed, then go back to Step 3. If success, then enter decision.
5. Confirm your decision.
6. If audit the ballot, receive a receipt and go back to Step 3 to vote again.
7. If confirm the ballot, receive a receipt.
8. Voting continue from Step 3.
9. After collecting all ballots, then tally. 

## zkp.py
It contains functions to use in DRE machine.
 #### DRE_receipt(i, c, d, h, gq, q, g1, g2, s1, n1, t, m, s, n)
 - Generate a receipt. 
 #### genProof_s1(n1, g1, s1, q)
 - a non-interactive proof of knowledge of (a secret) s such that (for publicly-known $g_1$ and s): n = $g_1$ ^ s
 - a non-interactive proof of knowledge of (a secret) $s_1$ such that (for publicly-known $g_1$ and $s_1$): $n_1$ = $g_1$ ^ $s_1$
 #### genProof_Ei(ri, g1, g2, c, d, h, Ui, Vi, Ei, Wi, q)
 - a proof of well-formedness of $E_i$ with respect to $g_1, g_2, c, d, h, U_i, V_i, W_i$
 #### printReceipt(receipt)
 - Generate a receipt file for verifying. 
