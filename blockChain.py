import hashlib
import time
from verify import verifyPWF, verifySingleProof, auditVerify

class Block:
    def __init__(self, index, previous_hash, receipt, filename, timestamp=None):
        self.index = index
        self.timestamp = timestamp or time.time()
        self.receipt = receipt
        self.file = filename
        self.previous_hash = previous_hash
        self.nonce = 0  # for mining
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.receipt}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    
    def mine_block(self, difficulty):
        # Mines the block by finding a hash with a certain number of leading zeros.
        prefix = '0' * difficulty
        while not self.hash.startswith(prefix):
            self.nonce += 1
            self.hash = self.compute_hash()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.difficulty = 2 
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, "0", "Genesis Block", "no_file")
        self.chain.append(genesis_block)

    def add_block(self, receipt, filename, n1, g1, q, n, s, c):
        # verify all the zero knowledge proofs in a receipt
        # Pwf EI
        if not verifyPWF(filename, receipt):
            print("PWF failed in blockchain.")
            return False
        # Pk s1
        for i in range(len(c)):
            tmp = str(g1[i]) + str(n1[i]) + str(receipt["Pk_s1"][i][0])
            hash_c = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
            hash_c = int(hash_c, 16)
            if not verifySingleProof(receipt["Pk_s1"][i][1], receipt["Pk_s1"][i][0], g1[i], n1[i], hash_c, q[i]):
                print("Pks1 failed in blockchain.")
                return False

        if receipt["status"] != "confirm":
            # verify ri and vi for audited ballot
            if not auditVerify(filename, n1, receipt):
                print("Audit verification failed in blockchain.")
                return False
        else: 
            # verify Pks for confirmed ballot
            for i in range(len(c)):
                tmp = str(g1[i]) + str(n[i]) + str(receipt["Pk_s"][i][0])
                hash_c = hashlib.sha256(tmp.encode("utf-8")).hexdigest()
                hash_c = int(hash_c, 16)
                if not verifySingleProof(receipt["Pk_s"][i][1], receipt["Pk_s"][i][0], g1[i], n[i], hash_c, q[i]):
                    print("Pks failed in blockchain.")
                    return False

        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), previous_block.hash, receipt, filename)
        
        # Mine the block
        new_block.mine_block(self.difficulty)
        
        # Add the mined block to the chain
        self.chain.append(new_block)
        return True

    def is_chain_valid(self):
        # Validates the blockchain to ensure integrity.
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Check hash integrity
            if current_block.hash != current_block.compute_hash():
                return False

            # Check the hash chain
            if current_block.previous_hash != previous_block.hash:
                return False

        return True
    

if __name__ == '__main__':
    # receipt = readReceipt("Receipt1.txt")
    # print(receipt)
    
    blockchain = Blockchain()
    #blockchain.add_block(receipt, s1, n1, g1, q, n, s)
    #print(f"Blockchain is valid: {blockchain.is_chain_valid()}")

# This code was modified from the blockchain how-to on Geeks for Geeks: https://www.geeksforgeeks.org/create-simple-blockchain-using-python/