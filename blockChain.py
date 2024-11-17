import hashlib
import time
from zkp import genProof_Ei, genProof_s1
from verify import readReceipt

class Block:
    def __init__(self, index, previous_hash, receipt, timestamp=None):
        self.index = index
        self.timestamp = timestamp or time.time()
        self.receipt = receipt
        self.previous_hash = previous_hash
        self.nonce = 0  # for mining
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.receipts}{self.previous_hash}{self.nonce}"
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
        genesis_block = Block(0, "0", "Genesis Block")
        self.chain.append(genesis_block)

    def add_block(self, receipt, s1, n1, g1, q, n, s):
        # verify all the zero knowledge proofs in a receipt
        # Pwf EI
        if (receipt["Pwf"]["E"] != genProof_Ei(receipt["Ei"])):
            return
        # Pk s1
        if (receipt["Pk_s1"] != genProof_s1(n1, g1, s1, q)):
            return

        if "ballot" in receipt:
            # verify ri and vi for audited ballot
            # TODO
            pass
        else: 
            # verify Pks for confirmed ballot
            if (receipt["Pk_s"] != genProof_s1(n, g1, s, q)):
                return

        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), previous_block.hash, receipt)
        
        # Mine the block
        new_block.mine_block(self.difficulty)
        
        # Add the mined block to the chain
        self.chain.append(new_block)

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
    receipt = readReceipt("Receipt1.txt")
    print(receipt)
    
    blockchain = Blockchain()
    #blockchain.add_block(receipt, s1, n1, g1, q, n, s)
    #print(f"Blockchain is valid: {blockchain.is_chain_valid()}")