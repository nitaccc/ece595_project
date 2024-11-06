# Python code for implemementing Merkle Tree
from typing import List, Tuple
import hashlib


class Node:
    def __init__(self, left, right, value: str, content, is_copied=False) -> None:
        self.left: Node = left
        self.right: Node = right
        self.value = value
        self.content = content
        self.is_copied = is_copied

    @staticmethod
    def hash(val: str) -> str:
        return hashlib.sha256(val.encode('utf-8')).hexdigest()

    def __str__(self):
        return (str(self.value))

    def copy(self):
        """
        class copy function
        """
        return Node(self.left, self.right, self.value, self.content, True)


class MerkleTree:
    def __init__(self, values: List[str]) -> None:
        self.__buildTree(values)

    def __buildTree(self, values: List[str]) -> None:

        self.leaves: List[Node] = [Node(None, None, Node.hash(e), e)
                              for e in values]
        if len(self.leaves) % 2 == 1:
            # duplicate last elem if odd number of elements
            self.leaves.append(self.leaves[-1].copy())
        self.root: Node = self.__buildTreeRec(self.leaves)

    def __buildTreeRec(self, nodes: List[Node]) -> Node:
        if len(nodes) % 2 == 1:
            # duplicate last elem if odd number of elements
            nodes.append(nodes[-1].copy())
        half: int = len(nodes) // 2

        if len(nodes) == 2:
            return Node(nodes[0], nodes[1], Node.hash(nodes[0].value + nodes[1].value), nodes[0].content+"+"+nodes[1].content)

        left: Node = self.__buildTreeRec(nodes[:half])
        right: Node = self.__buildTreeRec(nodes[half:])
        value: str = Node.hash(left.value + right.value)
        content: str = f'{left.content}+{right.content}'
        return Node(left, right, value, content)

    def printTree(self) -> None:
        self.__printTreeRec(self.root)

    def __printTreeRec(self, node: Node) -> None:
        if node != None:
            if node.left != None:
                print("Left: "+str(node.left))
                print("Right: "+str(node.right))
            else:
                print("Input")

            if node.is_copied:
                print('(Padding)')
            print("Value: "+str(node.value))
            print("Content: "+str(node.content))
            print("")
            self.__printTreeRec(node.left)
            self.__printTreeRec(node.right)

    def getRootHash(self) -> str:
        return self.root.value
    
    # ADDED FUNCTION
    # return(hash_list): retun required hash value for verifying
    # hash_list[0] is root
    def verify(self, hash_value: str) -> Tuple[List[str], List[str]]:
        hash_list = []
        hash_loc = []
        present_node = self.root
        while present_node != None:            
            if present_node.left != None:
                if hash_value in present_node.left.content:
                    hash_list.append(present_node.right.value)
                    hash_loc.append("L")
                    present_node = present_node.left
                else:
                    hash_list.append(present_node.left.value)
                    hash_loc.append("R")
                    present_node = present_node.right
            else:
                break

        return hash_list, hash_loc
    

# This code was contributed by Pranay Arora (TSEC-2023).

# Copy above from https://www.geeksforgeeks.org/introduction-to-merkle-tree/