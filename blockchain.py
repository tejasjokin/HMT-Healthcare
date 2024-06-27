import time
import copy
from hashlib import sha256

class block:
    def __init__(self, timestamp, data, previousHash=' '):
        self.timestamp = timestamp
        self.data = data
        self.previousHash = previousHash
        self.hash = self.calculateHash()

    def calculateHash(self):
        return sha256((str(self.timestamp) + str(self.data) + str(self.previousHash)).encode()).hexdigest()
        
class blockchain:
    def __init__(self):
        self.chain = [self.createGenesis()]
        self.block_index = {}

    def createGenesis(self):
        return block(time.ctime(), ["genesisBlock"], "00000")

    def mineBlock(self, data, email):
        new_data = []
        if email in self.block_index.keys():
            prev_block = self.chain[self.block_index[email]]
            if prev_block:
                new_data = copy.deepcopy(prev_block.data)
        new_data.append(data)
        node = block(time.ctime(), new_data, self.chain[-1].hash)
        # mining a new block to the blockchain
        self.chain.append(node)
        self.block_index[email] = len(self.chain)-1
    
    def retrieveBlock(self, email):
        if email in self.block_index.keys():
            block_index = self.block_index[email]
            retrievedBlock = self.chain[block_index]
            return retrievedBlock.data

    def printBlockchain(self):
        print("Index dict: ", self.block_index)
        for i in range(len(self.chain)):
            print("")
            print("-----------Block " + str(i) + "----------")
            print("timestamp = " + self.chain[i].timestamp)
            print("--------------------------------------")
            print("-----data-----")
            for j in range(len(self.chain[i].data)):
                print(f"\t Record {str(j+1)}")
                print(f"\t{self.chain[i].data[j]}")
                print("")
            print("--------------------------------------")
            print("previousHash : " + self.chain[i].previousHash)
            print("--------------------------------------")
            print("hash = " + self.chain[i].hash)
            print("--------------------------------------")
            print("\t|\n\t|\n\tV")
        print("End")