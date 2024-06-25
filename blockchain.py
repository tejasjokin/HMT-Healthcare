import time
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

    def createGenesis(self):
        return block(time.ctime(), "genesisBlock", "00000")

    def mineBlock(self, data):
        node = block(time.ctime(), data, self.chain[-1].hash)
        # mining a new block to the blockchain
        self.chain.append(node)

    def printBlockchain(self):
        BCN_data = []
        for i in range(len(self.chain)):
            BCN_data.append("")
            BCN_data.append("-----Block " + str(i) + "---------")
            BCN_data.append("timestamp = " + self.chain[i].timestamp)
            BCN_data.append("data = ")
            BCN_data.append(self.chain[i].data)
            BCN_data.append("previousHash = " + self.chain[i].previousHash)
            BCN_data.append("hash = " + self.chain[i].hash)
        print("BCN DATA: ",BCN_data)