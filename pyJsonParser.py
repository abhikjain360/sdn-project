"""
    XGBOOST JSON PARSER TO P4 Commands
"""
import json
import sys


class Queue:
    def __init__(self):
        self.queue = list()

    def push(self, val):
        if val not in self.queue:
            self.queue.insert(0, val)
            return True
        return False

    def pop(self):
        if len(self.queue) > 0:
            return self.queue.pop()
        else:
            raise Exception("Queue empty!")

    def isEmpty(self):
        return len(self.queue) == 0


class Node:
    def __init__(self, index):
        self.isRoot = False
        self.isLeaf = False
        self.nodeIndex = index
        self.parent = -1
        self.leftChild = -1
        self.rightChild = -1
        self.splitCondition = 0
        self.defaultLeft = True
        self.splitIndex = 0
        self.childPosition = 0

    def update(self):
        if self.leftChild == -1 and self.rightChild == -1:
            self.isLeaf = True
        elif self.parent > 1024:
            self.isRoot = True


class Tree:
    def __init__(self, index, numNodes):
        self.numNodes = numNodes
        self.treeIndex = index
        self.indexToNode = dict()
        for i in range(numNodes):
            self.indexToNode[i] = Node(i)

    def getRoot(self):
        return self.indexToNode[0]


class Data:
    def __init__(self):
        self.featureToIndex = dict()
        self.indexToFeature = dict()
        self.numTrees = 1


def main():
    with open('model_output.json', 'r') as f:
        data = json.load(f)
    # print(data)
    obj = Data()
    model = data['learner']['gradient_booster']['model']
    for i, element in enumerate(data['learner']['feature_names']):
        obj.featureToIndex[element] = i
        obj.indexToFeature[i] = element
    obj.numTrees = model['gbtree_model_param']['num_trees']
    treesData = model['trees']
    numTrees = int(model['gbtree_model_param']['num_trees'])
    treeDict = dict()
    for i in range(numTrees):
        numNodes = int(treesData[i]['tree_param']['num_nodes'])
        treeDict[i] = Tree(i, numNodes)
        curTreeData = treesData[i]
        for j in range(numNodes):
            curNode = treeDict[i].indexToNode[j]
            curNode.defaultLeft = int(curTreeData['default_left'][j])
            curNode.leftChild = int(curTreeData['left_children'][j])
            curNode.rightChild = int(curTreeData['right_children'][j])
            curNode.parent = int(curTreeData['parents'][j])
            curNode.splitIndex = int(curTreeData['split_indices'][j])
            curNode.splitCondition = float(curTreeData['split_conditions'][j])
            curNode.update()
            # print("- ", curNode.isLeaf, curNode.splitCondition)
    for i in range(numTrees):
        numNodes = treeDict[i].numNodes
        curTree = treeDict[i]
        for j in range(numNodes):
            curNode = curTree.indexToNode[j]
            parent = curNode.parent
            if parent > 1024:
                continue
            parentNode = curTree.indexToNode[parent]
            if parentNode.leftChild == j:
                curNode.childPosition = 1
            elif parentNode.rightChild == j:
                curNode.childPosition = 2

    """
    Generate
    """
    res = []
    for i in range(numTrees):
        Q = Queue()
        curTree = treeDict[i]
        Q.push((0, 0, 1024))
        lvlData = []
        while not Q.isEmpty():
            lvl, cur, prev_split_index = Q.pop()
            curNode = curTree.indexToNode[cur]
            # print("? ", curNode.isLeaf, curNode.splitCondition, curNode.splitIndex)
            if curNode.isLeaf:
                lvlData.append(["leaf", lvl, cur, curNode.splitCondition, curNode.splitCondition, prev_split_index,
                                curNode.childPosition])
            else:
                lvlData.append(["node", lvl, cur, curNode.splitIndex, curNode.splitCondition, prev_split_index,
                                curNode.childPosition])
                if curNode.leftChild != -1:
                    Q.push((lvl + 1, curNode.leftChild, curNode.splitIndex))
                if curNode.rightChild != -1:
                    Q.push((lvl + 1, curNode.rightChild, curNode.splitIndex))
        res.append(lvlData)
    ans = ""
    for i, tree in enumerate(res):
        curTree = treeDict[i]
        output = ""
        for det in tree:
            if det[0] == "node":
                output += "table_add tree{}_level{} ".format(i, det[1])
                parent = curTree.indexToNode[det[2]].parent
                if parent >= 2147483646:
                    output += "check_feature {} {} {}".format(det[2], 1024, det[6] % 2)
                else:
                    output += "check_feature {} {} {}".format(det[2], parent, det[5] % 2)
                output += " => "
                output += "{} {} {}\n".format(det[2], det[3], int(det[4]))
            else:
                output += "table_add tree{}_level{} ".format(i, det[1])
                if det[4] > 0:
                    parent = curTree.indexToNode[det[2]].parent
                    if parent >= 2147483646:
                        output += "add_value {} {} {}".format(det[2], 1024, det[6] % 2)
                    else:
                        output += "add_value {} {} {}".format(det[2], parent, det[6] % 2)
                    output += " => "
                    output += str(int(det[4] * 1000)) + "\n"
                else:
                    parent = curTree.indexToNode[det[2]].parent
                    if parent >= 2147483646:
                        output += "sub_value {} {} {}".format(det[2], 1024, det[6] % 2)
                    else:
                        output += "sub_value {} {} {}".format(det[2], parent, det[6] % 2)
                    output += " => "
                    output += str(int(-1 * det[4] * 1000)) + "\n"
        ans += output
    print(ans)
    with open("commands.txt", "w") as f:
        f.write(ans)


if __name__ == "__main__":
    main()
