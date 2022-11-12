from hashTool import merkel_tree
import random
import json
import math

def leaves(tree):
    if(('data' in tree.keys())):
        return leaves(tree['data'][0]) + leaves(tree['data'][1])
    else:
        return 1

def helper(index, tree):
    max = leaves(tree)
    dim = math.ceil(math.log(max, 2))
    list = []
    for i in range(dim):
        tmp = index & (2**(dim-i-1))
        list.append(tmp>>(dim-i-1))
    output = []
    dot = tree
    level = 0
    while('data' in dot.keys()):
        output.append(dot["data"][list[1-level]]["hash"])
        dot = dot["data"][list[level]]
        level+=1
    return output

def test():
    data = []
    trans = 27
    for i in range(trans):
        data.append({'hash':(random.randbytes(5).hex())})
    p = merkel_tree(data)
    print(json.dumps(p, indent=4))
    print(helper(12, p))

if __name__ == '__main__':
    test()
