import random
from random import randint
import math
from random import randbytes
import string
import hashlib as hasher
import base64
import time
import ecdsa
from hashTool import merkel_tree,from_merkel_to_list
from charm.toolbox.eccurve import prime192v1
import merkletools
import copy
from hashlib import sha256


def get_binlist(v):
    tmp = list(bin(v))[2:]
    tmp2=[]
    for _ in tmp:
        tmp2.append(int(_))
    return tmp2

def inverse01(v01):
    if v01 == 0:
        return 1
    else:
        return 0

def get_proof_list(binlist):
    proof_list = []
    for _ in range(len(binlist)):
        if _ == 0:
            proof_list.append([inverse01(binlist[_])])
        else:
            tmp = copy.copy(binlist[:_])
            tmp.append(inverse01(binlist[_]))
            proof_list.append(tmp)
    return proof_list

def get_hash_from_path(p,path):
        tmp = copy.deepcopy(p)
        for _ in path:
            tmp = tmp['data'][_]
        return tmp['hash']

def construct_sample(k):
    data = []
    trans = 2**k
    for i in range(trans):
        data.append({'hash':(random.randbytes(5).hex())})

    p = merkel_tree(data)

    return p

def verify(p, node_idx, show_the_process=False):
    target_bin_list = get_binlist(node_idx)
    target = get_hash_from_path(p,target_bin_list)

    proof_list = get_proof_list(target_bin_list)

    proof_rt = []
    for path in proof_list:
        tmp = copy.deepcopy(p)
        for _ in path:
            tmp = tmp['data'][_]
        proof_rt.append(tmp['hash'])

    new_hash = target

    if (show_the_process==True):
        print('在此我们展示默克尔证明的过程，我们从以下节点出发')
        print(f'target:{target}')
        print('默克尔路径上经过的节点有：')
        for i in range(1,len(proof_list)+1):
            print(f'{i}th: {proof_rt[-i]}')
        print()
        print('具体过程')
        for i in range(1,len(proof_list)+1):
            if target_bin_list[-i] == 1:
                print(f'{i}th')
                print(f'{new_hash}<==>{proof_rt[-i]}')
                new_hash = sha256(bytes.fromhex(proof_rt[-i]) + bytes.fromhex(new_hash)).hexdigest()
                print(f'get {new_hash}')
            else:
                print(f'{i}th')
                print(f'{new_hash}<==>{proof_rt[-i]}')
                new_hash = sha256(bytes.fromhex(new_hash) + bytes.fromhex(proof_rt[-i])).hexdigest()
                print(f'get {new_hash}')
    else:
        for i in range(1,len(proof_list)+1):
            if target_bin_list[-i] == 1:
                new_hash = sha256(bytes.fromhex(proof_rt[-i]) + bytes.fromhex(new_hash)).hexdigest()
            else:
                new_hash = sha256(bytes.fromhex(new_hash) + bytes.fromhex(proof_rt[-i])).hexdigest()
        
    return new_hash





def generate_ECDSA_keys():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST192p) #this is your sign (private key)
    private_key = sk.to_string().hex() #convert your private key to hex
    vk = sk.get_verifying_key() #this is your verification key (public key)
    public_key = vk.to_string().hex()
    public_key = base64.b64encode(bytes.fromhex(public_key))
    return public_key.decode(),private_key

def sign(private_key, data):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.NIST192p)
    return base64.b64encode(sk.sign(data)).decode()

def validate_signature(public_key, signature, message):
    public_key = (base64.b64decode(public_key)).hex()
    signature = base64.b64decode(signature)
    try:
        vk = ecdsa.VerifyingKey.from_string(
            bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
        return vk.verify(signature, message.encode())
    except:
        return False

    

def hash_data(data, hash_function = 'sha256'):
    "hash function"
    hash_function = getattr(hasher, hash_function)
    data = data.encode('utf-8')
    return hash_function(data).hexdigest()

def concat_and_hash_list(lst, hash_function = 'sha256'):
    lst1 = []
    for i in lst:
        lst1.append(hash_data(i))
    # print(lst1)

    assert len(lst1)>2, "no tracnsactions to be hashed"
    n = 0 #merkle树高度
    while len(lst1) >1:
        n += 1
        if len(lst1)%2 == 0:
            v = []
            while len(lst1) >1 :
                a = lst1.pop(0)
                b = lst1.pop(0)
                v.append(hash_data(a+b, hash_function))
            lst1 = v
        else:
            v = []
            l = lst1.pop(-1)
            while len(lst1) >1 :
                a = lst1.pop(0)
                b = lst1.pop(0)
                v.append(hash_data(a+b, hash_function))
            v.append(l)
            lst1 = v
    return lst1[0]


def hash(index, data,  previous_hash):
    sha = hasher.sha256()
    sha.update("{0}{1}{2}".format(
        index, data,  previous_hash).encode("utf8"))
    return sha.hexdigest()


def make_a_block(index,data, hash1, previous_hash):
    block = {}
    block["index"] = index
    block["data"] = data
    block['merkle'] = hash1
    block["previous_hash"] = previous_hash
    block["hash"] = hash(index, hash1,  previous_hash)
    return block

def make_a_genesis_block():
    index = 0
    data = "Genesis Block"
    previous_hash = 0
    hash = 0
    blockchain.append(make_a_block(index, data, hash, previous_hash))

def add_a_block(data,hash1):

    last_block = blockchain[len(blockchain)-1]
    index = last_block["index"]+1
    previous_hash = last_block["hash"]

    block = make_a_block(index, data, hash1, previous_hash)
    blockchain.append(block)
    return index

def time4verification(n,k,repeat=100):

    make_a_genesis_block()

    data=[]
    tree_list=[]
    alphabet='abcdefghijklmnopqrstuvw'
    for i in range(n):
        data.append(random.choice(alphabet))

    for i in range(0,n):
        tree_list.append(construct_sample(k))
        add_a_block(data[i],tree_list[i]['hash'])

    blockidx_list = [random.randint(1, n-1) for _ in range(repeat)]
    nodeidx_list = [random.randint(2**(k-1), 2**k-1) for _ in range(repeat)]
    starttime = time.time()
    for cnt in range(repeat):
        for _ in blockchain:
            if _['index'] == blockidx_list[cnt]:
                merkleRoot = _['hash']
                if merkleRoot == blockchain[blockidx_list[cnt]+1]['merkle']:
                    assert verify(_, nodeidx_list[cnt], show_the_process=False)
                    na=bin(randint(1,100)).encode()
                    public_key,private_key=generate_ECDSA_keys()
                    signature=sign(private_key, na)
                    validate_signature(public_key, signature, na)

    endtime = time.time()

    
    return f"{(endtime-starttime)/repeat} "


if __name__ == '__main__':
# 默克尔证明过程展示
    # p = construct_sample(k=5)
    # node_idx = 30

    # reconstruct_hash = verify(p,node_idx,show_the_process=True)

    # print()
    # print(f'reconstruct_hash: {reconstruct_hash}')
    # print(f'original hash: ', p['hash'])

# 时间计算
    blockchain = []

    time_log = []
    with open("time_log",'w') as file:
        for n in [10,100,1000]:
            for k in [2,4,6,8,10]:
                time_log.append(f'n:{n}  k:{k}  time:{time4verification(n=n,k=k)}')
                file.write(f'{n}  {k}  {time4verification(n=n,k=k)}\n')
    for _ in time_log:
        print("------------")
        print(_)