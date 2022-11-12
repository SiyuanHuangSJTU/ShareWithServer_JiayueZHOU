from hashlib import sha256
import ecdsa
import base64
from charm.toolbox.eccurve import prime192v1
from charm.toolbox.ecgroup import ECGroup, G, ZR

group = ECGroup(prime192v1)


# 创建 merkel 树
# data: ["{"from":"xx", "to": "xx", "message":"xx", "sig": "xx", "hash": "xxx}, ...]
def merkel_tree(data):
    while len(data) != 1:
        tmp = []
        for i in range(0, len(data), 2):
            if i + 1 >= len(data):
                tmp.append(data[i])
            else:
                new_hash = sha256(bytes.fromhex(data[i]["hash"]) + bytes.fromhex(data[i + 1]["hash"])).hexdigest()
                tmp.append({"hash": new_hash, "data": [data[i], data[i + 1]]})
        data = tmp
    return data[0]


# 将 merkel 树转换成 list
# 迭代自身
def from_merkel_to_list(merkel, result_list):
    if "data" in merkel:
        for i in merkel['data']:
            from_merkel_to_list(i, result_list)
    else:
        result_list.append(merkel)


# 密钥生成
# 生成并返回一对公私钥
def generate_ECDSA_keys():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)  # this is your sign (private key)
    private_key = sk.to_string().hex()  # convert your private key to hex
    vk = sk.get_verifying_key()  # this is your verification key (public key)
    public_key = vk.to_string().hex()
    return public_key, private_key


# 签名
# private_key: hex string 格式的私钥
# data: bytes 类型的消息数据
# 返回 base64 编码的签名
def sign(private_key, data):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    return base64.b64encode(sk.sign(data)).decode()


# 验证签名
# public_key: hex string 格式的公钥
# signature: base64 编码的签名
# message: bytes 类型的消息数据
# 返回 True（验证成功）或 False（验证失败）
def validate_signature(public_key, signature, message):
    signature = base64.b64decode(signature)
    try:
        vk = ecdsa.VerifyingKey.from_string(
            bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
        return vk.verify(signature, message)
    except:
        return False


# 生成 chameleon hash 初始参数
# 返回两个大整数，x 用来修改，y 用来生成
def chameleon_init():
    g = group.random(G)
    x = group.random(ZR)
    y = g ** x
    return g, x, y


# 计算变色龙哈希
# y：
# msg: 待计算的消息
def chameleon_hash(g, y, msg):
    r, s = group.random(ZR), group.random(ZR)
    ch = r - group.hash(y ** group.hash((msg, r)) * (g ** s))
    return r, s, ch


# 变色龙哈希验证过程的计算
def chameleon_verify(g, y, msg, r, s):
    group = ECGroup(prime192v1)
    return r - group.hash(y ** group.hash((msg, r)) * (g ** s))


# 变色龙哈希的修改
def chameleon_adjust(g, x, msg, ch):
    group = ECGroup(prime192v1)
    k = group.random(ZR)
    r = ch + group.hash(g ** k)
    s = k - x * group.hash((msg, r))
    return r, s


# 对变色龙哈希输出值进行序列化，转换成str
# group_element: 变色龙哈希过程中产生的值
# 返回值：序列化之后的字符串
def chameleon_serialize(group_element):
    return group.serialize(group_element).decode()


# 对变色龙哈希输出值进行序列化，转换成str
# string_element: str类型的字符串
# 返回值：反序列化之后的group类型的值
def chameleon_deserialize(string_element):
    return group.deserialize(string_element.encode())