#!/usr/bin/python
# -*- coding:utf-8 -*-
import hashlib as hasher
from time import *
import json
from flask import Flask, jsonify, render_template, request
from argparse import ArgumentParser
import requests
import hashlib
import requests
import base64
import ecdsa
import random
import threading
import base64
import ecdsa

from merkletree import concat_and_hash_list

blockchain = []
#nodes = [{"ip":"localhost","port":8080}]
nodes = []
deals = []


# 验证区块链
def validate(blocks):
    bool = True
    # 上一个区块
    previous_index = 0
    previous_hash = 0
    for block in blocks:
        index = block["index"]
        hash = block["hash"]
        if (index > 0):
            # 如果index是衔接的
            if (previous_index == index-1):
                pass
            else:
                bool = False
            # 如果上一个区块的当前hash和当前区块的上一个hash值能对上
            if (previous_hash == block["previous_hash"]):
                pass
            else:
                bool = False

            if bool:
                # 把当前的变为上一个
                previous_index = index
                previous_hash = hash
        if (index == 0):
            previous_index = index
            previous_hash = hash
            pass
    return bool

# 添加节点


def add_node(node):
    nodes.append(node)


# 返回自身区块链高度


def get_height():
    last_block = blockchain[len(blockchain)-1]
    last_block_index = last_block["index"]
    return last_block_index


def hash(index, data, timestamp, previous_hash):
    sha = hasher.sha256()
    sha.update("{0}{1}{2}{3}".format(
        index, data, timestamp, previous_hash).encode("utf8"))
    return sha.hexdigest()

#产生区块
def make_a_block(index, timestamp, data, hash1, previous_hash):
    block = {}
    block["index"] = index
    block["timestamp"] = timestamp
    block["data"] = data
    block['merkle'] = hash1
    block["previous_hash"] = previous_hash
    block["hash"] = hash(index, hash1, timestamp, previous_hash)
    return block


# def add_a_block(data):

#     last_block = blockchain[len(blockchain)-1]

#     index = last_block["index"]+1
#     timestamp = int(round(time() * 1000))
#     previous_hash = last_block["hash"]

#     block = make_a_block(index, timestamp, data, previous_hash)
#     blockchain.append(block)
#     return index

#产生创世区块
def make_a_genesis_block():
    index = 0
    timestamp = int(round(time() * 1000))
    data = "Genesis Block"
    previous_hash = 0
    hash = 0
    blockchain.append(make_a_block(index, timestamp, data, hash, previous_hash))

#确认签名
def validate_signature(public_key, signature, message):
    public_key = (base64.b64decode(public_key)).hex()
    signature = base64.b64decode(signature)
    try:
        vk = ecdsa.VerifyingKey.from_string(
            bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
        return vk.verify(signature, message.encode())
    except:
        return False


app = Flask(__name__)


@app.route('/', methods=['POST', 'GET'])
def home():
    if request.method == 'POST':
        address = request.form.get('address')

        out_logs = []
        in_logs = []

        for i in range(1, len(blockchain)):
            block = blockchain[i]
            data = block["data"]
            if address == data["from"]:
                out_logs.append(block)
            if address == data["to"]:
                in_logs.append(block)
        return render_template('index.html', out_logs=out_logs, in_logs=in_logs)
    if request.method == 'GET':
        return render_template('index.html')

# 查找


@app.route('/find', methods=['POST', 'GET'])
def find():
    if request.method == 'POST':
        address = request.form.get('address')

        out_logs = []
        in_logs = []

        for i in range(1, len(blockchain)):
            block = blockchain[i]
            data = block["data"]
            if address == data["from"]:
                out_logs.append(block)
            if address == data["to"]:
                in_logs.append(block)
        return jsonify({"out": out_logs, "in": in_logs})
    if request.method == 'GET':
        return render_template('find.html')
# 信息上链


@app.route('/post', methods=['POST'])
def post():
    if request.method == 'POST':
        # data = request.form.get('hash')
        # block_index = add_a_block(data)
        # return jsonify({"index": block_index, "hash": data})
        from_address=request.form.get('from_address')
        to_address=request.form.get('to_address')
        memo=request.form.get('memo')
        signature=request.form.get('signature')
        message=request.form.get('message')
        if validate_signature(from_address, signature, message):
            msg = {
                "from": from_address,
                "to": to_address,
                "memo": memo
            }
            deals.append(msg)
            return jsonify(deals)
        else:
            return jsonify("error")


@app.route('/blocks/last', methods=['GET'])
def get_last_block():
    last_block = blockchain[len(blockchain)-1]
    return jsonify(last_block)


@app.route('/blocks/<int:index>', methods=['GET'])
def get_block(index):
    if(len(blockchain) >= index):
        block = blockchain[index]
        return jsonify(block)
    else:
        return jsonify({"error": "noindex"})


@app.route('/blocks/<int:from_index>/<int:to_index>', methods=['GET'])
def get_block_from_to(from_index, to_index):
    blocks = []
    if(len(blockchain) > from_index and len(blockchain) > to_index and to_index >= from_index):
        for i in range(from_index, to_index+1):
            block = blockchain[i]
            blocks.append(block)
        return jsonify(blocks)
    else:
        return jsonify({"error": "noindex"})

# 验证


@app.route('/validate', methods=['GET'])
def blocks_validate():

    return jsonify(validate(blockchain))


@app.route('/blocks/all', methods=['GET'])
def get_all_block():
    return jsonify(blockchain)

# 查看区块链高度


@app.route('/blocks/height', methods=['GET'])
def get_block_height():
    last_block = blockchain[len(blockchain)-1]
    return jsonify(last_block["index"])

# 查看节点


@app.route('/nodes', methods=['GET'])
def get_get_nodes():
    return jsonify(nodes)

# @app.route('/nodes/find',methods=['GET'])
# def find_find_nodes():
#     return nodes

# 添加节点


@app.route('/nodes/add/<string:ip>/<int:port>', methods=['GET'])
def add_nodes(ip, port):
    node = {"ip": ip, "port": port}
    # 确保不重复添加
    if node not in nodes:
        nodes.append(node)
    return jsonify(nodes)

# 同步区块


@app.route('/blocks/sync', methods=['GET'])
def blocks_sync():
    json = []
    for node in nodes:
        ip = node["ip"]
        port = node["port"]
        url_height = "http://{0}:{1}/blocks/height".format(ip, port)
        url_all = "http://{0}:{1}/blocks/all".format(ip, port)
        # 尝试去同步
        try:
            # 尝试获得对方高度
            r_height = requests.get(url_height)
            height = int(r_height.json())
            self_index = get_height()

            # 如果对方的比自己的大
            if height > self_index:
                r_blocks_all = requests.get(url_all)
                blocks = r_blocks_all.json()
                # 对对方的区块进行验证
                is_validate = validate(blocks)
                # 把对方的blockchain赋值自己的blokchain
                if (is_validate):
                    blockchain.clear()
                    for block in blocks:
                        blockchain.append(block)
                    return jsonify("synced")
                else:
                    return jsonify("not validate")
            else:
                # 不同步
                return jsonify("no synced")

        except:
            return jsonify("error")
    return jsonify("no nodes")


#产生交易对其签名并向外广播的threading继承类


class deal_generation(threading.Thread):
    def run(self):
        while(True):
            public_key,private_key = generate_ECDSA_keys()
            signature, message = sign_ECDSA_msg(private_key)
            d = {"from_address": public_key, "to_address": public_key,"memo":"test","signature":signature,"message":message}
            for node in nodes:
                ip = node["ip"]
                port = node["port"]
                url = "http://{0}:{1}/post".format(ip,port)
                r = requests.post(url, data=d)
            sleep(4)

# 产生特定交易与随机公私钥
def generate_ECDSA_keys():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) #this is your sign (private key)
    private_key = sk.to_string().hex() #convert your private key to hex
    vk = sk.get_verifying_key() #this is your verification key (public key)
    public_key = vk.to_string().hex()
    public_key = base64.b64encode(bytes.fromhex(public_key))
    return public_key.decode(),private_key

def sign_ECDSA_msg(private_key):
    message = str(round(time()))
    bmessage = message.encode()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    signature = base64.b64encode(sk.sign(bmessage))
    return signature, message


# 建立产生新区块的threading继承类


class block_generate(threading.Thread):
    def run(self):
        while True:
            last_block = blockchain[len(blockchain)-1]
            index = last_block["index"]+1
            previous_hash = last_block["hash"]
            data = []
            if len(deals) >= 4*index:
                for i in range(4):
                #public_key,private_key = generate_ECDSA_keys()
                #signature,message = sign_ECDSA_msg(private_key)
                    data.append(str(deals[4*index-4+i]))
                hash = concat_and_hash_list(data)
                timestamp = int(round(time() * 1000))
                block = make_a_block(index, timestamp, data, hash, previous_hash)
                last_block = blockchain[len(blockchain)-1]
                if index == last_block["index"]+1 and previous_hash == last_block["hash"]:
                    blockchain.append(block)
            #print("one added")
            sleep(10)


# 与其他节点进行同步的threading继承类


class synchronization(threading.Thread):
    def run(self):
        while True:
            for node in nodes:
                ip = node["ip"]
                port = node["port"]
                url_height = "http://{0}:{1}/blocks/height".format(ip, port)
                url_all = "http://{0}:{1}/blocks/all".format(ip, port)
                url_nodes = "http://{0}:{1}/nodes".format(ip, port)
                # 获得未知节点
                oth_nodes = requests.get(url_nodes)
                other_nodes = oth_nodes.json()
                for other_node in other_nodes:
                    if other_node not in nodes:
                        nodes.append(other_node)
                # 尝试去同步
                try:
                    # 尝试获得对方高度
                    r_height = requests.get(url_height)
                    height = int(r_height.json())
                    self_index = get_height()

                    # 如果对方的比自己的大
                    if height > self_index:
                        r_blocks_all = requests.get(url_all)
                        blocks = r_blocks_all.json()
                        # 对对方的区块进行验证
                        is_validate = validate(blocks)
                        # 把对方的blockchain赋值自己的blokchain
                        if (is_validate):
                            blockchain.clear()
                            for block in blocks:
                                blockchain.append(block)
                            print("synced")
                        else:
                            print("not validate")
                    else:
                        # 不同步
                        print("no synced")

                except:
                    print("error")
            #print("no nodes")
            sleep(1)


if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080,
                        type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    nodes.append({"ip":"localhost","port":port})
    app.run(debug=True, host='0.0.0.0', port=port)

    make_a_genesis_block()
    thread1 = deal_generation()
    thread2 = block_generate()
    thread3 = synchronization()
    thread1.start()
    thread2.start()
    thread3.start()

    # url_h = "http://localhost:8080/nodes/add/localhost/{0}".format(port)
    # x = requests.get(url_h)
