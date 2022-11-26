import hashlib
import base64
import datetime
import json
import os
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA


class Person:
    def __init__(self, file):
        self.key, self.money, self.signatures = self.import_private_from_file(file)
        self.pubkey = self.key.publickey().export_key(pkcs=8)
        self.address = self.get_address(self.pubkey)
        self.update_info_file(file)

    # Payments
    def resume(self):
        return f"{self.address.decode()} owns {self.money} $G10"

    def add_money(self, value):
        self.money = self.money + value

    def check_balance(self, value):
        return self.money + value >= 0

    def new_payment(self, blockchain, receiver, money):
        value = {
            'sender': self.address.decode(),
            'recipient': receiver.address.decode(),
            'amount': money
        }
        if self.check_balance(-1 * money) and money >= 0:
            self.add_money(-1 * money)
            receiver.add_money(money)
            return blockchain.create_transaction(value)
        else:
            return False

    def update_info_file(self, file):
        info = {'address': self.address.decode(), 'public': self.pubkey.decode(), 'balance': self.money, 'signatures': self.signatures}
        with open(f"{file}.json", "w+") as write_file:
            if json.dumps(info) != write_file.read():
                json.dump(info, write_file, indent=4)

    def new_signature(self, msg, signature, signer):
        sign = {'Message': msg, 'Signature': signature, 'Signer': signer}
        if sign not in self.signatures:
            self.signatures.append(sign)

    @staticmethod
    def get_address(public_key):
        sha256_1 = hashlib.sha256(public_key)

        ripemd160 = hashlib.new("ripemd160")
        ripemd160.update(sha256_1.digest())

        hashed_public_key = bytes.fromhex("00") + ripemd160.digest()
        checksum_full = hashlib.sha256(hashlib.sha256(hashed_public_key).digest()).digest()
        checksum = checksum_full[:4]
        bin_addr = hashed_public_key + checksum

        result_address = base64.b64encode(bin_addr)
        return result_address

    # Files
    def export_private_key(self, file):
        private_key = self.key.export_key(pkcs=8)
        file_out = open(f"{file}.pem", "wb")
        file_out.write(private_key)
        file_out.close()

    def import_private_from_file(self, file):
        money = 0
        signatures = []
        if not(os.path.exists(f"./{file}.pem")):
            key = RSA.generate(3072)
            self.key = key
            self.export_private_key(file)
        else:
            with open(f"{file}.pem", mode='rb') as privatefile:
                privkey = privatefile.read()
            if os.path.exists(f"{file}.json"):
                with open(f"{file}.json", "r") as rf:
                    line = rf.read()
                    if len(line) > 0:
                        data = json.loads(line)
                        money = data['balance']
                        signatures = data['signatures']
            key = RSA.import_key(privkey)
        return key, money, signatures


class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.miner_transactions = []
        self.block_size = 2
        if not(os.path.exists(f"./data_file.json")):
            self.genesis_block = self.new_block(0, "30/09 G10 CH41N released.")
            print(self.genesis_block['previous_hash'], "\n")
            self.chain.append(self.genesis_block)
            self.export_chain_to_file()
        else:
            self.chain_import(self.import_chain_from_file())
        self.miner_queue = []

    def chain_import(self, chain):
        self.chain = chain
        return True

    # Blocks
    def new_block(self, proof, previous_hash):
        current_transactions = self.current_transactions[0:self.block_size]
        if len(self.chain) > 0:
            current_transactions.append(self.miner_transactions.pop(0))

        block = {
            'index': len(self.chain),
            'timestamp': str(datetime.datetime.now()),
            'transactions': current_transactions,
            'proof': proof,
            'previous_hash': previous_hash
        }
        return block

    def create_block(self, proof, previous_hash):
        nblock = self.new_block(proof, previous_hash)
        self.current_transactions = self.current_transactions[self.block_size:]
        self.chain.append(nblock)
        return nblock

    @property
    def last_block(self):
        return self.chain[-1]

    # Transactions
    def new_transaction(self, sender, recipient, amount):
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })
        return self.last_block['index'] + 1 + int((len(self.current_transactions)-1) / self.block_size)

    def create_transaction(self, values):
        if values:
            index = self.new_transaction(values['sender'], values['recipient'], values['amount'])
            result = self.mine()

            response = {'message': f'Transaction will be added to the Block {index}.'}
        else:
            result = ""
            response = {'message': f'Transaction failed due to lack of funds.'}
        return response['message'] + result

    def new_payout(self, sender, recipient, amount):
        self.miner_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })
        return ""

    # Signatures
    @staticmethod
    def sign_message(k, msg):
        hashb = SHA512.new(msg)
        signature = pkcs1_15.new(k).sign(hashb)
        return signature

    @staticmethod
    def verify_message(k, msg, signature):
        hashb = SHA512.new(msg)
        try:
            pkcs1_15.new(k).verify(hashb, signature)
            result = "Signature is valid."
        except ValueError:
            result = "Signature is invalid."
        return result

    # Files
    @staticmethod
    def import_chain_from_file():
        with open("data_file.json", "r") as read_file:
            line = read_file.read()
            if len(line) > 0:
                data = json.loads(line)
            else:
                data = ""
        return data

    def export_chain_to_file(self):
        if self.chain_valid(self.chain):
            with open("data_file.json", "w") as write_file:
                json.dump(self.chain, write_file, indent=4)

    # Methods
    @staticmethod
    def proof_of_work(previous_proof):
        new_proof = 1
        check_proof = False

        while check_proof is False:
            hash_operation = hashlib.sha512(
                str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:5] == '00000':
                check_proof = True
            else:
                new_proof += 1

        return new_proof

    @staticmethod
    def hash(block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha512(encoded_block).hexdigest()

    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1

        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                print(block['previous_hash'], self.hash(previous_block))
                return False

            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha512(
                str(proof**2 - previous_proof**2).encode()).hexdigest()

            if hash_operation[:5] != '00000':
                return False
            previous_block = block
            block_index += 1

        return True

    def valid(self):
        validate = self.chain_valid(self.chain)

        if validate:
            response = {'message': 'The Blockchain is valid.'}
        else:
            response = {'message': 'The Blockchain is not valid.'}
        return response['message']

    def display_chain(self):
        response = {'chain': self.chain, 'length': len(self.chain)}

        return json.dumps(response, indent=2)

    # Mine Methods
    def add_miner(self, miner):
        self.miner_queue.append(miner)
        result = self.mine()

        return f"Miner {miner.address.decode()} added to Miner Queue." + result

    def mine(self):
        if len(self.miner_queue) > 0 and len(self.current_transactions) >= self.block_size:
            miner = self.miner_queue.pop(0)
        else:
            return "\nNo miner available." if len(self.miner_queue) == 0 else ""

        reward = 10

        self.new_payout(
            sender=0,
            recipient=miner.address.decode(),
            amount=reward,
        )
        miner.add_money(reward)

        previous_block = self.last_block
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)

        previous_hash = self.hash(previous_block)
        nblock = self.create_block(proof, previous_hash)

        response = {
            'message': "Forged new block.",
            'index': nblock['index'],
            'transactions': nblock['transactions'],
            'proof': nblock['proof'],
            'previous_hash': nblock['previous_hash'],
        }

        return '\n' + response['message'] + str(response['index'])
