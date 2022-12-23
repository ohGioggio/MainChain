import hashlib
import base64
import datetime
import json
import os
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
import random as rand


class Wallet:
    def __init__(self, file):
        self.file = file
        self.key, self._money, self._stake, self.signatures = self.import_wallet_info(file)
        self.pubkey = self.key.publickey().export_key(pkcs=8, format='DER')
        self.address = self.get_address(self.pubkey)
        self.update_info_file(self.file)

    # Payments
    def resume(self):
        return f"{self.address.decode()} owns {self._money} $G10, and stakes {self._stake}."

    def add_funds(self, value):
        self._money = self._money + value

    def add_shares(self, value):
        self._stake = round(self._stake + value, 8)

    def check_balance(self, value):
        return self._money + value >= 0

    def create_payment_value(self, blockchain, receiver, amount, sign=True):
        value = {
            'sender': self.address.decode(),
            'recipient': receiver.address.decode(),
            'amount': amount,
            'timestamp': str(datetime.datetime.now())
        }
        if sign:
            self.sign_payment(value, blockchain)
        return value

    def sign_payment(self, value, blockchain):
        signature_mess = blockchain.sign_message(self.key, json.dumps(value).encode('utf-8'))
        value['signature'] = signature_mess.hex()
        value['signer'] = self.key.publickey().export_key(pkcs=8, format='DER').hex()
        return value

    def validate_payment(self, amount):
        return self.check_balance(-1 * amount) and amount >= 0

    def new_payment(self, blockchain, receiver, amount):
        value = self.create_payment_value(blockchain, receiver, amount)
        if self.validate_payment(amount):
            self.add_funds(-1 * amount)
            receiver.add_funds(amount)
            self.update_info_file(self.file)
            return blockchain.create_transaction(value)
        else:
            return False

    def update_info_file(self, file):
        info = {'address': self.address.decode(), 'public': self.pubkey.hex(), 'balance': self._money, 'stake': self._stake, 'signatures': self.signatures}
        with open(f"{file}.json", "w+") as write_file:
            if json.dumps(info) != write_file.read():
                json.dump(info, write_file, indent=4)

    def new_signature(self, msg, signature, signer):
        sign = {'Message': msg, 'Signature': signature, 'Signer': signer}
        if sign not in self.signatures:
            self.signatures.append(sign)
            self.update_info_file(self.file)

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
        with open(f"{file}.pem", "wb") as fo:
            fo.write(private_key)

    def import_wallet_info(self, file):
        """Import wallet information from a file.

        If the private key file does not exist, a new private key is generated and
        exported to a file. If the wallet info file does not exist, default values
        for balance, stake, and signatures are used.

        Args:
            file: The file name for the wallet.

        Returns:
            A tuple containing the private key, balance, stake, and signatures for
            the wallet.
        """
        balance = 0
        stake = 1
        signatures = []

        # Generate a new private key if the file does not exist
        private_key_file = f"{file}.pem"
        if not os.path.exists(private_key_file):
            key = RSA.generate(3072)
            self.key = key
            self.export_private_key(file)
        else:
            # Import the private key from the file
            try:
                with open(private_key_file, mode='rb') as privatefile:
                    privkey = privatefile.read()
            except IOError:
                raise IOError(f"Unable to open private key file {private_key_file}")
            try:
                key = RSA.import_key(privkey)
            except ValueError:
                raise ValueError(f"Invalid private key in file {private_key_file}")

        # Import wallet info from the JSON file
        wallet_info_file = f"{file}.json"
        if os.path.exists(wallet_info_file):
            try:
                with open(wallet_info_file, "r") as rf:
                    line = rf.read()
                    if len(line) > 0:
                        data = json.loads(line)
                        balance = data['balance']
                        if 'stake' not in data.keys():
                            stake = 1
                        else:
                            stake = data['stake']
                        signatures = data['signatures']
            except IOError:
                raise IOError(f"Unable to open wallet info file {wallet_info_file}")
            except ValueError:
                raise ValueError(f"Invalid wallet info in file {wallet_info_file}")

        return key, balance, stake, signatures


class Block:
    def __init__(self, index, timestamp, transactions, proof, previous_hash, validator):
        self._index = index
        self._timestamp = timestamp
        self._transactions = transactions
        self._proof = proof
        self._previous_hash = previous_hash
        self._validator = validator
        self._block = self.format_block()

    def format_block(self):
        block = {
            'index': self._index,
            'timestamp': self._timestamp,
            'transactions': self._transactions,
            'proof': self._proof,
            'previous_hash': self._previous_hash,
            'validator': self._validator
        }
        return block


class Blockchain:
    def __init__(self, file='data_file'):
        self.chain = []
        self._current_transactions = []
        self._block_size = 2
        if not(os.path.exists(f"./{file}.json")):
            self._genesis_block = self._new_block(0, "30/09 G10 CH41N released.")
            print(self._genesis_block['previous_hash'], "\n")
            self.chain.append(self._genesis_block)
            self.export_chain_to_file(file)
        else:
            self.chain_import(self.import_chain_from_file(file))
        self._miner_queue = []
        self._miner_reward = 10
        self._hashrate = 10
        self._validator_pool = []
        self._validator_stake = {}

    def chain_import(self, chain):
        self.chain = chain
        return True

    # Blocks
    def _new_block(self, proof, previous_hash, validator=0):
        current_transactions = self._current_transactions[0:self._block_size]

        block = Block(len(self.chain), str(datetime.datetime.now()), current_transactions, proof, previous_hash, validator).format_block()
        return block

    def create_block(self, proof, previous_hash, validator):
        nblock = self._new_block(proof, previous_hash, validator)
        self._current_transactions = self._current_transactions[self._block_size:]
        self.chain.append(nblock)
        return nblock

    @property
    def last_block(self):
        return self.chain[-1]

    # Transactions
    def _new_transaction(self, values):
        self._current_transactions.append(values)
        return self.last_block['index'] + 1 + int((len(self._current_transactions)-1) / self._block_size)

    def create_transaction(self, values):
        if values:
            index = self._new_transaction(values)
            # result = self._mine()
            result = self._validate_block()

            response = {'message': f'Transaction will be added to the Block {index}.'}
        else:
            result = ""
            response = {'message': f'Transaction failed due to lack of funds.'}
        return response['message'] + result

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
    def import_chain_from_file(file):
        with open(f"{file}.json", "r") as read_file:
            line = read_file.read()
            if len(line) > 0:
                data = json.loads(line)
            else:
                data = ""
        return data

    def export_chain_to_file(self, file='data_file'):
        if self.chain_valid(self.chain):
            with open(f"{file}.json", "w") as write_file:
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

    def check_transaction(self, transaction):
        key = transaction.pop('signer')
        signature = transaction.pop('signature')
        result = self.verify_message(RSA.import_key(bytes.fromhex(key)), json.dumps(transaction).encode('utf-8'), bytes.fromhex(signature))
        transaction['signature'] = signature
        transaction['signer'] = key

        return result == "Signature is valid."

    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1

        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                print(block['previous_hash'], self.hash(previous_block))
                return False

            for transaction in block['transactions'][:-1]:
                if not self.check_transaction(transaction):
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

    # Proof of Work
    def add_miner(self, miner):
        self._miner_queue.append(miner)
        result = self._mine()

        return f"Miner {miner.address.decode()} added to Miner Queue." + result

    def _mine(self):
        if len(self._miner_queue) > 0 and len(self._current_transactions) >= self._block_size:
            miner = rand.choice(self._miner_queue)
        else:
            return "\nNo miner available." if len(self._miner_queue) == 0 else ""

        validator = {
            'public': miner.pubkey.hex(),
            'reward': self._miner_reward
        }
        miner.add_funds(self._miner_reward)

        previous_block = self.last_block
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)

        nblock = self.create_block(proof, previous_hash, validator)

        response = {
            'message': f"Forged new Block {nblock['index']}.",
        }

        return '\n' + response['message']

    # Proof of Stake
    def _validate_block(self):
        for transaction in self._current_transactions:
            if not self.check_transaction(transaction):
                self._current_transactions.pop(self._current_transactions.index(transaction))

        if len(self._validator_pool) > 0 and len(self._current_transactions) >= self._block_size:
            winner_address, reward = self.pick_winner()
            for validator in self._validator_pool:
                if winner_address == validator.address.decode():
                    winner = validator

                    validator = {
                        'address': winner_address,
                        'public': winner.pubkey.hex(),
                        'reward': reward
                    }
                    winner.add_shares(reward)
                    self._validator_stake[winner_address] = winner._stake
                    winner.update_info_file(winner.file)

                    previous_block = self.last_block
                    previous_proof = previous_block['proof']
                    proof = self.proof_of_work(previous_proof)
                    previous_hash = self.hash(previous_block)

                    nblock = self.create_block(proof, previous_hash, validator)

                    response = {
                        'message': f"Forged new Block {nblock['index']}.",
                    }

                    return '\n' + response['message']
        else:
            return "\nNo validator available." if len(self._validator_pool) == 0 else "\nNo transactions in current block."

    def add_validator(self, validator):
        self._validator_pool.append(validator)
        self._validator_stake[validator.address.decode()] = validator._stake
        result = self._validate_block()

        return f"Validator {validator.address.decode()} added to Validator Register." + result

    def pick_winner(self):
        pool = self._validator_stake
        keys, values = list(pool.keys()), list(pool.values())
        rc = rand.choices(keys, weights=values, k=1)
        index = sum(values)/(pool[rc[0]])*(len(values)**(-2/3))
        pool[rc[0]] = round(pool[rc[0]] * (10**(-6)*index), 8)
        return rc[0], pool[rc[0]]
