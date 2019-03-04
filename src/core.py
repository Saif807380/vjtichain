import copy
import json
from datetime import datetime
from collections import Counter
from dataclasses import dataclass, field
from operator import attrgetter
from statistics import median
from sys import getsizeof
from threading import RLock
from typing import Any, Dict, List, Optional, Set

import utils.constants as consts
from utils.dataclass_json import DataClassJson
from utils.logger import logger
from utils.storage import add_block_to_db, check_block_in_db, get_block_from_db, remove_block_from_db, write_header_list_to_db
from utils.utils import dhash, get_time_difference_from_now_secs, lock, merkle_hash, generate_tx_hist
from wallet import Wallet
from authority_rules import authority_rules
from collections import deque


@dataclass
class SingleOutput(DataClassJson):
    """ References a single output """

    # The transaction id which contains this output
    txid: str

    # The index of this output in the transaction
    vout: int


@dataclass
class TxOut(DataClassJson, dict):
    """ A single Transaction Output """

    # The amount in scoin
    amount: int

    # Public key hash of receiver in pubkey script
    address: str


@dataclass
class TxIn(DataClassJson, dict):
    """ A single Transaction Input """

    # The UTXO we will be spending
    # Can be None for coinbase tx
    payout: Optional[SingleOutput]

    # Signature and public key in the scriptSig
    sig: str
    pub_key: str

    # Check if the TxIn is Valid
    def is_valid(self) -> bool:
        try:
            # Ensure the Transaction Id is valid hex string
            if not len(self.payout.txid or "") == consts.HASH_LENGTH_HEX:
                logger.debug("TxIn: TxID of invalid length")
                return False
            # Ensure the payment index is valid
            if not int(self.payout.vout) >= 0:
                logger.debug("TxIn: Payment index(vout) invalid")
                return False
            # Ensure the sig and pubkey are valid
            if len(self.sig or "") == 0 or len(self.pub_key or "") == 0:
                logger.debug("TxIN: Sig/Pubkey of invalid length")
                return False
        except Exception as e:
            logger.error(e)
            return False
        return True


@dataclass
class Transaction(DataClassJson):
    """ A transaction as defined by bitcoin core """

    def __str__(self):
        return self.to_json()

    def __hash__(self):
        return int(dhash(self), 16)

    def __eq__(self, other):
        attrs_sam = self.version == other.version
        attrs_same = attrs_sam and self.timestamp == other.timestamp and self.locktime == other.locktime
        txin_same = True
        for txin in self.vin.values():
            if txin not in other.vin.values():
                txin_same = False
                break
        txout_same = True
        for txout in self.vout.values():
            if txout not in other.vout.values():
                txout_same = False
                break
        return attrs_same and txin_same and txout_same

    def hash(self):
        return dhash(self)

    def sign(self, w=None):
        sign_copy_of_tx = copy.deepcopy(self)
        sign_copy_of_tx.vin = {}
        sig = w.sign(sign_copy_of_tx.to_json())
        for i in self.vin:
            self.vin[i].sig = sig

    def add_sign(self, sig):
        for i in self.vin:
            self.vin[i].sig = sig

    def summarize(self):
        # Summarize the transaction and give sender address, receiver addresses and amount.
        pub_key = "SomePublicKey"
        receivers = {}
        for i in self.vin:
            pub_key = self.vin[i].pub_key

        for i in self.vout:
            address = self.vout[i].address
            if address == pub_key:
                continue
            if address not in receivers:
                receivers[address] = 0
            receivers[address] += self.vout[i].amount      
        return pub_key, receivers

    def is_valid(self):
        # No empty inputs or outputs -1
        if len(self.vin) == 0 or len(self.vout) == 0:
            logger.debug("Transaction: Empty vin/vout")
            return False

        # Transaction size should not exceed max block size -2
        if getsizeof(str(self)) > consts.MAX_BLOCK_SIZE_KB * 1024:
            logger.debug("Transaction: Size Exceeded")
            return False

        # All outputs in legal money range -3
        for index, out in self.vout.items():
            if out.amount > consts.MAX_COINS_POSSIBLE or out.amount <= 0:
                logger.debug("Transaction: Invalid Amount" + str(out.amount))
                return False

        # Verify all Inputs are valid - 4
        for index, inp in self.vin.items():
            if not inp.is_valid():
                logger.debug("Transaction: Invalid TxIn")
                return False

        # Verify locktime -5
        difference = get_time_difference_from_now_secs(self.locktime)
        if difference > 0:
            logger.debug("Transaction: Locktime Verify Failed")
            return False

        # Limit Message size
        if len(self.message) > consts.MAX_MESSAGE_SIZE:
            logger.debug("Transaction: Message exceeds allowed length")
            return False
        return True

    def object(self):
        newtransaction = copy.deepcopy(self)
        n_vin = {}
        for j, tx_in in self.vin.items():
            if not isinstance(tx_in, TxIn):
                n_vin[int(j)] = TxIn.from_json(json.dumps(tx_in))
            else:
                n_vin[int(j)] = copy.deepcopy(tx_in)

        n_vout = {}
        for j, tx_out in self.vout.items():
            if not isinstance(tx_out, TxOut):
                n_vout[int(j)] = TxOut.from_json(json.dumps(tx_out))
            else:
                n_vout[int(j)] = copy.deepcopy(tx_out)

        newtransaction.vin = n_vin
        newtransaction.vout = n_vout

        return newtransaction

    # Version for this transaction
    version: int

    # Timestamp for this transaction
    timestamp: int    

    # Earliest time(Unix timestamp >500000000)
    # when this transaction may be added to the block chain.
    # -1 for coinbase transaction
    locktime: int

    # The input transactions
    vin: Dict[int, TxIn]

    # The output transactions
    vout: Dict[int, TxOut]

    # Message associated with this transaction
    message: str = ""


@dataclass
class BlockHeader(DataClassJson):
    """ The header of a block """

    # Version
    version: int

    # Block Height
    height: Optional[int] = field(repr=False)

    # A reference to the hash of the previous block
    prev_block_hash: Optional[str]

    # A hash of the root of the merkle tree of this block’s transactions
    merkle_root: str

    # The approximate creation time of this block (seconds from Unix Epoch)
    timestamp: int

    # Signature of the authority who mined this block
    signature: str


@dataclass
class Block(DataClassJson):
    """ A single block """

    # The block header
    header: BlockHeader

    # The transactions in this block
    transactions: List[Transaction]

    # Validate object
    def object(self):
        newblock = copy.deepcopy(self)
        for i, tx in enumerate(self.transactions):
            newblock.transactions[i] = self.transactions[i].object()
        return newblock

    def __repr__(self):
        return dhash(self.header)

    def is_valid(self) -> bool:
        # Block should be of valid size and List of Transactions should not be empty -1
        if getsizeof(self.to_json()) > consts.MAX_BLOCK_SIZE_KB * 1024 or len(self.transactions) == 0:
            logger.debug("Block: Size Exceeded/No. of Tx==0")
            return False

        # Make sure each transaction is valid -3
        for tx in self.transactions:
            if not tx.is_valid():
                logger.debug("Block: Transaction is not Valid")
                return False

        # Verify merkle hash -4
        if self.header.merkle_root != merkle_hash(self.transactions):
            logger.debug("Block: Merkle Hash failed")
            return False
        return True


@dataclass
class Utxo:
    # Mapping from string repr of SingleOutput to List[TxOut, Blockheader]
    utxo: Dict[str, List[Any]] = field(default_factory=dict)

    def get(self, so: SingleOutput) -> Optional[List[Any]]:
        so_str = so.to_json()
        if so_str in self.utxo:
            return self.utxo[so_str]
        return None, None, None

    def set(self, so: SingleOutput, txout: TxOut, blockheader: BlockHeader):
        so_str = so.to_json()
        self.utxo[so_str] = [txout, blockheader]

    def remove(self, so: SingleOutput) -> bool:
        so_str = so.to_json()
        if so_str in self.utxo:
            del self.utxo[so_str]
            return True
        return False


@dataclass
class TxHistory:
    tx_hist: Dict = field(default_factory=dict)

    def append(self, pub_key: str, tx: str) -> None:
        if pub_key not in self.tx_hist:
            self.tx_hist[pub_key] = deque(maxlen=consts.MAX_TRANSACTION_HISTORY_TO_KEEP)
        self.tx_hist[pub_key].append(tx)
        return

    def get(self, pub_key: str) -> List[str]:
        if pub_key in self.tx_hist:
            return list(reversed(self.tx_hist[pub_key]))
        return []


@dataclass
class Chain:
    # The max length of the blockchain
    length: int = 0

    # The list of blocks
    header_list: List[BlockHeader] = field(default_factory=list)

    # The UTXO Set
    utxo: Utxo = field(default_factory=Utxo)

    # Transaction History
    transaction_history: TxHistory = field(default_factory=TxHistory)

    def __eq__(self, other):
        for i, h in enumerate(self.header_list):
            if dhash(h) != dhash(other.header_list[i]):
                return False
        return True

    @classmethod
    def build_from_header_list(cls, hlist: List[BlockHeader]):
        nchain = cls()
        nchain.header_list = []
        for header in hlist:
            block = Block.from_json(get_block_from_db(dhash(header))).object()
            nchain.add_block(block)
        return nchain

    # Build the UTXO Set from scratch
    def build_utxo(self):
        for header in self.header_list:
            block = Block.from_json(get_block_from_db(dhash(header))).object()
            self.update_utxo(block)

    # Update the UTXO Set on adding new block, *Assuming* the block being added is valid
    def update_utxo(self, block: Block):
        block_transactions: List[Transaction] = block.transactions
        for t in block_transactions:
            thash = dhash(t)
            # Remove the spent outputs
            for tinput in t.vin:
                so = t.vin[tinput].payout
                if so:
                    self.utxo.remove(so)
            # Add new unspent outputs
            for touput in t.vout:
                self.utxo.set(SingleOutput(txid=thash, vout=touput), t.vout[touput], block.header)

    def is_transaction_valid(self, transaction: Transaction):
        if not transaction.is_valid():
            return False

        sum_of_all_inputs = 0
        sum_of_all_outputs = 0
        sign_copy_of_tx = copy.deepcopy(transaction)
        sign_copy_of_tx.vin = {}
        for inp, tx_in in transaction.vin.items():
            tx_out, block_hdr = self.utxo.get(tx_in.payout)
            # ensure the TxIn is present in utxo, i.e exists and has not been spent
            if block_hdr is None:
                logger.debug(tx_in.payout)
                logger.debug("Chain: Transaction not present in utxo")
                return False

            # Verify that the Signature is valid for all inputs
            if not Wallet.verify(sign_copy_of_tx.to_json(), tx_in.sig, tx_out.address):
                logger.debug("Chain: Invalid Signature")
                return False

            sum_of_all_inputs += tx_out.amount

        if sum_of_all_inputs > consts.MAX_COINS_POSSIBLE or sum_of_all_inputs < 0:
            logger.debug("Chain: Invalid input Amount")
            return False

        for out, tx in transaction.vout.items():
            sum_of_all_outputs += tx.amount

        # ensure sum of amounts of all inputs is in valid amount range
        if sum_of_all_outputs > consts.MAX_COINS_POSSIBLE or sum_of_all_outputs < 0:
            logger.debug("Chain: Invalid output Amount")
            return False

        # ensure sum of amounts of all inputs is > sum of amounts of all outputs
        if not sum_of_all_inputs == sum_of_all_outputs:
            logger.debug("Chain: input sum less than output sum")
            return False

        return True

    def is_block_valid(self, block: Block):
        # Check if the block is valid -1

        local_utxo = copy.deepcopy(self.utxo)

        if not block.is_valid():
            logger.debug("Block is not valid")
            return False

        # Ensure the prev block header matches the previous block hash in the Chain -4
        if len(self.header_list) > 0 and not dhash(self.header_list[-1]) == block.header.prev_block_hash:
            logger.debug("Chain: Block prev header does not match previous block")
            return False

        # Validating each transaction in block
        for t in block.transactions:
            if self.is_transaction_valid(t):
                thash = dhash(t)
                # Remove the spent outputs
                for tinput in t.vin:
                    so = t.vin[tinput].payout
                    if so:
                        if local_utxo.get(so)[0] is not None:
                            local_utxo.remove(so)
                        else:
                            logger.error("Chain: Single output missing in UTxO, Transaction invalid")
                            return False
                    else:
                        logger.error("Chain: No Single output, Transaction invalid")
                        return False
                # Add new unspent outputs
                for touput in t.vout:
                    local_utxo.set(SingleOutput(txid=thash, vout=touput), t.vout[touput], block.header)
            else:
                logger.debug("Chain: Transaction not valid")
                return False

        # Validate Authority Signature
        timestamp = datetime.fromtimestamp(block.header.timestamp)
        seconds_since_midnight = (timestamp - timestamp.replace(hour=0, minute=0, second=0, microsecond=0)).total_seconds()
        for authority in authority_rules["authorities"]:
            if seconds_since_midnight <= authority["to"] and seconds_since_midnight >= authority["from"]:
                blk_hdr = copy.deepcopy(block.header)
                blk_hdr.signature = ""
                if Wallet.verify(dhash(blk_hdr), block.header.signature, authority["pubkey"]):
                    return True
        return False

    def add_block(self, block: Block, is_genesis: bool) -> bool:
        if is_genesis or self.is_block_valid(block):
            self.header_list.append(block.header)
            self.update_utxo(block)
            self.length = len(self.header_list)
            add_block_to_db(block)
            for tx in block.transactions:
                pub_key, data = tx.summarize()
                for address in data:
                    amount = data[address]
                    timestamp = tx.timestamp
                    bhash = dhash(block.header)
                    thash = dhash(tx)
                    message = tx.message
                    history = generate_tx_hist(amount, pub_key, timestamp, bhash, thash, message)
                    self.transaction_history.append(address, history)

                    history = generate_tx_hist(-amount, address, timestamp, bhash, thash, message)
                    self.transaction_history.append(pub_key, history)

            logger.info("Chain: Added Block " + str(block))
            return True
        return False


class BlockChain:

    block_lock = RLock()

    def __init__(self):
        self.active_chain: Chain = Chain()
        self.mempool: Set[Transaction] = set()

    def remove_transactions_from_mempool(self, block: Block):
        """Removes transaction from the mempool based on a new received block

        Arguments:
            block {Block} -- The block which is received
        """
        new_mempool = set()
        for x in self.mempool:
            DONE = True
            for t in block.transactions:
                if dhash(x) == dhash(t):
                    DONE = False
            if DONE:
                new_mempool.add(x)
        self.mempool = new_mempool

    def update_active_chain(self):
        # Save Active Chain to DB
        write_header_list_to_db(self.active_chain.header_list)

    def build_from_header_list(self, hlist: List[str]):
        try:
            for header in hlist:
                block = Block.from_json(get_block_from_db(header)).object()
                if block:
                    self.add_block(block)
                else:
                    logger.error("Blockchain: Block does not exist in DB")
        except Exception as e:
            logger.error("Blockchain: Exception " + str(e))

    @lock(block_lock)
    def add_block(self, block: Block):
        blockAdded = False

        chain = self.active_chain
        is_genesis = chain.length == 0
        if is_genesis or block.header.prev_block_hash == dhash(chain.header_list[-1]):
            if chain.add_block(block, is_genesis):
                self.update_active_chain()
                self.remove_transactions_from_mempool(block)
                blockAdded = True

        return blockAdded


genesis_block_transaction = [
    Transaction(
        version=1,
        locktime=0,
        timestamp=1551698572,
        message="Genesis Transaction",
        vin={0: TxIn(payout=None, sig=consts.GENESIS_BLOCK_SIGNATURE, pub_key="Genesis")},
        vout={
            0: TxOut(
                amount=1000000,
                address="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0tmjDG6v51ELMieRGuTfOgmfTe7BzNBsHQseqygX58+MQjNyjoOPkphghhYFpIFPzVORAI6Qief9lrncuWsOMg==",
            ),
            1: TxOut(
                amount=1000000,
                address="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3s5Iqp9VzlL7ngLfR2xb1RIGfuo+siL/zaZdeFblI8pnU5SpJCFEEMZDQBnEEPIOz9bv9lK46AwV3vLcN1VpCA==",
            ),
        },
    )
]


genesis_block_header = BlockHeader(
    version=1,
    prev_block_hash=None,
    height=0,
    merkle_root=merkle_hash(genesis_block_transaction),
    timestamp=1551698580,
    signature="",
)
genesis_block = Block(header=genesis_block_header, transactions=genesis_block_transaction)


if __name__ == "__main__":
    print(genesis_block)
    logger.debug(genesis_block)
    gb_json = genesis_block.to_json()
    gb = Block.from_json(gb_json).object()
    print(gb.transactions[0].vout[0].amount)
