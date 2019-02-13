import copy
import time
import json
from multiprocessing import Process
from sys import getsizeof
from typing import List, Optional, Set, Tuple

import requests

import utils.constants as consts
from core import Block, BlockHeader, Chain, Transaction
from utils.logger import logger
from utils.utils import compress, dhash, merkle_hash, get_time_difference_from_now_secs
from wallet import Wallet

from authority_rules import authority_rules


def is_my_turn(wallet):
    timestamp = int(time.time())
    turn = int(timestamp / authority_rules["interval"]) % len(authority_rules["authorities"])
    for authority in authority_rules["authorities"]:
        if authority["order"] == turn and wallet.public_key == authority["pubkey"]:
            return True
    return False


class Authority:
    def __init__(self):
        self.p: Optional[Process] = None

    def is_mining(self):
        if self.p:
            if self.p.is_alive():
                return True
            else:
                self.p = None
        return False

    def start_mining(self, mempool: Set[Transaction], chain: Chain, wallet: Wallet):
        if not self.is_mining():
            if is_my_turn(wallet):
                if len(mempool) > consts.MINING_TRANSACTION_THRESHOLD or (
                    len(mempool) > 0
                    and abs(get_time_difference_from_now_secs(chain.header_list[-1].timestamp)) > consts.MINING_INTERVAL_THRESHOLD
                ):
                    self.p = Process(target=self.__mine, args=(mempool, chain, wallet))
                    self.p.start()
                    logger.debug("Miner: Started mining")

    def stop_mining(self):
        if self.is_mining():
            # logger.debug("Miner: Called Stop Mining")
            self.p.terminate()
            self.p = None

    def __calculate_transactions(self, transactions: List[Transaction]) -> List[Transaction]:
        i = 0
        size = 0
        mlist = []
        while i < len(transactions) and size <= consts.MAX_BLOCK_SIZE_KB:
            t = transactions[i]
            mlist.append(t)
            size += getsizeof(t.to_json())
            i += 1
        return mlist

    def __mine(self, mempool: Set[Transaction], chain: Chain, wallet: Wallet) -> Block:
        c_pool = list(copy.deepcopy(mempool))
        mlist = self.__calculate_transactions(c_pool)
        logger.debug(len(mlist))

        block_header = BlockHeader(
            version=consts.MINER_VERSION,
            height=chain.length,
            prev_block_hash=dhash(chain.header_list[-1]),
            merkle_root=merkle_hash(mlist),
            timestamp=int(time.time()),
            signature="",
        )

        sign = wallet.sign(dhash(block_header))
        block_header.signature = sign
        block = Block(header=block_header, transactions=mlist)
        requests.post("http://0.0.0.0:" + str(consts.MINER_SERVER_PORT) + "/newblock", data=compress(block.to_json()))
        logger.info(f"Miner: Mined Block with {len(mlist)} transactions.")
        return

