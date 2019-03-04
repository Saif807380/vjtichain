import argparse
import logging
import sys

# LOGGING CONSTANTS
LOG_DIRECTORY = "log/"
DATE_FORMAT = "%b %d %H:%M:%S"
LOG_LEVEL = logging.DEBUG

# DNS SEED CONSTANTS
ENTRY_DURATION = 60 * 10  # duration in seconds
SEED_SERVER_URL = "http://localhost:8080"
SEED_SERVER_PORT = 8080

# MINER CONSTANTS
MINER_SERVER_PORT = 9000
MINER_VERSION = 1
MINING_INTERVAL_THRESHOLD = 5  # Seconds
MINING_TRANSACTION_THRESHOLD = 10  # No. of Transactions

# BLOCKCHAIN CONSTANTS
HASH_LENGTH_HEX = 64  # 256 bit string is 64 hexa_dec string

PUBLIC_KEY_LENGTH = 124  # Length of Armoured Public Key

MAX_MESSAGE_SIZE = 128  # Maximum Message Length for each Transaction

FORK_CHAIN_HEIGHT = 7  # Keep only chains that are within this height of the active chain

MAX_BLOCK_SIZE_KB = 4096
MAX_COINS_POSSIBLE = 10000000 * 10

INITIAL_BLOCK_REWARD = 5 * 100
REWARD_UPDATE_INTERVAL = 20_000

# A block cannot have timestamp greater than this time in the future
BLOCK_MAX_TIME_FUTURE_SECS = 2 * 60 * 60

INITIAL_BLOCK_DIFFICULTY = 1

BLOCK_DIFFICULTY_UPDATE_INTERVAL = 5  # number of blocks
AVERAGE_BLOCK_MINE_INTERVAL = 2 * 60  # seconds
MAXIMUM_TARGET_DIFFICULTY = "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

# Cheat Code
BLOCK_MINING_SPEEDUP = 1

# Max History
MAX_TRANSACTION_HISTORY_TO_KEEP = 2048

# Define Values from arguments passed
parser = argparse.ArgumentParser()

parser.add_argument("--version", help="Print Implementation Version", action="store_true")
parser.add_argument("-p", "--port", type=int, help="Port on which the fullnode should run", default=MINER_SERVER_PORT)
parser.add_argument("-s", "--seed-server", type=str, help="Url on which the DNS seed server is running", default=SEED_SERVER_URL)
parser.add_argument("-nm", "--no-mining", help="Do not Mine", action="store_true")
parser.add_argument("-n", "--new-blockchain", help="Start a new Blockchain from Genesis Block", action="store_true")
group = parser.add_mutually_exclusive_group()
group.add_argument("-v", "--verbose", action="store_true")
group.add_argument("-q", "--quiet", action="store_true")
args = parser.parse_args()

# Print Somechain Version
if args.version:
    print("## Somchain Version: " + str(MINER_VERSION) + " ##")
    sys.exit(0)

# Set Logging Level
if args.quiet:
    LOG_LEVEL = logging.INFO
elif args.verbose:
    LOG_LEVEL = logging.DEBUG

# Set Server Port
MINER_SERVER_PORT = args.port

# Set Seed Server URL
SEED_SERVER_URL = args.seed_server

# Set if create new blockchain
if args.new_blockchain:
    NEW_BLOCKCHAIN = True
else:
    NEW_BLOCKCHAIN = False

# Set if to mine of not
if args.no_mining:
    NO_MINING = True
else:
    NO_MINING = False


# Coinbase Maturity
COINBASE_MATURITY = 0

# Genesis Block Sign
GENESIS_BLOCK_SIGNATURE = "4093f844282309feb788feb2d3a81946cbc70478360f0d0fe581e1425027feaa9992553797ce1aa005eb0f23824edef7582997a289e45696143bc5f55dd55a47"

# DB CONSTANTS
BLOCK_DB_LOC = "db/" + str(MINER_SERVER_PORT) + "block.sqlite"
CHAIN_DB_LOC = "db/" + str(MINER_SERVER_PORT) + "chain.json"

# WALLET CONSTANTS
WALLET_DB_LOC = "wallet/"

# AUTHORITY RULES
AUTHORITY_RULES_LOC = "authority_rules.json"
