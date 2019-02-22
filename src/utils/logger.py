import logging
from datetime import datetime

from . import constants as consts

for name in ['werkzeug', 'bottle', 'waitress']:
    log = logging.getLogger(name)
    log.setLevel(logging.CRITICAL)
    log.disabled = True

logger = logging.getLogger("vjtichain")
logger.propagate = False

iplogger = logging.getLogger("ipd")
iplogger.propagate = False
iplogger.setLevel(logging.DEBUG)
ipformatter = logging.Formatter("%(asctime)s %(message)s", consts.DATE_FORMAT)
ipfile_handler = logging.FileHandler(consts.LOG_DIRECTORY +  "ip.log")
ipfile_handler.setFormatter(ipformatter)
ipfile_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s %(levelname)-10s %(message)s", consts.DATE_FORMAT)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler(consts.LOG_DIRECTORY + datetime.strftime(datetime.now(), consts.DATE_FORMAT) + ".log")
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.DEBUG)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(consts.LOG_LEVEL)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

iplogger.addHandler(ipfile_handler)