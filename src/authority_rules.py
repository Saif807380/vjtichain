import json
import utils.constants as consts

# Retrieve Authority List
with open(consts.AUTHORITY_RULES_LOC, "r") as file:
    data = file.read()
authority_rules = json.loads(data)
