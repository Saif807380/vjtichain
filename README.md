# VJTI Chain
A complete implementation of a Proof of Authority (POA) Blockchain in python 3.7+

## Simplifications
- Storage using pickledb in flat files
- Communication between peers using http api calls
- Can only send tokens to a single public key
- Serialization completely done via json
- No scripting language
- All nodes assumed to be honest and non malicious
- Peer discovery through a central server
- Every node is a full node with a wallet, light nodes would be implemented as Android Apps.

## Installing and running
Use conda to create an env using the environment.yml file and run src/fullnode.py

#### Installing Dependencies
```
sudo apt-get install python-dev libgmp3-dev wget #for fastecdsa
```

#### Installing Miniconda
```
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh # Follow the instructions and ensure that conda is added to shell path.
```

#### Creating conda environment
```
# Inside the Repo directory
cd somechain/
conda env create -f=./environment.yml
```

#### Running
```
cd src/
source activate pychain
python dns_seed.py # Run the central dns server for peer discovery
python fullnode.py -p 9000 -n -q # Run the full node on port(-p) 9000, (-n) new blockchain from genesis i.e. no restore and in quiet mode(-q)
# To terminate press ctrl+C twice.
```


#### Add DDOS ban
```
sudo apt install fail2ban
sudo cp ddoskill.conf /etc/fail2ban/filter.d/
# Change Log file location in jail.local before copying
sudo cp jail.local /etc/fail2ban/
sudo service fail2ban start # or restart
sudo fail2ban-client start # or reload
# To check ban status
sudo fail2ban-client status ddoskill
```
