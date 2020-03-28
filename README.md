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
Use `conda` to create an env using the `environment.yml` file and run `src/fullnode.py`

#### Installing Dependencies
```bash
sudo apt-get install python-dev libgmp3-dev wget gcc #for fastecdsa
```

#### Installing Miniconda
```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh # Follow the instructions and ensure that conda is added to shell path.
```

#### Creating conda environment
```bash
# Inside the Repo directory
cd somechain/
conda env create -f=./environment.yml
# If creation fails, you might need to delete the environment before retrying
# conda env remove -n pychain
```

#### Running
```bash
cd src/
source activate pychain
# You will need to run 2 processes. We suggest using a terminal multiplexer like tmux or screen.
# tmux
python dns_seed.py # Run the central dns server for peer discovery
python fullnode.py -p 9000 -n -q # Run the full node on port(-p) 9000, (-n) new blockchain from genesis i.e. no restore and in quiet mode(-q)
# To terminate press ctrl+C twice.
```


#### Add DDOS ban
```bash
sudo apt install fail2ban
sudo cp ddoskill.conf /etc/fail2ban/filter.d/
# Change Log file location in jail.local before copying
sudo cp jail.local /etc/fail2ban/
sudo service fail2ban start # or restart
sudo fail2ban-client reload # or start
# To check ban status
sudo fail2ban-client status ddoskill
```

#### Using Apache (For SSL)

Follow [this](https://www.digitalocean.com/community/tutorials/how-to-secure-apache-with-let-s-encrypt-on-ubuntu-18-04) for latest methods to install apache with Let's Encrypt certbot for SSL.
```bash
sudo add-apt-repository ppa:certbot/certbot
sudo apt install python-certbot-apache
sudo apt-get install apache2
```

Enable Mods for proxy
```
sudo a2enmod proxy
sudo a2enmod proxy_http
sudo a2enmod proxy_balancer
sudo a2enmod lbmethod_byrequests
sudo a2enmod rewrite
```

You will need to modify your Apache config.
```
# sudo  vim /etc/apache2/sites-available/000-default.conf
# You Will need to write your own config file. Here a snippet of what our file looks like

<VirtualHost *:80>
    ServerName <SERVER_NAME> # example.com
    ServerAlias <SERVER_ALIAS> # chain.example.com
    ProxyPreserveHost On
    ProxyPass / http://0.0.0.0:9000/
    ProxyPassReverse / http://0.0.0.0:9000/
</VirtualHost>

# Here we redirect all requests that come to example.com at port 80 to 
# our chain that is running locally at port 9000.
```

Now we need to enable the certbot 
```
sudo ufw allow 'Apache Full'
sudo certbot --apache -d <SERVER_NAME> -d <SERVER_ALIAS>
# Folow the stes as asked by the bot
sudo systemctl restart apache2
```
