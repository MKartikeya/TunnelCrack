### Code structure
These are the scripts used for localNet/serverIP attack present in same directory:
1. ap-config.py	
2. ap-start-localnet.py
3. ap-start-serverip.py
4. ap-cleanup.py

### How to run
First make all files executable by running 
```bash
sudo chmod +x *
```

#### Attack scripts (AP side)
For running the attack, just run ap-config.py with root permissions. 
```bash
sudo ./ap-config.py
```
It will prompt to select interfaces, LocalNet/ServerIP attack.

For cleanup run ap-cleanup.py. 
```bash
sudo ./ap-cleanup.py
```

#### Defense scripts (victim side)
To run defense scripts
1. localnet
```bash
```
2. serverip
```bash
```
3. routes-ip check
```bash
```