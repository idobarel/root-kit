#!/bin/bash
echo "GodZilo's Root-Kit Installation:"
echo "Running..."
sudo python3 -c "import os; arr=os.popen('python3 --version').split(' ')[1].split('.');x=f'python{arr[0]}.{arr[1]}';os.system(f'sudo setcap cap_net_raw=eip /usr/bin/{x}')"
sudo pip3 install -r requirements.txt
cp main.py rootkit
sudo cp -r www /usr/local/bin/
chmod +x rootkit
sudo cp rootkit /usr/local/bin/
clear
rm rootkit
echo "Installed!"
echo "Use rootkit -h"
