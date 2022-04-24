#!/bin/bash
echo "GodZilo's Root-Kit Installation:"
echo "Running..."
sudo pip3 install -r requirements.txt
cp main.py rootkit
sudo cp -r www /usr/local/bin/
chmod +x rootkit
sudo cp rootkit /usr/local/bin/
clear
rm rootkit
echo "Installed!"
echo "Use rootkit -h"
