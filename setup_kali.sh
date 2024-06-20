#!/bin/bash

echo "Starting CMS Scanner setup..."

# Update package lists
echo "Updating package lists..."
sudo apt update

# Install other system dependencies
echo "Installing other system dependencies..."
sudo apt install -y nmap git unzip curl ruby-full build-essential

# Install WPScan and joomscan
echo "Installing WPScan..."
sudo apt install -y wpscan joomscan


# Install Python dependencies globally using Python
echo "Installing Python dependencies globally using Python"
pip install -r requirements.txt

# Clone and set up external tools
echo "Setting up external tools..."

# Droopescan
echo "Cloning Droopescan..."
git clone https://github.com/droope/droopescan.git
cd droopescan
pip install -r requirements.txt
cd ..

# Typo3Scan
echo "Cloning Typo3Scan..."
git clone https://github.com/whoot/Typo3Scan.git
cd Typo3Scan
pip install -r requirements.txt
cd ..

# AEMScan
echo "Cloning AEMScan..."
git clone https://github.com/Raz0r/aemscan.git
cd aemscan
sudo python setup.py install
cd ..

# VBScan
echo "Cloning VBScan..."
git clone https://github.com/OWASP/vbscan.git
cd vbscan
chmod +x ./vbscan.pl
cd ..

# Badmoodle
echo "Cloning Badmoodle..."
git clone https://github.com/cyberaz0r/badmoodle
cd badmoodle
pip install -r requirements.txt
chmod +x badmoodle.py
cd ..

# Download and extract the CPE dictionary
echo "Downloading and extracting the CPE dictionary..."
wget https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
unzip official-cpe-dictionary_v2.3.xml.zip
rm official-cpe-dictionary_v2.3.xml.zip

echo "Setup complete. You can now run the CMS Scanner tool."
