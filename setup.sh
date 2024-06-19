#!/bin/bash

echo "Starting CMS Scanner setup..."

# Update package lists
echo "Updating package lists..."
sudo apt update

# Install system dependencies
echo "Installing system dependencies..."
sudo apt install -y python3 python3-pip nmap git unzip curl ruby-full build-essential

# Install WPScan
echo "Installing WPScan..."
sudo gem install wpscan

# Install JoomScan
echo "Installing JoomScan..."
if [ "$(lsb_release -is)" == "Kali" ]; then
  sudo apt install -y joomscan
else
  git clone https://github.com/OWASP/joomscan.git
  cd joomscan
  sudo cp joomscan.pl /usr/local/bin/joomscan
  sudo chmod +x /usr/local/bin/joomscan
  cd ..
  mv joomscan cms-scanner/
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

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
pip3 install -r requirements.txt
cd ..

# AEMScan
echo "Cloning AEMScan..."
git clone https://github.com/Raz0r/aemscan.git
cd aemscan
chmod +x setup.py
python setup.py install
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
pip3 install -r requirements.txt
chmod +x badmoodle.py
cd ..

# Download and extract the CPE dictionary
echo "Downloading and extracting the CPE dictionary..."
wget https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
unzip official-cpe-dictionary_v2.3.xml.zip
rm official-cpe-dictionary_v2.3.xml.zip

echo "Setup complete. You can now run the CMS Scanner tool."
