#!/bin/bash

echo "Starting CMS Scanner setup..."

# Update package lists
echo "Updating package lists..."
sudo apt update

# Install software-properties-common if not already installed
echo "Installing software-properties-common..."
sudo apt install -y software-properties-common

# Add deadsnakes PPA for Python 3.7
echo "Adding deadsnakes PPA..."
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update

# Install Python 3.7 and ensure it includes distutils
echo "Installing Python 3.7 and system dependencies..."
sudo apt install -y python3.7 python3.7-distutils curl

# Install other system dependencies
echo "Installing other system dependencies..."
sudo apt install -y nmap git unzip curl ruby-full build-essential

# Install WPScan
echo "Installing WPScan..."
sudo gem install wpscan

# Install JoomScan
echo "Installing JoomScan..."
if [ "$(lsb_release -is)" == "Kali" ]; then
  sudo apt install -y joomscan
else
  git clone https://github.com/OWASP/joomscan.git
fi

# Install pip for Python 3.7
echo "Installing pip for Python 3.7..."
sudo apt remove python3-typing-extensions
sudo apt install python3.7-venv
python3.7 -m venv myenv
source myenv/bin/activate
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py

# Install Python dependencies globally using Python 3.7
echo "Installing Python dependencies globally using Python 3.7..."
sudo python3.7 -m pip install -r requirements.txt

# Clone and set up external tools
echo "Setting up external tools..."

# Droopescan
echo "Cloning Droopescan..."
git clone https://github.com/droope/droopescan.git
cd droopescan
sudo python3.7 -m pip install -r requirements.txt
cd ..

# Typo3Scan
echo "Cloning Typo3Scan..."
git clone https://github.com/whoot/Typo3Scan.git
cd Typo3Scan
sudo python3.7 -m pip install -r requirements.txt
cd ..

# AEMScan
echo "Cloning AEMScan..."
git clone https://github.com/Raz0r/aemscan.git
cd aemscan
sudo python3.7 setup.py install
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
sudo python3.7 -m pip install -r requirements.txt
chmod +x badmoodle.py
cd ..

# Download and extract the CPE dictionary
echo "Downloading and extracting the CPE dictionary..."
wget https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip
unzip official-cpe-dictionary_v2.3.xml.zip
rm official-cpe-dictionary_v2.3.xml.zip

echo "Setup complete. You can now run the CMS Scanner tool."
