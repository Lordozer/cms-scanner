# CMS-Scanner

## Overview
This Python-based CMS vulnerability scanner detects common Content Management Systems (CMS) like Joomla, WordPress, SilverStripe, and Drupal. It utilizes external tools such as JoomScan, WPScan, and DroopScan to perform passive detection of vulnerabilities and versions. The scanner can generate scan reports and search for Common Vulnerabilities and Exposures (CVEs) related to detected CMS versions.

## Usage Instructions
1. Clone the repository: `git clone https://github.com/lordozer/cms-scanner.git`
2. Navigate to the project directory: `cd cms-scanner`
3. Install dependencies: `pip install -r requirements.txt`
5. Navigate to the droopescan directory: `cd droopescan`
6. Install dependencies: `pip install -r requirements.txt`
7. return to the project directory `cd ..`
8. Run the scanner: `python scanner.py`

## Dependencies
- `requests==2.26.0`: HTTP library for making requests
- `reportlab==3.6.1`: Library for generating PDF files

## Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or create a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
