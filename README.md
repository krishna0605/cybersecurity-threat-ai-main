# Cybersecurity Threat AI

A comprehensive security analysis platform with AI-powered threat detection capabilities.

## Features

- **Malware Detection**: Scan files for malicious code using YARA rules and machine learning
- **Steganography Analysis**: Detect hidden information in images and files
- **Network Threat Detection**: Identify potential network threats using ML models
- **RESTful API**: Access all functionality programmatically

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/cybersecurity-threat-ai.git
   cd cybersecurity-threat-ai
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python src/app.py
   ```

## Usage

After starting the application, navigate to:
- http://localhost:5000/ - Main dashboard
- http://localhost:5000/malware-scan - Malware detection interface
- http://localhost:5000/steganalysis - Steganography analysis
- http://localhost:5000/threat-detection - Network threat detection
- http://localhost:5000/documentation - API documentation

## API Reference

The application provides a RESTful API:

- `POST /api/analyze` - Analyze files for malware
- `POST /api/scan_file` - Scan files using YARA rules
- `POST /api/scan_memory` - Scan memory for malware signatures
- `POST /api/yara/add` - Add new YARA rules
- `POST /api/steg/analyze` - Analyze files for steganography
- `POST /api/threat/detect` - Detect network threats
- `GET /api/status` - Get system status

## License

[MIT License](LICENSE)

## Technologies Used

- Flask
- YARA Rules
- Machine Learning (scikit-learn)
- Bootstrap
