from flask import Flask, render_template, jsonify, request
import os
import sys
import random
from cyberbot import CyberBot

app = Flask(__name__, template_folder='templates')

# Initialize CyberBot with better error handling
try:
    # Try to get API key from environment
    api_key = os.environ.get("GROQ_API_KEY", "YOUR_API_KEY_HERE")
    cyberbot = CyberBot(api_key=api_key)
    app.logger.info("CyberBot initialized successfully with provided API key.")
except Exception as e:
    cyberbot = None
    app.logger.warning(f"CyberBot initialization failed: {str(e)}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/malware-scan')
def malware_scan():
    return render_template('malware_scan.html')

@app.route('/steganalysis')
def steganalysis():
    return render_template('steganalysis.html')

@app.route('/threat-detection')
def threat_detection():
    return render_template('threat_detection.html')

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'message': 'Flask app running on Render.'
    })

# ----- API Stub Endpoints -----

@app.route('/api/analyze', methods=['POST'])
def analyze_file():
    """Stub endpoint for malware file analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Return dummy analysis results
    return jsonify({
        'success': True,
        'filename': file.filename,
        'detection': {
            'is_malware': random.choice([True, False]),
            'confidence': round(random.uniform(0.7, 0.99), 2),
            'malware_type': random.choice(['trojan', 'ransomware', 'worm', 'adware'])
        },
        'signatures': [
            'SuspiciousPEHeader',
            'BlacklistedStrings'
        ],
        'metadata': {
            'file_size': random.randint(1000, 100000),
            'md5': 'a1b2c3d4e5f6g7h8i9j0',
            'sha256': '1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t'
        }
    })

@app.route('/api/scan_file', methods=['POST'])
def scan_file():
    """Stub endpoint for YARA rule scanning"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Return dummy scan results
    return jsonify({
        'success': True,
        'filename': file.filename,
        'matches': [
            {
                'rule': 'BootkitMalware',
                'description': 'Detects potential bootkit malware',
                'strings': [
                    'MBR_Hook',
                    'BootSector'
                ]
            }
        ]
    })

@app.route('/api/scan_memory', methods=['POST'])
def scan_memory():
    """Stub endpoint for memory scanning"""
    if not request.json or 'data' not in request.json:
        return jsonify({'error': 'No data provided'}), 400
    
    # Return dummy memory scan results
    return jsonify({
        'success': True,
        'process_info': {
            'pid': 1234,
            'name': 'suspicious_process.exe'
        },
        'matches': [
            {
                'rule': 'RootkitMemoryPattern',
                'addresses': ['0x1a2b3c4d', '0x5e6f7g8h'],
                'severity': 'high'
            }
        ]
    })

@app.route('/api/yara/add', methods=['POST'])
def add_yara_rule():
    """Stub endpoint for adding YARA rules"""
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400
        
    data = request.get_json()
    
    if 'rule_name' not in data or 'rule_content' not in data:
        return jsonify({'error': 'Missing required fields: rule_name and rule_content'}), 400
    
    # Return success response
    return jsonify({
        'success': True,
        'message': f'Rule {data["rule_name"]} added successfully'
    })

@app.route('/api/steg/analyze', methods=['POST'])
def analyze_steganography():
    """Stub endpoint for steganography analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Determine if it's an image
    is_image = file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp'))
    
    # Return dummy steganalysis results
    has_hidden_data = random.choice([True, False])
    return jsonify({
        'success': True,
        'filename': file.filename,
        'hidden_data_detected': has_hidden_data,
        'file_info': {
            'file_size': random.randint(10000, 5000000),
            'mime_type': 'image/png' if is_image else 'application/octet-stream',
            'dimensions': {
                'width': 1920,
                'height': 1080
            } if is_image else {}
        },
        'detection_methods': [
            {
                'name': 'LSB Analysis',
                'description': 'Analyzes least significant bits for anomalies',
                'detected': has_hidden_data,
                'details': 'Suspicious bit patterns detected in image data' if has_hidden_data else ''
            },
            {
                'name': 'Statistical Analysis', 
                'description': 'Performs statistical tests for randomness',
                'detected': has_hidden_data,
                'details': 'Entropy levels indicate possible concealed data' if has_hidden_data else ''
            }
        ],
        'statistical_analysis': {
            'entropy': round(random.uniform(7.2, 7.9), 4) if has_hidden_data else round(random.uniform(6.5, 7.1), 4),
            'chi_square_p_value': round(random.uniform(0.001, 0.01), 4) if has_hidden_data else round(random.uniform(0.05, 0.5), 4),
            'lsb_ratio': round(random.uniform(0.48, 0.5), 4) if has_hidden_data else round(random.uniform(0.35, 0.45), 4)
        },
        'extracted_data': 'Hidden message found...' if has_hidden_data else None
    })

@app.route('/api/threat/detect', methods=['POST'])
def detect_threat():
    """Stub endpoint for network threat detection"""
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400
    
    data = request.get_json()
    
    # Randomly select attack type with weights
    attack_types = ['normal', 'dos', 'probe', 'r2l', 'u2r']
    weights = [0.6, 0.2, 0.1, 0.05, 0.05]
    attack = random.choices(attack_types, weights=weights, k=1)[0]
    
    # Set high confidence for chosen attack
    confidence = round(random.uniform(0.85, 0.99), 2)
    
    # Create scores dictionary
    scores = {attack_type: 0.01 for attack_type in attack_types}
    scores[attack] = confidence
    
    # Return prediction
    return jsonify({
        'success': True,
        'prediction': [attack],
        'confidence': [confidence],
        'scores': scores,
        'feature_importance': [
            {
                'feature': 'src_bytes',
                'importance': round(random.uniform(0.2, 0.4), 2)
            },
            {
                'feature': 'count',
                'importance': round(random.uniform(0.15, 0.35), 2)
            }
        ]
    })

@app.route('/api/status', methods=['GET'])
def get_status():
    """Status endpoint for API services"""
    return jsonify({
        'status': 'operational',
        'version': '1.0.0',
        'services': {
            'malware_detector': 'operational',
            'steg_analyzer': 'operational',
            'threat_detector': 'operational'
        },
        'uptime': 3624,
        'yara_rules_count': 15
    })

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    """Chat interface for CyberBot."""
    response = None
    error = None
    
    if request.method == 'POST':
        if cyberbot is None:
            error = "CyberBot is not available. Please set the GROQ_API_KEY environment variable."
        else:
            query = request.form.get('query', '')
            if query:
                response = cyberbot.get_security_response(query)
    
    return render_template('chat.html', response=response, error=error)

if __name__ == '__main__':
    app.run(debug=True) 