from flask import Flask, request, jsonify
import os
import tempfile
from werkzeug.utils import secure_filename
from malware_detection import malware_detector
import base64

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # Limit upload size to 50MB
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# Use the global malware detector instance from the module
# malware_detector = MalwareDetector()  # This is no longer needed

# Make sure the API routes are accessible from the main app
def configure_routes(flask_app):
    """
    Configure routes for the API
    This function will be called by the main app to register these routes
    """
    
    @flask_app.route('/api/analyze', methods=['POST'])
    def analyze_file():
        """
        API endpoint to analyze uploaded files for malware
        """
        # Check if file is in the request
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
            
        file = request.files['file']
        
        # Check if filename is empty
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        # Save file to temp location
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            # Analyze file for malware
            results = malware_detector.analyze_file(file_path, filename)
            
            # Remove the temp file after analysis
            os.remove(file_path)
            
            return jsonify(results)
        except Exception as e:
            # Make sure to clean up on error
            if os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/api/yara/add', methods=['POST'])
    def add_yara_rule():
        """
        API endpoint to add a new YARA rule
        """
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
            
        data = request.get_json()
        
        if 'rule_name' not in data or 'rule_content' not in data:
            return jsonify({'error': 'Missing required fields: rule_name and rule_content'}), 400
            
        rule_name = data['rule_name']
        rule_content = data['rule_content']
        
        # Ensure rule name is safe for filesystem
        safe_rule_name = secure_filename(rule_name)
        if not safe_rule_name.endswith('.yar'):
            safe_rule_name += '.yar'
            
        # Save the rule to the YARA rules directory
        try:
            os.makedirs('src/yara_rules', exist_ok=True)
            rule_path = os.path.join('src/yara_rules', safe_rule_name)
            
            with open(rule_path, 'w') as f:
                f.write(rule_content)
                
            # Reload YARA rules
            malware_detector.yara_rules = malware_detector.load_yara_rules()
            
            return jsonify({'success': True, 'message': f'Rule {rule_name} added successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/api/status', methods=['GET'])
    def get_status():
        """
        API endpoint to get the status of the malware detection service
        """
        return jsonify({
            'status': 'running',
            'version': '1.0.0',
            'rules_loaded': malware_detector.yara_rules is not None
        })

    @flask_app.route('/api/scan_file', methods=['POST'])
    def scan_file():
        """
        Scan a file for malware using the malware detector.
        
        Expected format:
        - POST request with file in 'file' field
        
        Returns:
        - JSON with scan results
        """
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        try:
            # Save the file temporarily
            temp_path = os.path.join(tempfile.gettempdir(), secure_filename(file.filename))
            file.save(temp_path)
            
            # Scan the file - check what method is available in malware_detector
            if hasattr(malware_detector, 'scan_file'):
                # Use the scan_file method if available
                result = malware_detector.scan_file(temp_path)
            else:
                # Fall back to analyze_file if scan_file is not available
                result = malware_detector.analyze_file(temp_path, file.filename)
            
            # Clean up
            os.unlink(temp_path)
            
            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/api/scan_memory', methods=['POST'])
    def scan_memory():
        """
        Scan a file from memory for malware.
        
        Expected format:
        - POST request with 'data' field containing base64 encoded file data
        - Optional 'filename' field 
        
        Returns:
        - JSON with scan results
        """
        if not request.json or 'data' not in request.json:
            return jsonify({'error': 'No data provided'}), 400
        
        try:
            # Decode base64 data
            file_data = base64.b64decode(request.json['data'])
            filename = request.json.get('filename', 'memory_file')
            
            # Scan the data - check which method is available
            if hasattr(malware_detector, 'scan_memory_file'):
                # Use the scan_memory_file method if available
                result = malware_detector.scan_memory_file(file_data, filename)
            else:
                # Save to temp file and use analyze_file if scan_memory_file is not available
                temp_path = os.path.join(tempfile.gettempdir(), secure_filename(filename))
                with open(temp_path, 'wb') as f:
                    f.write(file_data)
                
                result = malware_detector.analyze_file(temp_path, filename)
                
                # Clean up
                os.unlink(temp_path)
            
            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        
    # Add steganography endpoints
    @flask_app.route('/api/steg/analyze', methods=['POST'])
    def analyze_steganography():
        """
        API endpoint to analyze files for hidden content using steganography
        """
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
            
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        # Save file to temp location
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            # Import steganalysis module here to avoid circular imports
            from steganalysis import analyze_stego
            
            # Analyze file for steganography
            results = analyze_stego(file_path)
            
            # Remove the temp file after analysis
            os.remove(file_path)
            
            return jsonify(results)
        except Exception as e:
            # Make sure to clean up on error
            if os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({'error': str(e)}), 500
    
    @flask_app.route('/api/threat/detect', methods=['POST'])
    def detect_threat():
        """
        API endpoint to detect threats in network traffic data
        """
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
            
        data = request.get_json()
        
        try:
            # Import the predict function from deploy
            from deploy import predict_attack
            
            # Predict the threat
            prediction, confidence = predict_attack(data)
            
            return jsonify({
                'prediction': prediction,
                'confidence': confidence
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @flask_app.route('/api/chat', methods=['POST'])
    def chat_api():
        """API endpoint for CyberBot chat interactions."""
        
        from app import cyberbot
        
        if cyberbot is None:
            return jsonify({
                'status': 'error',
                'message': 'CyberBot is not available. Please set the GROQ_API_KEY environment variable.'
            }), 503
        
        data = request.get_json()
        
        # Validate input
        if not data or 'query' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Query parameter is required'
            }), 400
        
        query = data['query']
        
        # Get model parameter if provided
        if 'model' in data and data['model']:
            cyberbot.set_model(data['model'])
        
        # Clear conversation if requested
        if data.get('clear_history', False):
            cyberbot.clear_conversation()
        
        # Get response from CyberBot
        try:
            response = cyberbot.get_security_response(query)
            return jsonify({
                'status': 'success',
                'query': query,
                'response': response
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': f'Error processing query: {str(e)}'
            }), 500
    
    # Return reference to the app for chaining
    return flask_app

# If this file is run directly, start the server
if __name__ == '__main__':
    # Create YARA rules directory if it doesn't exist
    os.makedirs('src/yara_rules', exist_ok=True)
    # Configure routes on the app
    configure_routes(app)
    # Run the app
    app.run(debug=True, host='0.0.0.0', port=5000) 