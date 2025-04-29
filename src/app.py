from flask import Flask, request, jsonify, render_template, send_from_directory
import os
from malware_detection import malware_detector
from api import configure_routes

# Initialize Flask app with templates directory
app = Flask(__name__, template_folder='templates')

# Create directories for uploads and YARA rules
os.makedirs('temp_uploads', exist_ok=True)
os.makedirs('src/yara_rules', exist_ok=True)

# Import API routes and configure them on our app
configure_routes(app)

@app.route('/')
def index():
    """Main landing page with links to all features"""
    return render_template('index.html')

@app.route('/malware-scan')
def malware_scan():
    """Render the malware scanning interface."""
    return render_template('malware_scan.html')

@app.route('/steganalysis')
def steganalysis():
    """Render the steganography analysis interface."""
    return render_template('steganalysis.html')

@app.route('/threat-detection')
def threat_detection():
    """Render the threat detection interface."""
    return render_template('threat_detection.html')

@app.route('/documentation')
def documentation():
    """Render the API documentation."""
    return render_template('documentation.html')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000) 