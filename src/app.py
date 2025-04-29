from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import sys
import traceback

# Initialize Flask app with templates directory
app = Flask(__name__, template_folder='templates')

# Create directories for uploads and YARA rules
os.makedirs('temp_uploads', exist_ok=True)
os.makedirs('src/yara_rules', exist_ok=True)

# Flag to track if full functionality is available
HAS_DEPENDENCIES = False
ERROR_MESSAGE = ""

# Try to import dependencies, but handle missing ones gracefully
try:
    from malware_detection import malware_detector
    from api import configure_routes
    # Import API routes and configure them on our app
    configure_routes(app)
    HAS_DEPENDENCIES = True
except Exception as e:
    ERROR_MESSAGE = str(e)
    print(f"Warning: Some dependencies are missing: {e}")
    traceback.print_exc()
    
    # Define placeholder API routes that return "not available" messages
    @app.route('/api/analyze', methods=['POST'])
    @app.route('/api/scan_file', methods=['POST'])
    @app.route('/api/scan_memory', methods=['POST'])
    @app.route('/api/yara/add', methods=['POST'])
    @app.route('/api/steg/analyze', methods=['POST'])
    @app.route('/api/threat/detect', methods=['POST'])
    def api_not_available():
        return jsonify({
            "error": "This functionality is not available in the demo deployment",
            "message": "The full functionality requires additional dependencies that aren't supported in this deployment environment."
        }), 503
    
    @app.route('/api/status', methods=['GET'])
    def get_status():
        return jsonify({
            'status': 'limited',
            'version': '1.0.0',
            'message': 'Running in demo mode with limited functionality'
        })

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

# Add a route to handle health checks and deployment verification
@app.route('/api/health')
def health_check():
    """Health check endpoint for Vercel deployment verification"""
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    
    deps = []
    try:
        import flask
        deps.append(f"flask=={flask.__version__}")
    except:
        pass
    
    try:
        import numpy
        deps.append(f"numpy=={numpy.__version__}")
    except:
        pass
    
    try:
        import pandas
        deps.append(f"pandas=={pandas.__version__}")
    except:
        pass
    
    return jsonify({
        "status": "operational",
        "mode": "demo" if not HAS_DEPENDENCIES else "full",
        "python_version": python_version,
        "dependencies_loaded": deps,
        "error": ERROR_MESSAGE,
        "environment": os.environ.get("VERCEL_ENV", "development")
    })

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000) 