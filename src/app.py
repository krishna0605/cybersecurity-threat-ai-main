from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import sys

# Initialize Flask app with templates directory
app = Flask(__name__, template_folder='templates')

# Create directories for uploads and YARA rules
os.makedirs('temp_uploads', exist_ok=True)
os.makedirs('src/yara_rules', exist_ok=True)

# Try to import dependencies, but handle missing ones gracefully
try:
    from malware_detection import malware_detector
    from api import configure_routes
    # Import API routes and configure them on our app
    configure_routes(app)
    HAS_DEPENDENCIES = True
except ImportError as e:
    print(f"Warning: Some dependencies are missing: {e}")
    HAS_DEPENDENCIES = False

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
    
    return jsonify({
        "status": "operational",
        "python_version": python_version,
        "dependencies_loaded": HAS_DEPENDENCIES,
        "environment": os.environ.get("VERCEL_ENV", "development")
    })

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000) 