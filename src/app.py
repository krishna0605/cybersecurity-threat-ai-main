from flask import Flask, render_template, jsonify
import os
import sys

app = Flask(__name__, template_folder='templates')

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

if __name__ == '__main__':
    app.run(debug=True) 