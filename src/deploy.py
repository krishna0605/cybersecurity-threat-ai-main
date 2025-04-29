from flask import Flask, request, jsonify, render_template_string, send_from_directory
import joblib
import pandas as pd
import numpy as np
import os
from steganalysis import SteganographyDetector
from malware_detection import MalwareDetector
import base64
import uuid
import werkzeug.utils

app = Flask(__name__)

# Create upload directory for temporary file storage
UPLOAD_FOLDER = 'temp_uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Load the trained model
model = joblib.load("models/threat_detector_rf.pkl")

# Initialize detectors
steg_detector = SteganographyDetector()
malware_detector = MalwareDetector()

# Get the exact feature order used during training
try:
    FEATURE_COLUMNS = list(model.feature_names_in_)
except AttributeError:
    # If feature_names_in_ is not available, create minimal required features
    FEATURE_COLUMNS = ['col_0', 'col_1', 'col_2', 'col_3', 'col_4', 
                     'col_5', 'col_6', 'col_7', 'col_8']

# HTML template for the web UI
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cybersecurity Threat Detection</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .container {
            background-color: #f9f9f9;
            border-radius: 5px;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .tab {
            padding: 10px 20px;
            background-color: #ddd;
            border: none;
            border-radius: 5px 5px 0 0;
            cursor: pointer;
            margin-right: 5px;
            margin-bottom: 5px;
        }
        .tab.active {
            background-color: #f9f9f9;
            font-weight: bold;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        label {
            display: block;
            margin-top: 10px;
            font-weight: bold;
        }
        input, select {
            width: 100%;
            padding: 8px;
            margin-top: 5px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 10px 15px;
            margin-top: 20px;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #2980b9;
        }
        .result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 4px;
        }
        .normal {
            background-color: #dff0d8;
            border: 1px solid #d6e9c6;
        }
        .threat {
            background-color: #f2dede;
            border: 1px solid #ebccd1;
        }
        .hidden {
            display: none;
        }
        .feature-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 10px;
        }
        .file-upload {
            margin-top: 20px;
            border: 2px dashed #3498db;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
        }
        .file-upload-input {
            display: none;
        }
        .file-upload-label {
            display: block;
            cursor: pointer;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .file-info {
            margin-top: 15px;
            font-style: italic;
        }
        .progress-bar {
            width: 100%;
            height: 20px;
            background-color: #f0f0f0;
            border-radius: 10px;
            margin-top: 10px;
            overflow: hidden;
        }
        .progress {
            width: 0%;
            height: 100%;
            background-color: #4CAF50;
            transition: width 0.3s;
        }
        .steg-results, .malware-results {
            margin-top: 20px;
        }
        .steg-results h3, .malware-results h3 {
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }
        .detection-method {
            margin-bottom: 15px;
            padding: 10px;
            background-color: #f5f5f5;
            border-radius: 4px;
        }
        .risk-indicator {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 15px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }
        .risk-none, .risk-minimal {
            background-color: #5cb85c;
        }
        .risk-low {
            background-color: #f0ad4e;
        }
        .risk-medium {
            background-color: #d9534f;
        }
        .risk-high {
            background-color: #d9534f;
        }
        .file-hash {
            font-family: monospace;
            word-break: break-all;
            background-color: #f5f5f5;
            padding: 5px;
            border-radius: 3px;
            font-size: 0.9em;
        }
        @media (max-width: 600px) {
            .feature-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Cybersecurity Threat Detection</h1>
        <p>AI-powered analysis to detect network threats, steganography, and malware</p>
    </div>
    
    <div class="tabs">
        <button class="tab active" onclick="openTab(event, 'network-tab')">Network Traffic Analysis</button>
        <button class="tab" onclick="openTab(event, 'steg-tab')">Steganography Detection</button>
        <button class="tab" onclick="openTab(event, 'malware-tab')">Malware Detection</button>
    </div>
    
    <div id="network-tab" class="tab-content active">
        <div class="container">
            <h2>Network Traffic Analysis</h2>
            <p>Enter the network connection features below to analyze for security threats.</p>
            
            <form id="detection-form">
                <div class="feature-grid">
                    <div>
                        <label for="duration">Duration (seconds):</label>
                        <input type="number" id="duration" name="duration" value="0" min="0">
                    </div>
                    
                    <div>
                        <label for="protocol_type">Protocol Type:</label>
                        <select id="protocol_type" name="protocol_type">
                            <option value="0">TCP</option>
                            <option value="1" selected>UDP</option>
                            <option value="2">ICMP</option>
                        </select>
                    </div>
                    
                    <div>
                        <label for="service">Service Type:</label>
                        <input type="number" id="service" name="service" value="2" min="0" max="69">
                    </div>
                    
                    <div>
                        <label for="flag">Connection Flag:</label>
                        <select id="flag" name="flag">
                            <option value="0" selected>Normal</option>
                            <option value="1">Error</option>
                        </select>
                    </div>
                    
                    <div>
                        <label for="src_bytes">Source Bytes:</label>
                        <input type="number" id="src_bytes" name="src_bytes" value="491" min="0">
                    </div>
                    
                    <div>
                        <label for="dst_bytes">Destination Bytes:</label>
                        <input type="number" id="dst_bytes" name="dst_bytes" value="0" min="0">
                    </div>
                </div>
                
                <button type="submit">Analyze Traffic</button>
            </form>
            
            <div id="result" class="result hidden"></div>
        </div>
    </div>
    
    <div id="steg-tab" class="tab-content">
        <div class="container">
            <h2>Steganography Detection</h2>
            <p>Upload an image or PDF file to detect hidden content or malicious code.</p>
            
            <div class="file-upload">
                <input type="file" id="file-upload-steg" class="file-upload-input" accept=".jpg,.jpeg,.png,.gif,.bmp,.tiff,.pdf">
                <label for="file-upload-steg" class="file-upload-label">Click to select a file or drag and drop</label>
                <p>Supported formats: JPG, PNG, GIF, BMP, TIFF, PDF</p>
                <div id="file-info-steg" class="file-info hidden"></div>
                <div id="progress-container-steg" class="hidden">
                    <div class="progress-bar">
                        <div id="progress-steg" class="progress"></div>
                    </div>
                </div>
                <button id="analyze-btn-steg" disabled>Analyze File</button>
            </div>
            
            <div id="steg-result" class="steg-results hidden"></div>
        </div>
    </div>
    
    <div id="malware-tab" class="tab-content">
        <div class="container">
            <h2>Malware Detection</h2>
            <p>Upload a file to scan for potential malware and security threats.</p>
            
            <div class="file-upload">
                <input type="file" id="file-upload-malware" class="file-upload-input">
                <label for="file-upload-malware" class="file-upload-label">Click to select a file or drag and drop</label>
                <p>Supported formats: EXE, DLL, PDF, Office documents, Archives, Scripts, and more</p>
                <div id="file-info-malware" class="file-info hidden"></div>
                <div id="progress-container-malware" class="hidden">
                    <div class="progress-bar">
                        <div id="progress-malware" class="progress"></div>
                    </div>
                </div>
                <button id="analyze-btn-malware" disabled>Scan for Malware</button>
            </div>
            
            <div id="malware-result" class="malware-results hidden"></div>
        </div>
    </div>
    
    <script>
        // Tab functionality
        function openTab(evt, tabName) {
            // Hide all tab content
            var tabcontent = document.getElementsByClassName("tab-content");
            for (var i = 0; i < tabcontent.length; i++) {
                tabcontent[i].className = tabcontent[i].className.replace(" active", "");
            }
            
            // Remove "active" class from all tabs
            var tabs = document.getElementsByClassName("tab");
            for (var i = 0; i < tabs.length; i++) {
                tabs[i].className = tabs[i].className.replace(" active", "");
            }
            
            // Show the current tab and add "active" class
            document.getElementById(tabName).className += " active";
            evt.currentTarget.className += " active";
        }
        
        // Network traffic analysis form submission
        document.getElementById('detection-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            // Get form values
            const formData = {
                col_0: parseInt(document.getElementById('duration').value) || 0,
                col_1: parseInt(document.getElementById('protocol_type').value) || 0,
                col_2: parseInt(document.getElementById('service').value) || 0,
                col_3: parseInt(document.getElementById('flag').value) || 0,
                col_4: parseInt(document.getElementById('src_bytes').value) || 0,
                col_5: parseInt(document.getElementById('dst_bytes').value) || 0,
                col_6: 0, // land
                col_7: 0, // wrong_fragment
                col_8: 0  // urgent
            };
            
            // Add remaining features with default values
            for (let i = 9; i <= 40; i++) {
                formData[`col_${i}`] = 0;
            }
            
            // Send data to API
            try {
                const response = await fetch('/predict', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(formData)
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    // Display result
                    const resultDiv = document.getElementById('result');
                    resultDiv.classList.remove('hidden', 'normal', 'threat');
                    
                    const prediction = result.prediction[0];
                    const confidence = result.confidence[0];
                    
                    // Map numerical prediction to string if needed
                    let predictionText = prediction;
                    if (typeof prediction === 'number') {
                        const attackTypes = {
                            0: 'normal',
                            1: 'dos (Denial of Service)',
                            2: 'probe (Surveillance/Scanning)',
                            3: 'r2l (Remote to Local Attack)',
                            4: 'u2r (User to Root Attack)'
                        };
                        predictionText = attackTypes[prediction] || prediction;
                    }
                    
                    // Set result class based on prediction
                    resultDiv.classList.add(predictionText === 'normal' ? 'normal' : 'threat');
                    
                    resultDiv.innerHTML = `
                        <h3>Traffic Analysis Result</h3>
                        <p><strong>Prediction:</strong> ${predictionText}</p>
                        <p><strong>Confidence:</strong> ${(confidence * 100).toFixed(2)}%</p>
                    `;
                } else {
                    // Display error
                    const resultDiv = document.getElementById('result');
                    resultDiv.classList.remove('hidden', 'normal');
                    resultDiv.classList.add('threat');
                    resultDiv.innerHTML = `<h3>Error</h3><p>${result.error || 'Unknown error occurred'}</p>`;
                }
            } catch (error) {
                console.error('Error:', error);
                const resultDiv = document.getElementById('result');
                resultDiv.classList.remove('hidden', 'normal');
                resultDiv.classList.add('threat');
                resultDiv.innerHTML = `<h3>Error</h3><p>Failed to communicate with the API server</p>`;
            }
        });
        
        // File upload handling for Steganography
        const fileInputSteg = document.getElementById('file-upload-steg');
        const fileInfoSteg = document.getElementById('file-info-steg');
        const analyzeBtnSteg = document.getElementById('analyze-btn-steg');
        const progressContainerSteg = document.getElementById('progress-container-steg');
        const progressBarSteg = document.getElementById('progress-steg');
        const stegResult = document.getElementById('steg-result');
        
        // File upload handling for Malware Detection
        const fileInputMalware = document.getElementById('file-upload-malware');
        const fileInfoMalware = document.getElementById('file-info-malware');
        const analyzeBtnMalware = document.getElementById('analyze-btn-malware');
        const progressContainerMalware = document.getElementById('progress-container-malware');
        const progressBarMalware = document.getElementById('progress-malware');
        const malwareResult = document.getElementById('malware-result');
        
        // File drop functionality for all file upload areas
        const fileUploadAreas = document.querySelectorAll('.file-upload');
        
        fileUploadAreas.forEach(area => {
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                area.addEventListener(eventName, preventDefaults, false);
            });
            
            ['dragenter', 'dragover'].forEach(eventName => {
                area.addEventListener(eventName, () => highlight(area), false);
            });
            
            ['dragleave', 'drop'].forEach(eventName => {
                area.addEventListener(eventName, () => unhighlight(area), false);
            });
            
            area.addEventListener('drop', (e) => handleDrop(e, area), false);
        });
        
        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }
        
        function highlight(area) {
            area.style.borderColor = '#2980b9';
            area.style.backgroundColor = '#f0f8ff';
        }
        
        function unhighlight(area) {
            area.style.borderColor = '#3498db';
            area.style.backgroundColor = '';
        }
        
        function handleDrop(e, area) {
            const dt = e.dataTransfer;
            const files = dt.files;
            
            if (files.length > 0) {
                if (area.querySelector('input').id === 'file-upload-steg') {
                    fileInputSteg.files = files;
                    handleFileSelectSteg();
                } else if (area.querySelector('input').id === 'file-upload-malware') {
                    fileInputMalware.files = files;
                    handleFileSelectMalware();
                }
            }
        }
        
        // Handle file selection for Steganography
        fileInputSteg.addEventListener('change', handleFileSelectSteg);
        
        function handleFileSelectSteg() {
            if (fileInputSteg.files.length > 0) {
                const file = fileInputSteg.files[0];
                const fileSizeMB = (file.size / (1024 * 1024)).toFixed(2);
                
                // Check file size
                if (file.size > 16 * 1024 * 1024) { // 16MB limit
                    fileInfoSteg.innerHTML = `<span style="color: red;">File too large: ${fileSizeMB}MB (max 16MB)</span>`;
                    fileInfoSteg.classList.remove('hidden');
                    analyzeBtnSteg.disabled = true;
                    return;
                }
                
                // Display file info
                fileInfoSteg.innerHTML = `${file.name} (${fileSizeMB}MB)`;
                fileInfoSteg.classList.remove('hidden');
                analyzeBtnSteg.disabled = false;
                
                // Reset previous results
                stegResult.innerHTML = '';
                stegResult.classList.add('hidden');
                progressContainerSteg.classList.add('hidden');
                progressBarSteg.style.width = '0%';
            }
        }
        
        // Handle file selection for Malware Detection
        fileInputMalware.addEventListener('change', handleFileSelectMalware);
        
        function handleFileSelectMalware() {
            if (fileInputMalware.files.length > 0) {
                const file = fileInputMalware.files[0];
                const fileSizeMB = (file.size / (1024 * 1024)).toFixed(2);
                
                // Check file size
                if (file.size > 16 * 1024 * 1024) { // 16MB limit
                    fileInfoMalware.innerHTML = `<span style="color: red;">File too large: ${fileSizeMB}MB (max 16MB)</span>`;
                    fileInfoMalware.classList.remove('hidden');
                    analyzeBtnMalware.disabled = true;
                    return;
                }
                
                // Display file info
                fileInfoMalware.innerHTML = `${file.name} (${fileSizeMB}MB)`;
                fileInfoMalware.classList.remove('hidden');
                analyzeBtnMalware.disabled = false;
                
                // Reset previous results
                malwareResult.innerHTML = '';
                malwareResult.classList.add('hidden');
                progressContainerMalware.classList.add('hidden');
                progressBarMalware.style.width = '0%';
            }
        }
        
        // Steganography file analysis button
        analyzeBtnSteg.addEventListener('click', analyzeFileSteg);
        
        async function analyzeFileSteg() {
            if (fileInputSteg.files.length === 0) return;
            
            const file = fileInputSteg.files[0];
            const formData = new FormData();
            formData.append('file', file);
            
            // Show progress
            progressContainerSteg.classList.remove('hidden');
            analyzeBtnSteg.disabled = true;
            
            try {
                // Simulate progress (actual progress events not reliable for small files)
                let progress = 0;
                const progressInterval = setInterval(() => {
                    progress += 5;
                    if (progress > 90) {
                        clearInterval(progressInterval);
                    }
                    progressBarSteg.style.width = progress + '%';
                }, 100);
                
                // Send file to API
                const response = await fetch('/analyze-steg', {
                    method: 'POST',
                    body: formData
                });
                
                clearInterval(progressInterval);
                progressBarSteg.style.width = '100%';
                
                const result = await response.json();
                
                // Display results
                if (response.ok) {
                    displayStegResults(result);
                } else {
                    stegResult.innerHTML = `
                        <div class="threat">
                            <h3>Error</h3>
                            <p>${result.message || 'Unknown error occurred'}</p>
                        </div>
                    `;
                    stegResult.classList.remove('hidden');
                }
            } catch (error) {
                console.error('Error:', error);
                stegResult.innerHTML = `
                    <div class="threat">
                        <h3>Error</h3>
                        <p>Failed to communicate with the API server</p>
                    </div>
                `;
                stegResult.classList.remove('hidden');
            } finally {
                analyzeBtnSteg.disabled = false;
            }
        }
        
        // Malware detection file analysis button
        analyzeBtnMalware.addEventListener('click', analyzeFileMalware);
        
        async function analyzeFileMalware() {
            if (fileInputMalware.files.length === 0) return;
            
            const file = fileInputMalware.files[0];
            const formData = new FormData();
            formData.append('file', file);
            
            // Show progress
            progressContainerMalware.classList.remove('hidden');
            analyzeBtnMalware.disabled = true;
            
            try {
                // Simulate progress
                let progress = 0;
                const progressInterval = setInterval(() => {
                    progress += 5;
                    if (progress > 90) {
                        clearInterval(progressInterval);
                    }
                    progressBarMalware.style.width = progress + '%';
                }, 100);
                
                // Send file to API
                const response = await fetch('/analyze-malware', {
                    method: 'POST',
                    body: formData
                });
                
                clearInterval(progressInterval);
                progressBarMalware.style.width = '100%';
                
                const result = await response.json();
                
                // Display results
                if (response.ok) {
                    displayMalwareResults(result);
                } else {
                    malwareResult.innerHTML = `
                        <div class="threat">
                            <h3>Error</h3>
                            <p>${result.message || 'Unknown error occurred'}</p>
                        </div>
                    `;
                    malwareResult.classList.remove('hidden');
                }
            } catch (error) {
                console.error('Error:', error);
                malwareResult.innerHTML = `
                    <div class="threat">
                        <h3>Error</h3>
                        <p>Failed to communicate with the API server</p>
                    </div>
                `;
                malwareResult.classList.remove('hidden');
            } finally {
                analyzeBtnMalware.disabled = false;
            }
        }
        
        function displayStegResults(result) {
            // Build results HTML
            let html = '';
            
            if (result.status === 'error') {
                html = `
                    <div class="threat">
                        <h3>Error</h3>
                        <p>${result.message}</p>
                    </div>
                `;
            } else {
                // Create risk level indicator
                let riskClass = 'risk-none';
                if (result.threat_level === 'high') {
                    riskClass = 'risk-high';
                } else if (result.threat_level === 'medium') {
                    riskClass = 'risk-medium';
                } else if (result.threat_level === 'low') {
                    riskClass = 'risk-low';
                }
                
                html = `
                    <h3>Steganography Analysis Results</h3>
                    <div>
                        <p><strong>File:</strong> ${result.filename}</p>
                        <p><strong>Type:</strong> ${result.file_type}</p>
                        ${result.format ? `<p><strong>Format:</strong> ${result.format}</p>` : ''}
                        ${result.dimensions ? `<p><strong>Dimensions:</strong> ${result.dimensions}</p>` : ''}
                        <p><strong>Size:</strong> ${(result.size_bytes / 1024).toFixed(2)} KB</p>
                        <p>
                            <strong>Risk Score:</strong> 
                            <span class="risk-indicator ${riskClass}">${result.risk_score.toFixed(0)}%</span>
                            (${result.threat_level.toUpperCase()})
                        </p>
                    </div>
                `;
                
                // Add detected anomalies if any
                if (result.anomalies_detected && result.anomalies_detected.length > 0) {
                    html += `
                        <div class="threat" style="margin-top: 15px;">
                            <h3>Anomalies Detected</h3>
                            <ul>
                                ${result.anomalies_detected.map(anomaly => `<li>${anomaly}</li>`).join('')}
                            </ul>
                        </div>
                    `;
                }
                
                // Add detection methods details
                if (result.detection_methods && result.detection_methods.length > 0) {
                    html += `<h3>Detection Details</h3>`;
                    
                    result.detection_methods.forEach(method => {
                        html += `
                            <div class="detection-method">
                                <h4>${method.name}</h4>
                                <p>${method.description}</p>
                                <p><strong>Details:</strong> ${method.details}</p>
                            </div>
                        `;
                    });
                }
            }
            
            stegResult.innerHTML = html;
            stegResult.classList.remove('hidden');
        }
        
        function displayMalwareResults(result) {
            // Build results HTML
            let html = '';
            
            if (result.status === 'error') {
                html = `
                    <div class="threat">
                        <h3>Error</h3>
                        <p>${result.message}</p>
                    </div>
                `;
            } else {
                // Create risk level indicator
                let riskClass = 'risk-minimal';
                if (result.threat_level === 'high') {
                    riskClass = 'risk-high';
                } else if (result.threat_level === 'medium') {
                    riskClass = 'risk-medium';
                } else if (result.threat_level === 'low') {
                    riskClass = 'risk-low';
                }
                
                html = `
                    <h3>Malware Analysis Results</h3>
                    <div>
                        <p><strong>File:</strong> ${result.filename}</p>
                        <p><strong>Type:</strong> ${result.file_type}</p>
                        <p><strong>Size:</strong> ${(result.size_bytes / 1024).toFixed(2)} KB</p>
                        <p><strong>MD5 Hash:</strong> <span class="file-hash">${result.md5}</span></p>
                        <p><strong>SHA1 Hash:</strong> <span class="file-hash">${result.sha1}</span></p>
                        <p>
                            <strong>Risk Score:</strong> 
                            <span class="risk-indicator ${riskClass}">${result.risk_score.toFixed(0)}%</span>
                            (${result.threat_level.toUpperCase()})
                        </p>
                    </div>
                `;
                
                // Add detected malicious indicators if any
                if (result.malicious_indicators && result.malicious_indicators.length > 0) {
                    html += `
                        <div class="threat" style="margin-top: 15px;">
                            <h3>Malicious Indicators</h3>
                            <ul>
                                ${result.malicious_indicators.map(indicator => `<li>${indicator}</li>`).join('')}
                            </ul>
                        </div>
                    `;
                }
                
                // Add detection methods details
                if (result.detection_methods && result.detection_methods.length > 0) {
                    html += `<h3>Detection Details</h3>`;
                    
                    result.detection_methods.forEach(method => {
                        html += `
                            <div class="detection-method">
                                <h4>${method.name}</h4>
                                <p>${method.description}</p>
                                <p><strong>Details:</strong> ${method.details}</p>
                            </div>
                        `;
                    });
                }
            }
            
            malwareResult.innerHTML = html;
            malwareResult.classList.remove('hidden');
        }
    </script>
</body>
</html>
"""

# Add a root route for testing
@app.route('/', methods=['GET'])
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api-status', methods=['GET'])
def api_status():
    return jsonify({
        "status": "API is running",
        "usage": "Send POST request to /predict with network traffic features",
        "required_features": FEATURE_COLUMNS
    })

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get input JSON data from the POST request
        input_data = request.get_json()
        
        if input_data is None:
            return jsonify({"error": "No input data provided. Please send JSON data."}), 400

        # Convert to DataFrame
        input_df = pd.DataFrame([input_data]) if isinstance(input_data, dict) else pd.DataFrame(input_data)
        
        # Check if we have all the required columns
        missing_cols = [col for col in FEATURE_COLUMNS if col not in input_df.columns]
        if missing_cols:
            # Fill in missing columns with zeros
            for col in missing_cols:
                input_df[col] = 0
        
        # Only use columns that are expected by the model
        try:
            input_df = input_df[FEATURE_COLUMNS]
        except KeyError as e:
            return jsonify({"error": f"Missing required column: {str(e)}. Required columns: {FEATURE_COLUMNS}"}), 400
            
        input_df.columns.name = None  # Clear index name if it exists

        # Make prediction and get probabilities
        prediction = model.predict(input_df)
        confidence = model.predict_proba(input_df).max(axis=1)

        # Return both prediction and confidence
        return jsonify({
            "prediction": prediction.tolist(),
            "confidence": confidence.tolist()
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/analyze-steg', methods=['POST'])
def analyze_steganography():
    """Analyze uploaded file for steganography"""
    try:
        # Check if file is present in request
        if 'file' not in request.files:
            return jsonify({
                "status": "error",
                "message": "No file provided"
            }), 400
        
        file = request.files['file']
        
        # Check if filename is empty
        if file.filename == '':
            return jsonify({
                "status": "error",
                "message": "No file selected"
            }), 400
        
        # Verify file type is supported
        if not steg_detector.is_supported_file(file.filename):
            return jsonify({
                "status": "error",
                "message": f"Unsupported file type: {os.path.splitext(file.filename)[1]}",
                "supported_formats": steg_detector.supported_formats
            }), 400
        
        # Create a safe filename
        filename = werkzeug.utils.secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the file temporarily
        file.save(file_path)
        
        # Read file data
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Delete the temporary file
        os.remove(file_path)
        
        # Analyze file for steganography
        result = steg_detector.analyze_file(file_data, filename)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error processing file: {str(e)}"
        }), 500

@app.route('/analyze-malware', methods=['POST'])
def analyze_malware():
    """Analyze uploaded file for potential malware"""
    try:
        # Check if file is present in request
        if 'file' not in request.files:
            return jsonify({
                "status": "error",
                "message": "No file provided"
            }), 400
        
        file = request.files['file']
        
        # Check if filename is empty
        if file.filename == '':
            return jsonify({
                "status": "error",
                "message": "No file selected"
            }), 400
        
        # Create a safe filename
        filename = werkzeug.utils.secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the file temporarily
        file.save(file_path)
        
        # Read file data
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Delete the temporary file
        os.remove(file_path)
        
        # Analyze file for malware
        result = malware_detector.analyze_file(file_data, filename)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error processing file: {str(e)}"
        }), 500

# Run the Flask app
if __name__ == "__main__":
    print(f"API server starting with web UI. Available at:")
    print(f"- http://127.0.0.1:5000")
    print(f"- http://localhost:5000")
    print(f"Required input features: {FEATURE_COLUMNS}")
    app.run(debug=True, host='0.0.0.0')

 
