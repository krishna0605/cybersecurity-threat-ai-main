"""
Steganography Detection Module

This module provides functions to detect hidden content in images and PDF files
which could be used for data exfiltration or delivering malicious payloads.
"""

import os
import numpy as np
import io
import re
import math
import hashlib
from PIL import Image

class SteganographyDetector:
    """Class for detecting steganography in various file types"""
    
    def __init__(self):
        self.results = {}
        self.supported_formats = {
            'images': ['.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff'],
            'documents': ['.pdf']
        }
        
    def is_supported_file(self, filename):
        """Check if the file is supported for steganalysis"""
        ext = os.path.splitext(filename)[1].lower()
        for format_list in self.supported_formats.values():
            if ext in format_list:
                return True
        return False
    
    def get_file_type(self, filename):
        """Determine the type of file for appropriate analysis"""
        ext = os.path.splitext(filename)[1].lower()
        
        for file_type, formats in self.supported_formats.items():
            if ext in formats:
                return file_type
                
        return "unknown"
    
    def analyze_file(self, file_data, filename):
        """Analyze a file for possible steganography"""
        file_type = self.get_file_type(filename)
        
        if file_type == "images":
            return self.analyze_image(file_data, filename)
        elif file_type == "documents" and filename.lower().endswith('.pdf'):
            return self.analyze_pdf(file_data, filename)
        else:
            return {
                "status": "error",
                "message": f"Unsupported file type: {os.path.splitext(filename)[1]}",
                "supported_formats": self.supported_formats
            }
    
    def analyze_image(self, file_data, filename):
        """Analyze image for steganography techniques"""
        try:
            # Open image from binary data
            img = Image.open(io.BytesIO(file_data))
            
            # Get image info
            width, height = img.size
            format = img.format
            mode = img.mode
            
            # Convert to numpy array for analysis
            img_array = np.array(img)
            
            results = {
                "filename": filename,
                "file_type": "image",
                "format": format,
                "dimensions": f"{width}x{height}",
                "mode": mode,
                "size_bytes": len(file_data),
                "anomalies_detected": [],
                "risk_score": 0,
                "detection_methods": []
            }
            
            # Run various detection methods
            
            # 1. LSB (Least Significant Bit) analysis
            lsb_result = self._detect_lsb_anomalies(img_array)
            if lsb_result["detected"]:
                results["anomalies_detected"].append("LSB steganography")
                results["risk_score"] += lsb_result["confidence"] * 30
                results["detection_methods"].append({
                    "name": "LSB Analysis",
                    "description": "Analyzes the least significant bits of pixel values",
                    "details": lsb_result["details"]
                })
            
            # 2. Check file size inconsistencies
            size_result = self._check_file_size_anomalies(img, len(file_data))
            if size_result["detected"]:
                results["anomalies_detected"].append("File size anomaly")
                results["risk_score"] += size_result["confidence"] * 20
                results["detection_methods"].append({
                    "name": "File Size Analysis",
                    "description": "Checks for unusual file size relative to dimensions",
                    "details": size_result["details"]
                })
            
            # 3. Statistical analysis
            stat_result = self._statistical_analysis(img_array)
            if stat_result["detected"]:
                results["anomalies_detected"].append("Statistical anomaly")
                results["risk_score"] += stat_result["confidence"] * 25
                results["detection_methods"].append({
                    "name": "Statistical Analysis",
                    "description": "Analyzes pixel value distributions",
                    "details": stat_result["details"]
                })
            
            # Calculate overall score
            results["risk_score"] = min(100, results["risk_score"])
            
            # Set threat level
            if results["risk_score"] >= 70:
                results["threat_level"] = "high"
            elif results["risk_score"] >= 40:
                results["threat_level"] = "medium"
            elif results["risk_score"] > 10:
                results["threat_level"] = "low"
            else:
                results["threat_level"] = "none"
                
            return results
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error analyzing image: {str(e)}"
            }
    
    def analyze_pdf(self, file_data, filename):
        """Analyze PDF for steganography techniques"""
        try:
            # Basic PDF analysis without requiring PyPDF2
            # Looking for specific patterns that might indicate hidden content
            
            results = {
                "filename": filename,
                "file_type": "pdf",
                "size_bytes": len(file_data),
                "anomalies_detected": [],
                "risk_score": 0,
                "detection_methods": []
            }
            
            # Convert bytes to string for regex pattern matching
            # Note: This is a simplified approach; real PDF analysis would be more complex
            pdf_content = file_data.decode('latin-1', errors='ignore')
            
            # 1. Check for JavaScript
            js_result = self._detect_js_in_pdf(pdf_content)
            if js_result["detected"]:
                results["anomalies_detected"].append("JavaScript in PDF")
                results["risk_score"] += js_result["confidence"] * 40
                results["detection_methods"].append({
                    "name": "JavaScript Detection",
                    "description": "Checks for JavaScript code that could hide payloads",
                    "details": js_result["details"]
                })
            
            # 2. Check for unusual embedded objects
            obj_result = self._detect_unusual_objects(pdf_content)
            if obj_result["detected"]:
                results["anomalies_detected"].append("Unusual embedded objects")
                results["risk_score"] += obj_result["confidence"] * 30
                results["detection_methods"].append({
                    "name": "Embedded Object Analysis",
                    "description": "Detects unusual embedded objects that could contain hidden data",
                    "details": obj_result["details"]
                })
            
            # 3. Check entropy
            entropy_result = self._check_entropy(file_data)
            if entropy_result["detected"]:
                results["anomalies_detected"].append("High entropy regions")
                results["risk_score"] += entropy_result["confidence"] * 20
                results["detection_methods"].append({
                    "name": "Entropy Analysis",
                    "description": "Identifies high-entropy sections that may contain encrypted data",
                    "details": entropy_result["details"]
                })
            
            # Calculate overall score
            results["risk_score"] = min(100, results["risk_score"])
            
            # Set threat level
            if results["risk_score"] >= 70:
                results["threat_level"] = "high"
            elif results["risk_score"] >= 40:
                results["threat_level"] = "medium"
            elif results["risk_score"] > 10:
                results["threat_level"] = "low"
            else:
                results["threat_level"] = "none"
                
            return results
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error analyzing PDF: {str(e)}"
            }
    
    def _detect_lsb_anomalies(self, img_array):
        """Detect anomalies in least significant bits of image pixels"""
        try:
            # For simplicity, we'll just analyze a sample of the image
            if len(img_array.shape) < 3:  # Grayscale
                bit_plane = img_array & 1  # Get LSB
                lsb_count = np.sum(bit_plane)
                expected = img_array.size / 2  # Expected 50% 1s for random data
                deviation = abs(lsb_count - expected) / expected
                
                details = f"LSB ones: {lsb_count}, Expected: {expected:.1f}, Deviation: {deviation:.2f}"
                confidence = min(1.0, deviation * 2)  # Scale deviation to confidence
                
                return {
                    "detected": deviation > 0.1,  # Threshold for significant deviation
                    "confidence": confidence,
                    "details": details
                }
            else:  # Color image
                channels = []
                if img_array.shape[2] >= 3:  # RGB or RGBA
                    channels = [0, 1, 2]  # R, G, B channels
                
                total_deviation = 0
                details = []
                
                for ch in channels:
                    bit_plane = img_array[:, :, ch] & 1  # Get LSB
                    lsb_count = np.sum(bit_plane)
                    expected = bit_plane.size / 2
                    deviation = abs(lsb_count - expected) / expected
                    total_deviation += deviation
                    details.append(f"Channel {ch} LSB ones: {lsb_count}, Expected: {expected:.1f}, Deviation: {deviation:.2f}")
                
                avg_deviation = total_deviation / len(channels)
                confidence = min(1.0, avg_deviation * 2)
                
                return {
                    "detected": avg_deviation > 0.1,
                    "confidence": confidence,
                    "details": " | ".join(details)
                }
        except:
            return {"detected": False, "confidence": 0, "details": "LSB analysis failed"}
    
    def _check_file_size_anomalies(self, img, file_size):
        """Check if file size is unusual for the image dimensions"""
        try:
            width, height = img.size
            pixel_count = width * height
            bytes_per_pixel = file_size / pixel_count
            
            # Typical ranges for bytes per pixel
            if img.mode == "RGB":
                expected_range = (2.5, 4.5)  # Expected range for RGB
            elif img.mode == "RGBA":
                expected_range = (3.0, 5.0)  # Expected range for RGBA
            else:
                expected_range = (1.0, 3.0)  # Expected range for other modes
            
            too_small = bytes_per_pixel < expected_range[0]
            too_large = bytes_per_pixel > expected_range[1]
            
            details = f"Bytes per pixel: {bytes_per_pixel:.2f}, Expected range: {expected_range[0]:.1f}-{expected_range[1]:.1f}"
            
            if too_large:
                confidence = min(1.0, (bytes_per_pixel - expected_range[1]) / expected_range[1])
                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": f"{details} - File is larger than expected"
                }
            elif too_small:
                confidence = min(1.0, (expected_range[0] - bytes_per_pixel) / expected_range[0])
                return {
                    "detected": True,
                    "confidence": confidence,
                    "details": f"{details} - File is smaller than expected"
                }
            else:
                return {
                    "detected": False,
                    "confidence": 0,
                    "details": details
                }
        except:
            return {"detected": False, "confidence": 0, "details": "File size analysis failed"}
    
    def _statistical_analysis(self, img_array):
        """Perform statistical analysis on pixel values"""
        try:
            # For simplicity, check if histogram is unusual
            if len(img_array.shape) < 3:  # Grayscale
                hist, _ = np.histogram(img_array, bins=256, range=(0, 256))
                hist = hist / np.sum(hist)  # Normalize
                entropy = -np.sum(hist * np.log2(hist + 1e-10))  # Calculate entropy
                
                # Check for unusual entropy (too high or too low)
                if entropy > 7.9:  # Very high entropy (close to 8, maximum for 8-bit values)
                    return {
                        "detected": True,
                        "confidence": min(1.0, (entropy - 7.9) * 10),
                        "details": f"Unusually high entropy: {entropy:.2f}/8.0"
                    }
                elif entropy < 7.0:  # Unusually low entropy for natural images
                    return {
                        "detected": True,
                        "confidence": min(1.0, (7.0 - entropy) / 3.0),
                        "details": f"Unusually low entropy: {entropy:.2f}/8.0"
                    }
                else:
                    return {
                        "detected": False,
                        "confidence": 0,
                        "details": f"Normal entropy: {entropy:.2f}/8.0"
                    }
            else:  # Color image
                channels = []
                if img_array.shape[2] >= 3:
                    channels = [0, 1, 2]  # RGB channels
                
                channel_results = []
                detected = False
                max_confidence = 0
                
                for ch in channels:
                    hist, _ = np.histogram(img_array[:, :, ch], bins=256, range=(0, 256))
                    hist = hist / np.sum(hist)
                    entropy = -np.sum(hist * np.log2(hist + 1e-10))
                    
                    if entropy > 7.9:
                        confidence = min(1.0, (entropy - 7.9) * 10)
                        channel_results.append(f"Channel {ch}: High entropy {entropy:.2f}/8.0")
                        detected = True
                        max_confidence = max(max_confidence, confidence)
                    elif entropy < 7.0:
                        confidence = min(1.0, (7.0 - entropy) / 3.0)
                        channel_results.append(f"Channel {ch}: Low entropy {entropy:.2f}/8.0")
                        detected = True
                        max_confidence = max(max_confidence, confidence)
                    else:
                        channel_results.append(f"Channel {ch}: Normal entropy {entropy:.2f}/8.0")
                
                return {
                    "detected": detected,
                    "confidence": max_confidence,
                    "details": " | ".join(channel_results)
                }
        except:
            return {"detected": False, "confidence": 0, "details": "Statistical analysis failed"}
    
    def _detect_js_in_pdf(self, pdf_content):
        """Detect JavaScript in PDF content"""
        js_patterns = [
            r'/JavaScript\s', 
            r'/JS\s', 
            r'function\s*\(', 
            r'eval\s*\('
        ]
        
        matches = []
        for pattern in js_patterns:
            if re.search(pattern, pdf_content):
                matches.append(pattern)
        
        if matches:
            confidence = min(1.0, len(matches) / len(js_patterns))
            return {
                "detected": True,
                "confidence": confidence,
                "details": f"JavaScript patterns detected: {', '.join(matches)}"
            }
        else:
            return {
                "detected": False,
                "confidence": 0,
                "details": "No JavaScript detected"
            }
    
    def _detect_unusual_objects(self, pdf_content):
        """Detect unusual embedded objects in PDF"""
        unusual_patterns = [
            r'/EmbeddedFile', 
            r'/Launch', 
            r'/RichMedia', 
            r'/Flash', 
            r'/XFA'
        ]
        
        matches = []
        for pattern in unusual_patterns:
            if re.search(pattern, pdf_content):
                matches.append(pattern)
        
        if matches:
            confidence = min(1.0, len(matches) / len(unusual_patterns))
            return {
                "detected": True,
                "confidence": confidence,
                "details": f"Unusual objects detected: {', '.join(matches)}"
            }
        else:
            return {
                "detected": False,
                "confidence": 0,
                "details": "No unusual objects detected"
            }
    
    def _check_entropy(self, data):
        """Calculate entropy of data to identify potential encryption or compression"""
        try:
            # Convert to bytes if not already
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Split into chunks and calculate entropy for each
            chunk_size = 1024  # 1KB chunks
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            
            high_entropy_chunks = 0
            entropies = []
            
            for chunk in chunks:
                if len(chunk) > 16:  # Only analyze reasonably sized chunks
                    # Count byte frequencies
                    freq = {}
                    for byte in chunk:
                        if byte in freq:
                            freq[byte] += 1
                        else:
                            freq[byte] = 1
                    
                    # Calculate entropy
                    entropy = 0
                    for count in freq.values():
                        probability = count / len(chunk)
                        entropy -= probability * math.log2(probability)
                    
                    entropies.append(entropy)
                    if entropy > 7.8:  # Very high entropy threshold
                        high_entropy_chunks += 1
            
            if not entropies:
                return {"detected": False, "confidence": 0, "details": "Entropy analysis failed - not enough data"}
            
            avg_entropy = sum(entropies) / len(entropies)
            high_entropy_ratio = high_entropy_chunks / len(chunks) if chunks else 0
            
            if high_entropy_ratio > 0.7:  # More than 70% of chunks have high entropy
                return {
                    "detected": True,
                    "confidence": min(1.0, high_entropy_ratio),
                    "details": f"High entropy in {high_entropy_ratio:.1%} of file, avg: {avg_entropy:.2f}/8.0"
                }
            elif avg_entropy > 7.5:
                return {
                    "detected": True,
                    "confidence": min(1.0, (avg_entropy - 7.5) * 2),
                    "details": f"High average entropy: {avg_entropy:.2f}/8.0"
                }
            else:
                return {
                    "detected": False,
                    "confidence": 0,
                    "details": f"Normal entropy levels: {avg_entropy:.2f}/8.0"
                }
        except:
            return {"detected": False, "confidence": 0, "details": "Entropy analysis failed"} 