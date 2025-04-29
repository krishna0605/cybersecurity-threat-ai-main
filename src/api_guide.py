"""
Cybersecurity Threat Detection API Guide

This script demonstrates how to use the API and provides a simple interface
for testing the threat detection model.
"""

import requests
import json
import pandas as pd
import time

COLUMN_MAPPING = {
    # Basic connection features
    "duration": "col_0",        # Duration of connection (seconds)
    "protocol_type": "col_1",   # Protocol type (tcp=0, udp=1, icmp=2)
    "service": "col_2",         # Network service (http=0, ftp=1, etc.)
    "flag": "col_3",            # Status flag of connection (normal=0, error=1)
    
    # Content features 
    "src_bytes": "col_4",       # Bytes from source to destination
    "dst_bytes": "col_5",       # Bytes from destination to source
    "land": "col_6",            # 1 if connection is from/to same host/port, 0 otherwise
    "wrong_fragment": "col_7",  # Number of wrong fragments
    "urgent": "col_8",          # Number of urgent packets
    
    # For complete feature mapping, refer to KDD Cup 1999 documentation
}

# Mapping of prediction values to attack types
ATTACK_TYPES = {
    0: "normal",                # Normal traffic
    1: "dos",                   # Denial of Service attack
    2: "probe",                 # Surveillance/scanning
    3: "r2l",                   # Unauthorized access from remote machine
    4: "u2r"                    # Unauthorized access to root privileges
}

def get_api_status():
    """Check if the API is running"""
    try:
        response = requests.get("http://127.0.0.1:5000/")
        if response.status_code == 200:
            print("✅ API is running and accessible")
            return True
        else:
            print(f"❌ API returned status code {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ API is not running or not accessible")
        return False

def detect_threat(input_features):
    """Send network traffic features to API and get prediction result"""
    # Convert any user-friendly names to the column names used by the model
    payload = {}
    
    # Map any user-friendly names to column names
    for key, value in input_features.items():
        if key in COLUMN_MAPPING:
            col_name = COLUMN_MAPPING[key]
            payload[col_name] = value
        else:
            # If already using column name format, keep as is
            payload[key] = value
    
    # Fill in remaining required columns with zeros
    for i in range(41):  # We have 41 feature columns
        col_name = f"col_{i}"
        if col_name not in payload:
            payload[col_name] = 0
    
    try:
        url = "http://127.0.0.1:5000/predict"
        response = requests.post(url, json=payload)
        
        if response.status_code == 200:
            result = response.json()
            prediction = result['prediction'][0]
            confidence = result['confidence'][0]
            
            # Map numerical prediction to attack type name if possible
            if isinstance(prediction, int) and prediction in ATTACK_TYPES:
                prediction = ATTACK_TYPES[prediction]
            
            print(f"\n🔍 Threat Detection Result:")
            print(f"   Prediction: {prediction}")
            print(f"   Confidence: {confidence:.2f}")
            return prediction, confidence
        else:
            print(f"❌ Error: {response.text}")
            return None, None
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return None, None

def interactive_demo():
    """Run an interactive demo of the threat detection API"""
    print("\n" + "="*60)
    print("🛡️  CYBERSECURITY THREAT DETECTION SYSTEM - INTERACTIVE DEMO")
    print("="*60)
    
    if not get_api_status():
        print("\nPlease start the API server with: python src/deploy.py")
        return
    
    print("\nThis demo allows you to test the threat detection model.")
    print("You can enter network traffic features to detect potential threats.")
    
    while True:
        print("\n" + "-"*60)
        print("Enter network traffic features (or 'q' to quit):")
        
        # Sample input to demonstrate feature format
        sample_features = {
            "duration": 0,
            "protocol_type": 1,  # 0=tcp, 1=udp, 2=icmp
            "service": 2,        # Network service type
            "flag": 0,           # Connection status flag
            "src_bytes": 491,    # Data bytes from source to destination
            "dst_bytes": 0       # Data bytes from destination to source
        }
        
        # Show sample
        print("\nSample input features:")
        for k, v in sample_features.items():
            print(f"  {k}: {v}")
        
        # Let user choose between sample and custom input
        choice = input("\nUse sample features? (y/n/q): ").lower()
        
        if choice == 'q':
            break
            
        if choice == 'y':
            features = sample_features
        else:
            # Custom input - simplified for demo purposes
            features = {}
            try:
                features["duration"] = int(input("Duration (seconds): ") or "0")
                features["protocol_type"] = int(input("Protocol type (0=tcp, 1=udp, 2=icmp): ") or "0")
                features["service"] = int(input("Service type (0-69): ") or "0")
                features["src_bytes"] = int(input("Source bytes: ") or "0")
                features["dst_bytes"] = int(input("Destination bytes: ") or "0")
            except ValueError:
                print("❌ Invalid input. Using default values.")
                features = sample_features
        
        # Send to API
        print("\nSending to API for threat detection...")
        detect_threat(features)
        
        print("\nWould you like to try another prediction?")
        if input("Continue? (y/n): ").lower() != 'y':
            break
    
    print("\nThank you for using the Cybersecurity Threat Detection System!")

if __name__ == "__main__":
    interactive_demo() 