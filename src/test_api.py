import requests
import json

def test_root():
    """Test that the API root is accessible"""
    url = "http://127.0.0.1:5000/"
    response = requests.get(url)
    print(f"Root endpoint status code: {response.status_code}")
    if response.status_code == 200:
        print(f"Response: {response.json()}")
    else:
        print(f"Error: {response.text}")
    
def test_predict():
    """Test the prediction endpoint with a sample network traffic data"""
    url = "http://127.0.0.1:5000/predict"
    
    # Sample input using the generic column names the model expects
    sample_data = {
        "col_0": 0,      # duration
        "col_1": 1,      # protocol_type
        "col_2": 2,      # service
        "col_3": 0,      # flag
        "col_4": 491,    # src_bytes
        "col_5": 0,      # dst_bytes
        "col_6": 0,      # land
        "col_7": 0,      # wrong_fragment
        "col_8": 0,      # urgent
        "col_9": 0,
        "col_10": 0,
        "col_11": 0,
        "col_12": 0,
        "col_13": 0,
        "col_14": 0,
        "col_15": 0,
        "col_16": 0,
        "col_17": 0,
        "col_18": 0,
        "col_19": 0,
        "col_20": 0,
        "col_21": 0,
        "col_22": 0,
        "col_23": 0,
        "col_24": 0,
        "col_25": 0,
        "col_26": 0,
        "col_27": 0,
        "col_28": 0,
        "col_29": 0,
        "col_30": 0,
        "col_31": 0,
        "col_32": 0,
        "col_33": 0,
        "col_34": 0,
        "col_35": 0,
        "col_36": 0,
        "col_37": 0,
        "col_38": 0,
        "col_39": 0,
        "col_40": 0
    }
    
    headers = {'Content-Type': 'application/json'}
    
    try:
        response = requests.post(url, json=sample_data, headers=headers)
        print(f"Prediction endpoint status code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"Prediction: {result['prediction']}")
            print(f"Confidence: {result['confidence']}")
        else:
            print(f"Error: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")

def test_scan_file():
    """Test the file scanning endpoint."""
    with open('requirements.txt', 'rb') as f:
        test_file = f.read()
    
    # Create a test file with multipart/form-data
    import io
    test_data = io.BytesIO(test_file)
    test_data.name = 'test_file.txt'
    
    # Create a test client
    with app.test_client() as client:
        response = client.post(
            '/api/scan_file',
            data={'file': (test_data, 'test_file.txt')},
            content_type='multipart/form-data'
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'file_path' in data
        assert 'file_name' in data
        assert 'detections' in data
        assert 'is_malicious' in data
        
        print(f"File scanning endpoint response: {data}")

def test_scan_memory():
    """Test the memory scanning endpoint."""
    with open('requirements.txt', 'rb') as f:
        test_file = f.read()
    
    # Create a base64 encoded test file
    import base64
    test_data_b64 = base64.b64encode(test_file).decode('utf-8')
    
    # Create a test client
    with app.test_client() as client:
        response = client.post(
            '/api/scan_memory',
            json={'data': test_data_b64, 'filename': 'test_memory_file.txt'}
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'file_name' in data
        assert 'detections' in data
        assert 'is_malicious' in data
        
        print(f"Memory scanning endpoint response: {data}")

if __name__ == "__main__":
    print("Testing API connectivity...")
    test_root()
    print("\nTesting prediction endpoint...")
    test_predict()
    print("\nTesting file scanning endpoint...")
    test_scan_file()
    print("\nTesting memory scanning endpoint...")
    test_scan_memory()
    print("All tests passed!") 