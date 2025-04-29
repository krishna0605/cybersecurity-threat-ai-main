import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Column names for the KDD dataset
KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class'
]

# Load TXT file and add column names
def load_and_preprocess_txt(filepath):
    df = pd.read_csv(filepath, header=None)
    
    # Add column names
    if len(df.columns) == len(KDD_COLUMNS):
        df.columns = KDD_COLUMNS
    else:
        # If column count doesn't match, use default naming and ensure class column
        df.columns = [f'col_{i}' for i in range(len(df.columns)-1)] + ['class']
    
    return df

# Encode categorical features and the label column
def encode_features(df):
    label_encoders = {}
    
    # Encode categorical features
    categorical_cols = ['protocol_type', 'service', 'flag', 'class']
    for col in df.columns:
        if col in categorical_cols or df[col].dtype == 'object':
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            label_encoders[col] = le
    
    return df, label_encoders

# Save DataFrame to CSV
def save_to_csv(df, output_path):
    df.to_csv(output_path, index=False)
    print(f"Saved preprocessed data to {output_path}")

if __name__ == "__main__":
    input_path = "data/KDDTrain+.txt"
    output_path = "data/KDDTrain+Multi.csv"
    
    # Load and preprocess data
    df = load_and_preprocess_txt(input_path)
    print(f"Loaded data with {len(df)} rows and {len(df.columns)} columns")
    
    # Encode features
    df, encoders = encode_features(df)
    print("Encoded categorical features")
    
    # Save to CSV
    save_to_csv(df, output_path)
