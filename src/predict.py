import pandas as pd
import joblib

# Load model
model = joblib.load("models/threat_detector_rf.pkl")

# Load test data (or any new data)
df = pd.read_csv("data/KDDTrain+Multi.csv")

# Separate features
X = df.drop("class", axis=1)

# Make prediction
predictions = model.predict(X)
confidences = model.predict_proba(X).max(axis=1)

# Preview predictions
for i in range(5):
    print(f"Prediction: {predictions[i]}, Confidence: {confidences[i]:.2f}")
