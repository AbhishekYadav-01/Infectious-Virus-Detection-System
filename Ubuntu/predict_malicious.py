import pandas as pd
import joblib

model = joblib.load("virus_detection_model.pkl")

# Load a new data (replace this with actual file/process data)
sample_data = pd.read_csv("new_data_check.csv")

from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
sample_scaled = scaler.fit_transform(sample_data)

prediction = model.predict(sample_scaled)
print("Prediction (0 = Benign, 1 = Malicious):", prediction)
