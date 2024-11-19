import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Load the labeled dataset
data = pd.read_csv("combined_labeled_dataset.csv")

# Drop any columns that are not needed for the model
data = data.drop(columns=["File_Path", "Name", "PID", "Status", "Hash"], axis=1)

# Separate the features and labels
X = data.drop(columns=["Label"])  # Features
y = data["Label"]  # Labels

# Normalize/Standardize the features (important for models like RandomForest)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split the dataset into training and testing sets (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Save the processed data for future use
pd.DataFrame(X_train).to_csv("X_train.csv", index=False)
pd.DataFrame(X_test).to_csv("X_test.csv", index=False)
pd.DataFrame(y_train).to_csv("y_train.csv", index=False)
pd.DataFrame(y_test).to_csv("y_test.csv", index=False)

print("Data prepared and saved.")
