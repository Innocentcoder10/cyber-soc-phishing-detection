import pandas as pd

# Load dataset
data = pd.read_csv("../data/emails.csv")

# Remove unnecessary column
data = data.drop(columns=["Unnamed: 0"])

# Remove missing values
data = data.dropna()

# Convert labels to numbers
data["Email Type"] = data["Email Type"].map({
    "Safe Email": 0,
    "Phishing Email": 1
})

# Show cleaned data
print("Cleaned Data:")
print(data.head())

# Check values
print("\nLabel counts:")
print(data["Email Type"].value_counts())