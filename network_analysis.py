import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# -------------------------
# LOAD CSV DATASET
# -------------------------
def load_network_data(file):
    df = pd.read_csv(file)
    return df


# -------------------------
# CLEAN DATA
# -------------------------
def clean_network_data(df):
    df.columns = df.columns.str.strip()

    # Replace infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop rows with missing values
    df.dropna(inplace=True)

    return df


# -------------------------
# SELECT IMPORTANT FEATURES
# -------------------------
def select_features(df):
    features = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "Packet Length Mean",
        "Packet Length Std",
        "Idle Mean",
        "Active Mean"
    ]

    available_features = [f for f in features if f in df.columns]
    return df[available_features], available_features


# -------------------------
# ANOMALY DETECTION
# -------------------------
def run_anomaly_detection(df_features):
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df_features)

    model = IsolationForest(contamination=0.05, random_state=42)
    preds = model.fit_predict(X_scaled)

    return preds


# -------------------------
# LABEL RESULTS
# -------------------------
def add_anomaly_labels(df, preds):
    df["Anomaly"] = preds
    df["Anomaly_Label"] = df["Anomaly"].apply(lambda x: "Suspicious" if x == -1 else "Normal")
    return df


# -------------------------
# SUMMARY STATS
# -------------------------
def get_summary_stats(df):
    return {
        "Total Flows": len(df),
        "Suspicious Flows": len(df[df["Anomaly_Label"] == "Suspicious"]),
        "Normal Flows": len(df[df["Anomaly_Label"] == "Normal"])
    }