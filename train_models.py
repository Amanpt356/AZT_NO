import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
import xgboost as xgb
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# Create models directory if not exists
os.makedirs('models', exist_ok=True)

def train_models():
    # 1. Load Dataset
    print("Loading dataset...")
    df = pd.read_csv('AZT_NO_ZeroTrust_Dataset.csv')

    # 2. Preprocessing
    print("Preprocessing data...")
    # Drop irrelevant columns for training
    id_cols = ['device_id', 'ip_address', 'mac_address', 'anomaly_score', 'action_taken']
    df_clean = df.drop(columns=id_cols)

    # Label Encoding for categorical features
    categorical_cols = ['device_type', 'protocol', 'time_of_day']
    encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        df_clean[col] = le.fit_transform(df_clean[col])
        encoders[col] = le
    
    # Label Encoding for Target (threat_type)
    target_le = LabelEncoder()
    df_clean['threat_type'] = target_le.fit_transform(df_clean['threat_type'])
    encoders['threat_type'] = target_le

    # Features and Target
    X = df_clean.drop(columns=['threat_type'])
    y = df_clean['threat_type']

    # Scaling features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Save encoders and scaler
    joblib.dump(encoders, 'models/encoders.joblib')
    joblib.dump(scaler, 'models/scaler.joblib')
    joblib.dump(X.columns.tolist(), 'models/feature_names.joblib')

    # 3. Split Data
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    # 4. Model Training
    results = {}

    # Logistic Regression
    print("Training Logistic Regression...")
    lr = LogisticRegression(max_iter=1000)
    lr.fit(X_train, y_train)
    y_pred_lr = lr.predict(X_test)
    results['Logistic Regression'] = accuracy_score(y_test, y_pred_lr)
    joblib.dump(lr, 'models/logistic_regression.joblib')

    # Random Forest
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    y_pred_rf = rf.predict(X_test)
    results['Random Forest'] = accuracy_score(y_test, y_pred_rf)
    joblib.dump(rf, 'models/random_forest.joblib')

    # XGBoost
    print("Training XGBoost...")
    xgb_model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')
    xgb_model.fit(X_train, y_train)
    y_pred_xgb = xgb_model.predict(X_test)
    results['XGBoost'] = accuracy_score(y_test, y_pred_xgb)
    joblib.dump(xgb_model, 'models/xgboost.joblib')

    # Isolation Forest (for Anomaly Score)
    print("Training Isolation Forest...")
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    iso_forest.fit(X_train)
    joblib.dump(iso_forest, 'models/isolation_forest.joblib')

    # 5. Summary
    print("\nModel Training Summary:")
    for model_name, acc in results.items():
        print(f"{model_name}: Accuracy = {acc:.4f}")
    
    best_model_name = max(results, key=results.get)
    print(f"\nBest Model: {best_model_name}")
    
    # Save best model name for app use
    joblib.dump(best_model_name.lower().replace(' ', '_'), 'models/best_model_name.joblib')

    print("\nDetailed Performance (Best Model - XGBoost):")
    print(classification_report(y_test, y_pred_xgb, target_names=target_le.classes_))

if __name__ == "__main__":
    train_models()
