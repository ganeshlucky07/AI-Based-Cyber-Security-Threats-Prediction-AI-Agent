"""
Train WiFi Intrusion Detection Model using multiple WiFi security datasets.

Datasets:
1. AWID Dataset
2. AWID2 Dataset
3. WiFiDeauth Dataset
4. WIDS Dataset
5. IEEE 802.11 Intrusion Dataset
6. UNSW WiFi Dataset
7. CIC-Wireless Dataset
8. IoTID Dataset (IoT WiFi threats)
"""

import os
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import warnings

warnings.filterwarnings('ignore')

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data" / "wifi_datasets"
MODELS_DIR = BASE_DIR / "trained_models"

# Create directories
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)


class WiFiDetectionModelTrainer:
    """Train WiFi intrusion detection models using wireless security datasets."""
    
    # Supported dataset names and their label column names
    DATASET_LABEL_COLUMNS = {
        'AWID': 'Label',
        'AWID2': 'Label',
        'WiFiDeauth': 'Label',
        'WIDS': 'Label',
        'IEEE-802.11': 'Label',
        'UNSW-WiFi': 'Label',
        'CIC-Wireless': 'Label',
        'IoTID': 'Label'
    }
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_names = None
        self.model = None
        self.datasets_loaded = []
        
    def load_real_datasets(self):
        """Load all available WiFi security datasets."""
        print("Attempting to load WiFi security datasets...")
        all_data = []
        
        dataset_dirs = [
            'AWID', 'AWID2', 'WiFiDeauth', 'WIDS',
            'IEEE-802.11', 'UNSW-WiFi', 'CIC-Wireless', 'IoTID'
        ]
        
        for dataset_name in dataset_dirs:
            dataset_path = DATA_DIR / dataset_name
            if not dataset_path.exists():
                continue
            
            print(f"\nLoading {dataset_name}...")
            
            # Try to load CSV files
            csv_files = list(dataset_path.glob('*.csv'))
            if csv_files:
                try:
                    for csv_file in csv_files[:1]:  # Load first CSV
                        print(f"  Reading {csv_file.name}...")
                        df = pd.read_csv(csv_file, nrows=50000)
                        
                        # Standardize label column
                        label_col = self.DATASET_LABEL_COLUMNS.get(dataset_name, 'Label')
                        if label_col in df.columns:
                            df['Label'] = df[label_col]
                            if label_col != 'Label':
                                df = df.drop(label_col, axis=1)
                        
                        all_data.append(df)
                        self.datasets_loaded.append(dataset_name)
                        print(f"  ✓ Loaded {len(df)} samples")
                except Exception as e:
                    print(f"  ✗ Error loading {dataset_name}: {e}")
        
        if all_data:
            print(f"\n✓ Successfully loaded {len(all_data)} datasets")
            print(f"  Datasets: {', '.join(self.datasets_loaded)}")
            combined_df = pd.concat(all_data, ignore_index=True)
            print(f"  Combined shape: {combined_df.shape}")
            return combined_df
        else:
            print("✗ No real datasets found. Using synthetic data.")
            return None
    
    def create_synthetic_dataset(self):
        """Create synthetic WiFi intrusion detection dataset."""
        print("Creating synthetic WiFi intrusion detection dataset...")
        
        n_samples = 50000
        
        # WiFi/802.11 features
        data = {
            # Signal strength
            'rssi': np.random.normal(-50, 15, n_samples),
            'signal_strength': np.random.randint(-100, -30, n_samples),
            'noise_level': np.random.normal(-90, 10, n_samples),
            'snr': np.random.normal(30, 10, n_samples),
            
            # Frame statistics
            'total_frames': np.random.poisson(100, n_samples),
            'data_frames': np.random.poisson(60, n_samples),
            'mgmt_frames': np.random.poisson(30, n_samples),
            'ctrl_frames': np.random.poisson(10, n_samples),
            'probe_requests': np.random.poisson(5, n_samples),
            'probe_responses': np.random.poisson(5, n_samples),
            'beacon_frames': np.random.poisson(10, n_samples),
            'deauth_frames': np.random.poisson(2, n_samples),
            'disassoc_frames': np.random.poisson(1, n_samples),
            
            # Channel information
            'channel': np.random.choice([1, 6, 11, 36, 40, 44, 48], n_samples),
            'bandwidth': np.random.choice([20, 40, 80], n_samples),
            'frequency': np.random.choice([2400, 5000], n_samples),
            
            # Rate information
            'data_rate': np.random.choice([1, 2, 5, 11, 6, 9, 12, 18, 24, 36, 48, 54], n_samples),
            'retry_count': np.random.poisson(2, n_samples),
            'failed_frames': np.random.poisson(1, n_samples),
            
            # Encryption
            'wpa_enabled': np.random.choice([0, 1], n_samples),
            'wpa2_enabled': np.random.choice([0, 1], n_samples),
            'wpa3_enabled': np.random.choice([0, 1], n_samples),
            'open_network': np.random.choice([0, 1], n_samples),
            
            # Traffic patterns
            'avg_packet_size': np.random.exponential(500, n_samples),
            'packet_rate': np.random.exponential(10, n_samples),
            'bytes_sent': np.random.exponential(10000, n_samples),
            'bytes_received': np.random.exponential(10000, n_samples),
            
            # Anomaly indicators
            'unusual_ssid': np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
            'hidden_ssid': np.random.choice([0, 1], n_samples, p=[0.9, 0.1]),
            'multiple_bssid': np.random.choice([0, 1], n_samples, p=[0.85, 0.15]),
            'spoofed_mac': np.random.choice([0, 1], n_samples, p=[0.98, 0.02]),
        }
        
        df = pd.DataFrame(data)
        
        # Create labels: 0 = Normal, 1 = Attack
        # Attack indicators: high deauth frames, spoofed MAC, unusual patterns
        attack_probability = (
            (df['deauth_frames'] > 5).astype(int) * 0.4 +
            (df['spoofed_mac'] == 1).astype(int) * 0.3 +
            (df['failed_frames'] > 3).astype(int) * 0.2 +
            (df['unusual_ssid'] == 1).astype(int) * 0.1
        )
        
        df['Label'] = (np.random.random(n_samples) < attack_probability).astype(int)
        
        # Ensure some minimum number of attack samples
        n_attacks = max(int(n_samples * 0.2), 100)
        attack_indices = np.random.choice(n_samples, n_attacks, replace=False)
        df.loc[attack_indices, 'Label'] = 1
        
        return df
    
    def preprocess_data(self, df):
        """Preprocess the dataset."""
        print("Preprocessing data...")
        
        # Handle missing values
        df = df.fillna(df.mean(numeric_only=True))
        
        # Separate features and labels
        if 'Label' in df.columns:
            y = df['Label']
            X = df.drop('Label', axis=1)
        else:
            y = df.iloc[:, -1]
            X = df.iloc[:, :-1]
        
        # Encode categorical variables
        categorical_cols = X.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            if col not in self.label_encoders:
                self.label_encoders[col] = LabelEncoder()
            X[col] = self.label_encoders[col].fit_transform(X[col].astype(str))
        
        # Store feature names
        self.feature_names = X.columns.tolist()
        
        # Convert to numeric
        X = X.astype(float)
        
        # Handle any remaining NaN or inf values
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(X.mean())
        
        return X, y
    
    def train_model(self, X, y):
        """Train the WiFi detection model."""
        print("Training WiFi intrusion detection model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        print("Training Random Forest...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        rf_model.fit(X_train_scaled, y_train)
        
        # Train Gradient Boosting
        print("Training Gradient Boosting...")
        gb_model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=7,
            learning_rate=0.1,
            random_state=42
        )
        gb_model.fit(X_train_scaled, y_train)
        
        # Evaluate models
        print("\n=== Model Evaluation ===")
        
        rf_pred = rf_model.predict(X_test_scaled)
        rf_proba = rf_model.predict_proba(X_test_scaled)[:, 1]
        
        print("\nRandom Forest Results:")
        print(classification_report(y_test, rf_pred))
        print(f"ROC-AUC Score: {roc_auc_score(y_test, rf_proba):.4f}")
        
        gb_pred = gb_model.predict(X_test_scaled)
        gb_proba = gb_model.predict_proba(X_test_scaled)[:, 1]
        
        print("\nGradient Boosting Results:")
        print(classification_report(y_test, gb_pred))
        print(f"ROC-AUC Score: {roc_auc_score(y_test, gb_proba):.4f}")
        
        # Use the better performing model
        rf_score = roc_auc_score(y_test, rf_proba)
        gb_score = roc_auc_score(y_test, gb_proba)
        
        if rf_score >= gb_score:
            print("\n✓ Using Random Forest model (better performance)")
            self.model = rf_model
        else:
            print("\n✓ Using Gradient Boosting model (better performance)")
            self.model = gb_model
        
        return self.model
    
    def save_model(self):
        """Save the trained model and preprocessing objects."""
        print("\nSaving model artifacts...")
        
        artifact = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_names': self.feature_names,
        }
        
        model_path = MODELS_DIR / "wifi_detection_model.joblib"
        joblib.dump(artifact, model_path)
        print(f"✓ Model saved to {model_path}")
        
        return model_path
    
    def train(self):
        """Complete training pipeline."""
        print("=" * 60)
        print("WiFi Intrusion Detection Model Training")
        print("=" * 60)
        
        # Try to load real datasets first
        df = self.load_real_datasets()
        
        # If no real datasets, use synthetic
        if df is None:
            df = self.create_synthetic_dataset()
        
        print(f"\nDataset shape: {df.shape}")
        print(f"Normal/Attack distribution:\n{df['Label'].value_counts()}")
        
        # Preprocess
        X, y = self.preprocess_data(df)
        
        # Train
        self.train_model(X, y)
        
        # Save
        self.save_model()
        
        print("\n" + "=" * 60)
        print("Training Complete!")
        print("=" * 60)


def main():
    """Main training function."""
    trainer = WiFiDetectionModelTrainer()
    trainer.train()


if __name__ == "__main__":
    main()
