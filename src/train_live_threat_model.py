"""
Train Live Threat Prediction Model using multiple IDS datasets.

Datasets:
1. CIC-IDS 2017
2. CIC-DDoS 2019
3. CSE-CIC-IDS 2018
4. UNSW-NB15
5. TON_IoT
6. Bot-IoT Dataset
7. MAWI Traffic Archive
8. Kyoto 2006+ Dataset
9. DARPA Intrusion Detection
10. NSL-KDD
11. KDD CUP 1999
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
DATA_DIR = BASE_DIR / "data" / "ids_datasets"
MODELS_DIR = BASE_DIR / "trained_models"

# Create directories
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)


class LiveThreatModelTrainer:
    """Train live threat prediction models using IDS datasets."""
    
    # Supported dataset names and their label column names
    DATASET_LABEL_COLUMNS = {
        'CIC-IDS-2017': 'Label',
        'CIC-DDoS-2019': 'Label',
        'CSE-CIC-IDS-2018': 'Label',
        'UNSW-NB15': 'Label',
        'NSL-KDD': 'Label',
        'KDD-CUP-1999': 'class',
        'TON-IoT': 'Label',
        'Bot-IoT': 'Label',
        'MAWI': 'Label',
        'Kyoto-2006': 'Label',
        'DARPA': 'Label',
        'DoToSet': 'Label',
        'AAPS20M': 'Label',
        'MAWILab': 'Label'
    }
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_names = None
        self.model = None
        self.datasets_loaded = []
        
    def load_real_datasets(self):
        """Load all available real IDS datasets."""
        print("Attempting to load real IDS datasets...")
        all_data = []
        
        dataset_dirs = [
            'DoToSet', 'AAPS20M', 'CIC-IDS-2017', 'CIC-DDoS-2019',
            'CSE-CIC-IDS-2018', 'UNSW-NB15', 'NSL-KDD', 'KDD-CUP-1999',
            'TON-IoT', 'Bot-IoT', 'MAWI', 'Kyoto-2006', 'DARPA', 'MAWILab'
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
                        df = pd.read_csv(csv_file, nrows=50000)  # Limit rows
                        
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
            
            # Try to load TXT files
            txt_files = list(dataset_path.glob('*.txt'))
            if txt_files and not csv_files:
                try:
                    for txt_file in txt_files[:1]:
                        print(f"  Reading {txt_file.name}...")
                        df = pd.read_csv(txt_file, nrows=50000)
                        
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
        """
        Create a synthetic dataset combining features from multiple IDS datasets.
        This is used for demonstration when actual datasets are not available.
        """
        print("Creating synthetic IDS dataset...")
        
        # Features commonly found in IDS datasets
        n_samples = 50000
        
        data = {
            # Flow statistics
            'duration': np.random.exponential(100, n_samples),
            'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], n_samples),
            'service': np.random.choice(['http', 'ftp', 'ssh', 'smtp', 'dns', 'other'], n_samples),
            'flag': np.random.choice(['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'OTH'], n_samples),
            
            # Source and destination statistics
            'src_bytes': np.random.exponential(500, n_samples),
            'dst_bytes': np.random.exponential(500, n_samples),
            'land': np.random.choice([0, 1], n_samples, p=[0.99, 0.01]),
            'wrong_fragment': np.random.poisson(0.1, n_samples),
            'urgent': np.random.poisson(0.05, n_samples),
            
            # Connection statistics
            'hot': np.random.poisson(0.2, n_samples),
            'num_failed_logins': np.random.poisson(0.1, n_samples),
            'logged_in': np.random.choice([0, 1], n_samples, p=[0.7, 0.3]),
            'num_compromised': np.random.poisson(0.05, n_samples),
            'root_shell': np.random.choice([0, 1], n_samples, p=[0.98, 0.02]),
            'su_attempted': np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
            'num_root': np.random.poisson(0.1, n_samples),
            'num_file_creations': np.random.poisson(0.2, n_samples),
            'num_shells': np.random.poisson(0.1, n_samples),
            'num_access_files': np.random.poisson(0.15, n_samples),
            'num_outbound_cmds': np.random.poisson(0.05, n_samples),
            
            # Network statistics
            'is_host_login': np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
            'is_guest_login': np.random.choice([0, 1], n_samples, p=[0.99, 0.01]),
            'count': np.random.poisson(10, n_samples),
            'srv_count': np.random.poisson(8, n_samples),
            'serror_rate': np.random.beta(2, 5, n_samples),
            'srv_serror_rate': np.random.beta(2, 5, n_samples),
            'rerror_rate': np.random.beta(2, 5, n_samples),
            'srv_rerror_rate': np.random.beta(2, 5, n_samples),
            'same_srv_rate': np.random.beta(3, 2, n_samples),
            'diff_srv_rate': np.random.beta(2, 3, n_samples),
            'srv_diff_host_rate': np.random.beta(2, 3, n_samples),
            
            # Packet statistics
            'dst_host_count': np.random.poisson(20, n_samples),
            'dst_host_srv_count': np.random.poisson(15, n_samples),
            'dst_host_same_srv_rate': np.random.beta(3, 2, n_samples),
            'dst_host_diff_srv_rate': np.random.beta(2, 3, n_samples),
            'dst_host_same_src_port_rate': np.random.beta(2, 4, n_samples),
            'dst_host_srv_diff_host_rate': np.random.beta(2, 3, n_samples),
            'dst_host_serror_rate': np.random.beta(2, 5, n_samples),
            'dst_host_srv_serror_rate': np.random.beta(2, 5, n_samples),
            'dst_host_rerror_rate': np.random.beta(2, 5, n_samples),
            'dst_host_srv_rerror_rate': np.random.beta(2, 5, n_samples),
        }
        
        df = pd.DataFrame(data)
        
        # Create labels: 0 = Normal, 1 = Attack
        # Make attacks more likely when certain conditions are met
        attack_probability = (
            (df['num_failed_logins'] > 0).astype(int) * 0.3 +
            (df['root_shell'] == 1).astype(int) * 0.4 +
            (df['su_attempted'] == 1).astype(int) * 0.3 +
            (df['num_compromised'] > 0).astype(int) * 0.4 +
            (df['serror_rate'] > 0.5).astype(int) * 0.2 +
            (df['rerror_rate'] > 0.5).astype(int) * 0.2
        )
        
        df['label'] = (np.random.random(n_samples) < attack_probability).astype(int)
        
        # Ensure some minimum number of attacks
        n_attacks = max(int(n_samples * 0.2), 100)
        attack_indices = np.random.choice(n_samples, n_attacks, replace=False)
        df.loc[attack_indices, 'label'] = 1
        
        return df
    
    def preprocess_data(self, df):
        """Preprocess the dataset."""
        print("Preprocessing data...")
        
        # Handle missing values
        df = df.fillna(df.mean(numeric_only=True))
        
        # Separate features and labels
        if 'label' in df.columns:
            y = df['label']
            X = df.drop('label', axis=1)
        elif 'Label' in df.columns:
            y = df['Label']
            X = df.drop('Label', axis=1)
        else:
            # Assume last column is label
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
        """Train the threat detection model."""
        print("Training live threat prediction model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train ensemble model
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
        
        model_path = MODELS_DIR / "live_threat_model.joblib"
        joblib.dump(artifact, model_path)
        print(f"✓ Model saved to {model_path}")
        
        return model_path
    
    def train(self):
        """Complete training pipeline."""
        print("=" * 60)
        print("Live Threat Prediction Model Training")
        print("=" * 60)
        
        # Try to load real datasets first
        df = self.load_real_datasets()
        
        # If no real datasets, use synthetic
        if df is None:
            df = self.create_synthetic_dataset()
        
        print(f"\nDataset shape: {df.shape}")
        print(f"Attack distribution:\n{df['label'].value_counts() if 'label' in df.columns else df['Label'].value_counts()}")
        
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
    trainer = LiveThreatModelTrainer()
    trainer.train()


if __name__ == "__main__":
    main()
