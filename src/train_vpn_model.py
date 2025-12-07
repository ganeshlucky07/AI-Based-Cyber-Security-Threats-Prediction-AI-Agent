"""
Train VPN Detection Model using multiple VPN/Encrypted Traffic datasets.

Datasets:
1. ISCX VPN-NonVPN Dataset
2. USTC-TFC2016 Dataset
3. Deep Packet Dataset
4. UNIBS Encrypted Traffic Dataset
5. Tor vs VPN Traffic Dataset
6. MAWI Encrypted Flow Dataset
7. FETA Dataset (Fingerprinting Encrypted Traffic)
8. Cross-Platform VPN Detection Dataset
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
DATA_DIR = BASE_DIR / "data" / "vpn_datasets"
MODELS_DIR = BASE_DIR / "trained_models"

# Create directories
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)


class VPNDetectionModelTrainer:
    """Train VPN detection models using encrypted traffic datasets."""
    
    # Supported dataset names and their label column names
    DATASET_LABEL_COLUMNS = {
        'ISCX-VPN-NonVPN': 'Label',
        'USTC-TFC2016': 'Label',
        'Deep-Packet': 'Label',
        'UNIBS-Encrypted': 'Label',
        'Tor-vs-VPN': 'Label',
        'MAWI-Encrypted': 'Label',
        'FETA': 'Label',
        'Cross-Platform-VPN': 'Label'
    }
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_names = None
        self.model = None
        self.datasets_loaded = []
        
    def load_real_datasets(self):
        """Load all available VPN/Encrypted traffic datasets."""
        print("Attempting to load VPN/Encrypted traffic datasets...")
        all_data = []
        
        dataset_dirs = [
            'ISCX-VPN-NonVPN', 'USTC-TFC2016', 'Deep-Packet',
            'UNIBS-Encrypted', 'Tor-vs-VPN', 'MAWI-Encrypted',
            'FETA', 'Cross-Platform-VPN'
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
        """Create synthetic VPN/encrypted traffic dataset."""
        print("Creating synthetic VPN/Encrypted traffic dataset...")
        
        n_samples = 50000
        
        # VPN/Encrypted traffic features
        data = {
            # Flow statistics
            'duration': np.random.exponential(100, n_samples),
            'protocol_type': np.random.choice(['TCP', 'UDP', 'ICMP'], n_samples),
            'src_port': np.random.randint(1024, 65535, n_samples),
            'dst_port': np.random.randint(1, 65535, n_samples),
            
            # Packet statistics
            'total_fwd_packets': np.random.poisson(50, n_samples),
            'total_bwd_packets': np.random.poisson(50, n_samples),
            'total_len_fwd_packets': np.random.exponential(1000, n_samples),
            'total_len_bwd_packets': np.random.exponential(1000, n_samples),
            
            # Flow characteristics
            'fwd_packet_length_max': np.random.exponential(500, n_samples),
            'fwd_packet_length_min': np.random.exponential(100, n_samples),
            'fwd_packet_length_mean': np.random.exponential(300, n_samples),
            'bwd_packet_length_max': np.random.exponential(500, n_samples),
            'bwd_packet_length_min': np.random.exponential(100, n_samples),
            'bwd_packet_length_mean': np.random.exponential(300, n_samples),
            
            # Inter-arrival times
            'fwd_iat_total': np.random.exponential(1000, n_samples),
            'fwd_iat_mean': np.random.exponential(100, n_samples),
            'fwd_iat_std': np.random.exponential(50, n_samples),
            'bwd_iat_total': np.random.exponential(1000, n_samples),
            'bwd_iat_mean': np.random.exponential(100, n_samples),
            'bwd_iat_std': np.random.exponential(50, n_samples),
            
            # Flags
            'fwd_psh_flags': np.random.poisson(2, n_samples),
            'bwd_psh_flags': np.random.poisson(2, n_samples),
            'fwd_urg_flags': np.random.poisson(0.5, n_samples),
            'bwd_urg_flags': np.random.poisson(0.5, n_samples),
            'fwd_rst_flags': np.random.poisson(0.1, n_samples),
            'bwd_rst_flags': np.random.poisson(0.1, n_samples),
            'fwd_syn_flags': np.random.poisson(1, n_samples),
            'bwd_syn_flags': np.random.poisson(1, n_samples),
            'fwd_fin_flags': np.random.poisson(1, n_samples),
            'bwd_fin_flags': np.random.poisson(1, n_samples),
            
            # Entropy and statistics
            'fwd_payload_bytes': np.random.exponential(500, n_samples),
            'bwd_payload_bytes': np.random.exponential(500, n_samples),
            'fwd_packets_per_sec': np.random.exponential(10, n_samples),
            'bwd_packets_per_sec': np.random.exponential(10, n_samples),
            'packet_length_variance': np.random.exponential(100, n_samples),
            'packet_length_std': np.random.exponential(50, n_samples),
        }
        
        df = pd.DataFrame(data)
        
        # Create labels: 0 = Non-VPN, 1 = VPN
        # VPN traffic typically has more uniform packet sizes and regular patterns
        vpn_probability = (
            (df['packet_length_variance'] < df['packet_length_variance'].quantile(0.3)).astype(int) * 0.3 +
            (df['packet_length_std'] < df['packet_length_std'].quantile(0.3)).astype(int) * 0.3 +
            (df['total_fwd_packets'] > df['total_fwd_packets'].quantile(0.7)).astype(int) * 0.2 +
            (df['total_bwd_packets'] > df['total_bwd_packets'].quantile(0.7)).astype(int) * 0.2
        )
        
        df['Label'] = (np.random.random(n_samples) < vpn_probability).astype(int)
        
        # Ensure some minimum number of VPN samples
        n_vpn = max(int(n_samples * 0.3), 100)
        vpn_indices = np.random.choice(n_samples, n_vpn, replace=False)
        df.loc[vpn_indices, 'Label'] = 1
        
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
        """Train the VPN detection model."""
        print("Training VPN detection model...")
        
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
        
        model_path = MODELS_DIR / "vpn_detection_model.joblib"
        joblib.dump(artifact, model_path)
        print(f"✓ Model saved to {model_path}")
        
        return model_path
    
    def train(self):
        """Complete training pipeline."""
        print("=" * 60)
        print("VPN Detection Model Training")
        print("=" * 60)
        
        # Try to load real datasets first
        df = self.load_real_datasets()
        
        # If no real datasets, use synthetic
        if df is None:
            df = self.create_synthetic_dataset()
        
        print(f"\nDataset shape: {df.shape}")
        print(f"VPN/Non-VPN distribution:\n{df['Label'].value_counts()}")
        
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
    trainer = VPNDetectionModelTrainer()
    trainer.train()


if __name__ == "__main__":
    main()
