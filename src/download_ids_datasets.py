"""
Download and prepare IDS datasets for training.

This script provides utilities to download various IDS datasets:
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
import urllib.request
import zipfile
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data" / "ids_datasets"
DATA_DIR.mkdir(parents=True, exist_ok=True)


class IDSDatasetDownloader:
    """Download and manage IDS datasets."""
    
    # Dataset URLs and information
    DATASETS = {
        'DoToSet': {
            'url': 'https://github.com/DoToSet/DoToSet',
            'description': 'DoToSet - Simulated attacks (DDoS, brute force, infiltration) with labeled data',
            'local_path': DATA_DIR / 'DoToSet',
            'status': 'Manual download required',
            'features': 'Network flow features with attack labels',
            'attack_types': 'DDoS, Brute Force, Infiltration'
        },
        'AAPS20M': {
            'url': 'https://www.unb.ca/cic/datasets/aaps-20m.html',
            'description': 'AAPS20M - Advanced Attack and Payload Simulation 20M',
            'local_path': DATA_DIR / 'AAPS20M',
            'status': 'Manual download required',
            'features': '80+ network flow features',
            'attack_types': 'Advanced persistent threats, zero-day exploits'
        },
        'CIC-IDS-2017': {
            'url': 'https://www.unb.ca/cic/datasets/ids-2017.html',
            'description': 'Canadian Institute for Cybersecurity IDS 2017',
            'local_path': DATA_DIR / 'CIC-IDS-2017',
            'status': 'Manual download required',
            'features': '78 network flow features',
            'attack_types': 'DDoS, Infiltration, Botnet, Web attacks'
        },
        'CIC-DDoS-2019': {
            'url': 'https://www.unb.ca/cic/datasets/ddos-2019.html',
            'description': 'CIC DDoS Attack 2019',
            'local_path': DATA_DIR / 'CIC-DDoS-2019',
            'status': 'Manual download required'
        },
        'CSE-CIC-IDS-2018': {
            'url': 'https://www.unb.ca/cic/datasets/ids-2018.html',
            'description': 'CSE-CIC-IDS 2018',
            'local_path': DATA_DIR / 'CSE-CIC-IDS-2018',
            'status': 'Manual download required'
        },
        'UNSW-NB15': {
            'url': 'https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/',
            'description': 'UNSW-NB15 Network Intrusion Detection Dataset',
            'local_path': DATA_DIR / 'UNSW-NB15',
            'status': 'Manual download required'
        },
        'NSL-KDD': {
            'url': 'https://www.unb.ca/cic/datasets/nsl-kdd.html',
            'description': 'NSL-KDD Dataset',
            'local_path': DATA_DIR / 'NSL-KDD',
            'status': 'Manual download required'
        },
        'KDD-CUP-1999': {
            'url': 'http://kdd.ics.uci.edu/databases/kddcup99/',
            'description': 'KDD Cup 1999 Intrusion Detection',
            'local_path': DATA_DIR / 'KDD-CUP-1999',
            'status': 'Manual download required'
        },
        'TON-IoT': {
            'url': 'https://research.unsw.edu.au/projects/toniot-datasets',
            'description': 'TON_IoT Network and IoT Datasets',
            'local_path': DATA_DIR / 'TON-IoT',
            'status': 'Manual download required'
        },
        'Bot-IoT': {
            'url': 'https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/Bot-IoT/',
            'description': 'Bot-IoT Dataset',
            'local_path': DATA_DIR / 'Bot-IoT',
            'status': 'Manual download required'
        },
        'MAWI': {
            'url': 'http://mawi.wide.ad.jp/mawi/',
            'description': 'MAWI Traffic Archive',
            'local_path': DATA_DIR / 'MAWI',
            'status': 'Manual download required'
        },
        'Kyoto-2006': {
            'url': 'http://www.takakura.com/Kyoto_data/',
            'description': 'Kyoto 2006+ Honeypot Dataset',
            'local_path': DATA_DIR / 'Kyoto-2006',
            'status': 'Manual download required'
        },
        'DARPA': {
            'url': 'https://www.ll.mit.edu/r-d/datasets/1998-darpa-intrusion-detection-evaluation-dataset',
            'description': 'DARPA Intrusion Detection Evaluation',
            'local_path': DATA_DIR / 'DARPA',
            'status': 'Manual download required',
            'features': '41 features',
            'attack_types': 'Probe, DoS, U2R, R2L'
        },
        'MAWILab': {
            'url': 'http://mawi.wide.ad.jp/mawi/',
            'description': 'MAWILab - Real anonymized network traffic with behavior-based anomalies',
            'local_path': DATA_DIR / 'MAWILab',
            'status': 'Manual download required',
            'features': 'Real-world network traffic patterns',
            'attack_types': 'Behavior-based anomalies, zero-day attacks'
        }
    }
    
    @classmethod
    def print_dataset_info(cls):
        """Print information about available datasets."""
        print("\n" + "=" * 80)
        print("IDS DATASETS FOR LIVE THREAT PREDICTION MODEL TRAINING")
        print("=" * 80)
        
        for dataset_name, info in cls.DATASETS.items():
            print(f"\n{dataset_name}")
            print("-" * 80)
            print(f"Description: {info['description']}")
            print(f"URL: {info['url']}")
            print(f"Local Path: {info['local_path']}")
            print(f"Status: {info['status']}")
    
    @classmethod
    def get_download_instructions(cls):
        """Provide instructions for downloading datasets."""
        instructions = """
INSTRUCTIONS FOR DOWNLOADING IDS DATASETS
==========================================

The following datasets are recommended for training the live threat prediction model:

NEW DATASETS (Recommended)
==========================

1. DoToSet
   - Download from: https://github.com/DoToSet/DoToSet
   - Extract to: data/ids_datasets/DoToSet/
   - Features: Network flow features with attack labels
   - Attack Types: DDoS, Brute Force, Infiltration
   - Files: *.csv

2. AAPS20M
   - Download from: https://www.unb.ca/cic/datasets/aaps-20m.html
   - Extract to: data/ids_datasets/AAPS20M/
   - Features: 80+ network flow features
   - Attack Types: Advanced persistent threats, zero-day exploits
   - Files: *.csv

3. MAWILab
   - Download from: http://mawi.wide.ad.jp/mawi/
   - Extract to: data/ids_datasets/MAWILab/
   - Features: Real-world network traffic patterns
   - Attack Types: Behavior-based anomalies, zero-day attacks
   - Files: *.pcap or *.csv

CLASSIC DATASETS
================

1. CIC-IDS 2017
   - Download from: https://www.unb.ca/cic/datasets/ids-2017.html
   - Extract to: data/ids_datasets/CIC-IDS-2017/
   - Files: *.csv

2. CIC-DDoS 2019
   - Download from: https://www.unb.ca/cic/datasets/ddos-2019.html
   - Extract to: data/ids_datasets/CIC-DDoS-2019/
   - Files: *.csv

3. CSE-CIC-IDS 2018
   - Download from: https://www.unb.ca/cic/datasets/ids-2018.html
   - Extract to: data/ids_datasets/CSE-CIC-IDS-2018/
   - Files: *.csv

4. UNSW-NB15
   - Download from: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/
   - Extract to: data/ids_datasets/UNSW-NB15/
   - Files: *.csv

5. NSL-KDD
   - Download from: https://www.unb.ca/cic/datasets/nsl-kdd.html
   - Extract to: data/ids_datasets/NSL-KDD/
   - Files: *.txt or *.csv

6. KDD Cup 1999
   - Download from: http://kdd.ics.uci.edu/databases/kddcup99/
   - Extract to: data/ids_datasets/KDD-CUP-1999/
   - Files: *.data

7. TON_IoT
   - Download from: https://research.unsw.edu.au/projects/toniot-datasets
   - Extract to: data/ids_datasets/TON-IoT/
   - Files: *.csv

8. Bot-IoT
   - Download from: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/Bot-IoT/
   - Extract to: data/ids_datasets/Bot-IoT/
   - Files: *.csv

9. MAWI Traffic Archive
   - Download from: http://mawi.wide.ad.jp/mawi/
   - Extract to: data/ids_datasets/MAWI/
   - Files: *.pcap or *.csv

10. Kyoto 2006+ Honeypot
    - Download from: http://www.takakura.com/Kyoto_data/
    - Extract to: data/ids_datasets/Kyoto-2006/
    - Files: *.txt or *.csv

11. DARPA Intrusion Detection Evaluation
    - Download from: https://www.ll.mit.edu/r-d/datasets/
    - Extract to: data/ids_datasets/DARPA/
    - Files: *.txt or *.csv

QUICK START
===========

1. Create the data directory:
   mkdir -p data/ids_datasets

2. Download datasets from the URLs above

3. Extract them to the corresponding directories

4. Run the training script:
   python -m src.train_live_threat_model

NOTE: If you don't have the datasets downloaded, the trainer will create
a synthetic dataset for demonstration purposes.
"""
        return instructions
    
    @classmethod
    def check_available_datasets(cls):
        """Check which datasets are available locally."""
        print("\nChecking available datasets...")
        available = []
        missing = []
        
        for dataset_name, info in cls.DATASETS.items():
            path = info['local_path']
            if path.exists() and any(path.glob('*.csv')) or any(path.glob('*.txt')) or any(path.glob('*.data')):
                available.append(dataset_name)
                print(f"✓ {dataset_name} - Found")
            else:
                missing.append(dataset_name)
                print(f"✗ {dataset_name} - Missing")
        
        return available, missing
    
    @classmethod
    def load_datasets(cls):
        """Load all available datasets."""
        print("\nLoading available datasets...")
        all_data = []
        
        for dataset_name, info in cls.DATASETS.items():
            path = info['local_path']
            if not path.exists():
                continue
            
            # Try to load CSV files
            csv_files = list(path.glob('*.csv'))
            if csv_files:
                try:
                    for csv_file in csv_files[:1]:  # Load first CSV
                        print(f"Loading {dataset_name} from {csv_file.name}...")
                        df = pd.read_csv(csv_file, nrows=10000)  # Limit rows
                        all_data.append(df)
                except Exception as e:
                    print(f"Error loading {dataset_name}: {e}")
            
            # Try to load TXT files
            txt_files = list(path.glob('*.txt'))
            if txt_files and not csv_files:
                try:
                    for txt_file in txt_files[:1]:
                        print(f"Loading {dataset_name} from {txt_file.name}...")
                        df = pd.read_csv(txt_file, nrows=10000)
                        all_data.append(df)
                except Exception as e:
                    print(f"Error loading {dataset_name}: {e}")
        
        if all_data:
            print(f"\nCombining {len(all_data)} datasets...")
            combined_df = pd.concat(all_data, ignore_index=True)
            return combined_df
        else:
            return None


def main():
    """Main function."""
    print("\n" + "=" * 80)
    print("IDS DATASET MANAGEMENT")
    print("=" * 80)
    
    # Print dataset information
    IDSDatasetDownloader.print_dataset_info()
    
    # Check available datasets
    available, missing = IDSDatasetDownloader.check_available_datasets()
    
    print(f"\n\nSummary:")
    print(f"Available: {len(available)}")
    print(f"Missing: {len(missing)}")
    
    # Print download instructions
    print(IDSDatasetDownloader.get_download_instructions())


if __name__ == "__main__":
    main()
