# Quick Start Guide - Live Threat Prediction System

## 🚀 Get Started in 3 Steps

### Step 1: Start the Application
```bash
python app_flask.py
```

### Step 2: Open in Browser
```
http://localhost:5000
```

### Step 3: Click "Start Monitoring"
Watch real-time threats appear!

---

## 📋 Common Commands

### Run the Application
```bash
python app_flask.py
```

### Train the Live Threat Model
```bash
python -m src.train_live_threat_model
```

### Check Available Datasets
```bash
python -m src.download_ids_datasets
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Install WebSocket Support
```bash
pip install flask-socketio python-engineio python-socketio
```

---

## 🎯 Dashboard Overview

### When You Click "Start Monitoring"

**Top Section - Key Metrics**
```
Total Threats: 0  |  Critical: 0  |  High: 0  |  Medium: 0  |  Low: 0  |  Packets: 0
```

**Middle Section - Charts (3 columns)**
1. Threat Severity Distribution (Doughnut)
2. Attack Type Distribution (Bar)
3. Attack Category Distribution (Pie)

**Bottom Section - Live Threat Feed**
```
Time | Source IP | Dest IP | Port | Threat Type | Severity | Confidence
```

---

## 📊 What Each Chart Shows

### Severity Distribution
- Red = Critical threats
- Orange = High threats
- Yellow = Medium threats
- Green = Low threats

### Attack Type Distribution
- Port Scan, DDoS, SQL Injection, XSS, Brute Force, etc.
- Sorted by frequency

### Attack Category Distribution
- Network attacks
- Application attacks
- Endpoint attacks
- Web attacks
- Email attacks
- DNS attacks

---

## 🔴 Threat Severity Levels

| Severity | Confidence | Color | Action |
|----------|-----------|-------|--------|
| Critical | >= 85% | Red | Immediate response |
| High | 70-85% | Orange | Urgent investigation |
| Medium | 50-70% | Yellow | Monitor closely |
| Low | < 50% | Green | Log and review |

---

## 📥 Download Report

Click **"📥 Download Report"** button to get CSV file with:
- Timestamp
- Source IP
- Destination IP
- Port
- Threat Type
- Severity
- Confidence Score
- Protocol
- Attack Category

---

## 🔧 Troubleshooting

### App won't start
```bash
# Check if port 5000 is in use
netstat -ano | findstr :5000

# Kill process on port 5000
taskkill /PID <PID> /F
```

### WebSocket not connecting
```bash
# Reinstall socket.io
pip install --upgrade flask-socketio
```

### Model not found error
```bash
# Train the model
python -m src.train_live_threat_model
```

### Charts not showing
- Open browser console: F12
- Check for JavaScript errors
- Refresh page: Ctrl+R

---

## 📁 Important Files

| File | Purpose |
|------|---------|
| `app_flask.py` | Main application |
| `templates/index.html` | Web interface |
| `static/css/styles.css` | Dashboard styling |
| `src/train_live_threat_model.py` | Model training |
| `trained_models/live_threat_model.joblib` | Trained model |

---

## 🎓 Learning Resources

### Understand the System
1. Read `LIVE_THREAT_SETUP_SUMMARY.md`
2. Review `LIVE_THREAT_MODEL_README.md`
3. Check `app_flask.py` code

### Improve the Model
1. Download real datasets
2. Run training with real data
3. Adjust hyperparameters
4. Retrain and test

### Customize the Dashboard
1. Edit `templates/index.html` for layout
2. Modify `static/css/styles.css` for styling
3. Update `app_flask.py` for logic

---

## 🚀 Features

✅ Real-time threat monitoring
✅ Live threat feed with 7 columns
✅ 3 dynamic charts
✅ 6 key metrics
✅ Download threat reports
✅ Start/Stop monitoring
✅ WebSocket real-time updates
✅ Trained ML model
✅ Support for 11 IDS datasets
✅ Responsive design

---

## 📈 Model Information

**Algorithm**: Gradient Boosting Classifier
**Training Data**: 50,000 samples
**Features**: 42 network flow features
**Accuracy**: 73%
**ROC-AUC**: 0.6559

---

## 🔄 Workflow

```
Start App → Open Browser → Click Start Monitoring
    ↓
Background thread generates threats
    ↓
Model predicts severity
    ↓
WebSocket sends updates
    ↓
Dashboard displays in real-time
    ↓
Download report when needed
```

---

## 💡 Tips & Tricks

### Monitor Specific Threats
- Look for patterns in threat feed
- Check severity distribution
- Review attack types

### Improve Accuracy
- Use real IDS datasets
- Retrain model regularly
- Adjust thresholds

### Performance Optimization
- Reduce update frequency
- Limit threat history
- Use simpler models

---

## 🔗 Useful Links

- **CIC Datasets**: https://www.unb.ca/cic/datasets/
- **UNSW Datasets**: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/
- **UCI ML Repository**: https://archive.ics.uci.edu/ml/
- **Scikit-learn Docs**: https://scikit-learn.org/
- **Flask-SocketIO**: https://flask-socketio.readthedocs.io/

---

## ⚡ Performance Tips

### For Better Accuracy
- Use multiple real datasets
- Increase model complexity
- Fine-tune hyperparameters

### For Faster Performance
- Reduce chart update frequency
- Limit threat feed size
- Use simpler models

### For Better UX
- Customize colors
- Adjust chart sizes
- Modify update intervals

---

## 🎯 Next Steps

1. ✅ Start the app
2. ✅ Click "Start Monitoring"
3. ✅ Watch threats appear
4. ✅ Download a report
5. ⏳ Download real datasets
6. ⏳ Retrain with real data
7. ⏳ Deploy to production

---

## 📞 Quick Help

**Q: How do I start monitoring?**
A: Click the green "🟢 Start Monitoring" button

**Q: How do I stop monitoring?**
A: Click the red "🔴 Stop Monitoring" button

**Q: How do I download threats?**
A: Click "📥 Download Report" button

**Q: Where are the charts?**
A: They appear after you start monitoring

**Q: Can I use real datasets?**
A: Yes! See LIVE_THREAT_MODEL_README.md

**Q: How do I improve accuracy?**
A: Train with real IDS datasets

---

**Version**: 1.0
**Status**: ✅ Ready to Use
**Last Updated**: November 26, 2025

🎉 **You're all set! Start the app and begin monitoring threats!**
