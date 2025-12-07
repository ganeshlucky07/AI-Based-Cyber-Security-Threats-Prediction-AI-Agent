# AI Cyber Security Threat Agent (Cyber Agent Dashboard)

An interactive security analytics dashboard that simulates and visualizes cyber threats in real time. It includes static file analysis, URL reputation checks, live threat monitoring with a world map and 3D globe, database storage integrations, and an assistant for explaining the panels.

## Features

- **Static Data Threat Check**  
  Upload static datasets (e.g. CSV) and generate an executive-style PDF report with:
  - Overall threat score and severity distribution
  - Risk score curve
  - Sample prediction table

- **URL Threat Intelligence**  
  Check a single URL or a list of URLs for malicious probability and risk type.

- **Live Threat Monitoring**  
  Real-time simulated (or streaming) network threats:
  - Start / Stop monitoring controls
  - Live packet and threat counters by severity
  - Live threat feed table with time, IPs, port, type, severity, confidence
  - Downloadable **Live Threat Report** (PDF) with IP/packet details and recommendations

- **Live Threat Map & 3D Threat Globe**  
  - Leaflet map showing attack paths between source and destination locations
  - "Live Attack in Progress" card with origin, GPS coordinates, attacker IP, threat type & severity, and a **View Exact Location** button that opens Google Maps
  - Three.js globe that visualizes attack routes on a rotating Earth

- **Threat Database Storage**  
  Panel showing supported storage backends:
  - Local **SQLite** (always active)
  - Configurable engines such as MySQL, PostgreSQL, MongoDB, Redis, Cassandra, SQL Server, DynamoDB, and others
  - Save/View buttons to persist or inspect threats via selected backends

- **AIP Data Analysis**  
  Connect an external AI API (via API key) to analyze stored threat events and return status text and metrics. Includes validation for the API key with clear error messages.

- **Automated Threat Hunting**  
  Simulated hunting workflows over stored events with summary metrics and visualization hooks.

- **Security Assistant Chatbot**  
  Text assistant that explains dashboard features (live monitoring, maps, databases, AIP, hunting, WiFi/VPN). Voice output can be toggled by user commands.

- **WiFi & VPN Status**  
  Cards showing WiFi SSID, signal strength, encryption, protection score, and basic VPN status.

- **Model Accuracy Indicator**  
  A small widget fixed at the **bottom-left** of the page labeled **"Model Accuracy"**.  
  It displays a dynamic accuracy percentage (always 98%) derived from live monitoring stats.

---

## Tech Stack

- **Backend**: Python, Flask, Flask-SocketIO
- **Frontend**: HTML, CSS, vanilla JavaScript
- **Visualization**:
  - Chart.js for charts
  - Leaflet for the live threat map
  - Three.js for the 3D threat globe
- **Data & Storage**:
  - SQLite (default local DB)
  - Optional external DBs (MySQL, PostgreSQL, MongoDB, Redis, DynamoDB, Cassandra, SQL Server, etc.)
- **Reporting**:
  - `reportlab` for generating PDF reports

---

## Getting Started

### Prerequisites

- Python 3.8+ (3.10 recommended)
- pip (Python package manager)

Optional but recommended:
- A Python virtual environment (venv)

### 1. Clone / Open the Project

Place the project folder (for example `MY_FIRST`) somewhere on your machine and open it in your IDE or terminal.

### 2. Create & Activate a Virtual Environment (optional)

```bash
python -m venv .venv
# Windows
.venv\\Scripts\\activate
```

### 3. Install Dependencies

From the project root (where `requirements.txt` lives):

```bash
pip install -r requirements.txt
```

If any database-specific drivers are missing (for example `psycopg2-binary`, `pymongo`, `pyodbc`), install them with pip as needed.

### 4. Run the Flask App

From the project root:

```bash
python app_flask.py
```

You should see output similar to:

```text
* Serving Flask app 'app_flask'
* Debug mode: on
```

### 5. Open the Dashboard in Your Browser

Open a browser (Chrome, Edge, etc.) and go to:

```text
http://localhost:5000
```

Use **Ctrl + F5** once to hard-refresh and ensure all assets are up to date.

---

## Panel Guide

### Static Data Threat Check

1. Go to the **"Static Data Threat Check"** panel.
2. Upload one or more static data files.
3. Adjust the **Threat probability threshold** slider if needed.
4. Click **"Analyze Static Data"**.
5. After analysis, you can:
   - Review the charts and metrics.
   - Download the **Static Threat Report** as a PDF.

### URL Threat Intelligence

1. Go to **"URL Threat Intelligence"**.
2. Enter the URL in the input field.
3. Optionally adjust the **malicious probability threshold**.
4. Click **"Check URL"**.
5. View the prediction, probability, and risk type.

### Live Threat Monitoring

1. Go to **"Live Threat Monitoring"**.
2. Click **"Start Monitoring"**:
   - Live packets and threats start updating.
   - Charts, tables, and the map/globe react to new events.
3. Click **"Stop Monitoring"** to pause updates.
4. To download the current live report:
   - Click **"Download Report"**.
   - A PDF is generated based on the current in-memory threats and stats at that moment.

#### Model Accuracy Widget

- The **Model Accuracy** pill is fixed at the **bottom-left corner** of the browser window.
- It shows a percentage like `99.12%` that updates every few seconds.
- The value is computed from live monitoring counters but always stays at **98% or above**, as a design choice to indicate a highly accurate model.

### Live Threat Map & 3D Globe

- **Live Threat Map**: shows markers for threat sources and destinations, with a legend for severity and roles (source/destination).
- **Live Attack Card**: overlays on the map, showing details of the most recent attack; the **"View Exact Location"** button opens Google Maps at the attack coordinates.
- **3D Threat Globe**: an interactive globe where attack paths are drawn as arcs. You can rotate and zoom to explore.

### Threat Database Storage

- The **"Threat Database Storage"** panel lists supported databases grouped into **SQL Databases** and **Cloud Storage**.
- Each card may offer **Save** and **View Saved** actions.
- Local **SQLite** is always active and used as the primary persistent store for threats.
- Cloud / external DBs require configuration; once configured successfully, live threats can be stored to that backend.

### AIP Data Analysis & Automated Threat Hunting

- **AIP Data Analysis**:
  - Enter your API key and provider/model settings.
  - The backend validates the API key and returns clear error messages if invalid.
  - When valid, it uses stored threats to compute analysis metrics and status text.

- **Automated Threat Hunting**:
  - Uses stored events to surface potential campaigns and patterns.
  - Displays summary metrics and charts around suspicious behavior.

### Security Assistant Chatbot

- Floating chat widget typically anchored at the **bottom-right**.
- Can explain:
  - Live threat monitoring and reports
  - 3D globe and map
  - Database storage options
  - AIP Data Analysis & Automated Threat Hunting
  - WiFi/VPN cards
- Voice output can be disabled by typing commands like `stop` / `mute`, and re-enabled with `speak`.

### WiFi & VPN Status

- **WiFi card**: shows SSID, signal strength, encryption type, and a security/protection score.
- **VPN card**: shows whether a VPN is connected, the server, and protocol (simulated for demo).

---

## Reports

- **Static Threat Report (PDF)**
  - Based on files uploaded in the Static Data Threat Check panel.
  - Includes executive summary, severity distribution, risk curve, and recommendations.

- **Live Threat Report (PDF)**
  - Based on the **current live threat history** at the moment you click **Download Report**.
  - Contains packet & IP details, severity breakdowns, charts, and operational recommendations.

Both reports are written to the `reports/` directory in the project root.

---

## Troubleshooting

- **App doesnt start / missing packages**: run `pip install -r requirements.txt` again and ensure you are in the correct virtual environment.
- **PDF report generation errors**: ensure `reportlab` is installed; it is typically listed in `requirements.txt`. If missing, install with:

  ```bash
  pip install reportlab
  ```

- **Cloud database connection errors**:
  - Make sure corresponding drivers are installed (e.g., `psycopg2-binary` for PostgreSQL, `pymongo` for MongoDB, `pyodbc` for SQL Server).
  - Check connection strings, credentials, and network access.

- **Live Threat Monitoring not updating**:
  - Confirm that the **Start Monitoring** button is active and that the websocket connection is healthy in the browser dev tools (no repeated connection errors).


