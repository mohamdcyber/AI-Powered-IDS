from elasticsearch import Elasticsearch
import pandas as pd
from sklearn.ensemble import IsolationForest
from flask import Flask, render_template, jsonify
from datetime import datetime
import os
app = Flask(__name__)

monitor_start_time = None

# Connection.
es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", os.getenv("ELASTIC_PASSWORD")),
    verify_certs=False,
    headers={"Accept": "application/json", "Content-type": "application/json"}
)

def analyze():
    res = es.search(index="filebeat-*", 
                    size=2000,
                    sort =[{"@timestamp": {"order": "desc"}}] )

    records = []

    for hit in res["hits"]["hits"]:
        src = hit["_source"].get("source", {}).get("ip")
        port = hit["_source"].get("destination", {}).get("port")
        proto = hit["_source"].get("network", {}).get("transport")

        event_time = hit["_source"].get("@timestamp")

        if monitor_start_time and event_time:
            event_dt = datetime.fromisoformat(
                   event_time.replace("Z", "+00:00")
            ).replace(tzinfo=None)

            if event_dt < monitor_start_time:
                continue

            if src == "192.168.42.129":
                continue

        if src:
            records.append({
                "ip": src,
                "port": port,
                "proto": proto
            })

    df = pd.DataFrame(records)

    if df.empty:
        return []

    # Aggregation according to IP
    grouped = df.groupby("ip").agg({
        "port": ["count", "nunique"]
    })

    grouped.columns = ["connections", "unique_ports"]
    grouped = grouped.reset_index()

    #Redairect IP into digital.
    grouped["ip_num"] = grouped["ip"].apply(lambda x: hash(x) % 10000)

    X = grouped[["connections", "unique_ports", "ip_num"]]

    # AI
    model = IsolationForest(contamination=0.1)
    grouped["anomaly"] = model.fit_predict(X)

    results = []

    for _, row in grouped.iterrows():
        attack = "Normal"

        #The rules
        if row["connections"] > 50 and row["unique_ports"] == 1:
            attack = "SSH Brute Force"
        elif row["unique_ports"] > 20:
            attack = "Port Scanning"
        elif row["connections"] > 200:
            attack = "Possible DDoS"

        if row["anomaly"] == -1:
            results.append({
                "ip": row["ip"],
                "connections": int(row["connections"]),
                "ports": int(row["unique_ports"]),
                "type": attack
            })

    return results


@app.route("/")
def index():
    data = analyze()
    return render_template("index.html", data=data)

@app.route("/data")
def data():

    results = analyze()

    if len(results) == 0:
        return jsonify([])

    row = results[0]

    severity = "LOW"

    if row["type"] == "SSH Brute Force":
        severity = "HIGH"

    elif row["type"] == "Port Scanning":
        severity = "MEDIUM"

    elif row["type"] == "Possible DDoS":
        severity = "CRITICAL"

    row["severity"] = severity

    return jsonify(results)

@app.route("/start")
def start_monitoring():
    global monitor_start_time
    monitor_start_time = datetime.utcnow()
    return jsonify({"status": "started"})

if __name__ == "__main__":
    app.run(debug=True)
