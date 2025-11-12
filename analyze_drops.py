import re
import os
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

LOG_FILE = "packet_drops.log"
OUTPUT_DIR = "plots"
os.makedirs(OUTPUT_DIR, exist_ok=True)

entries = []

with open(LOG_FILE, "r") as f:
    data = f.read()

blocks = re.split(r"(?=\[\d{4}-\d{2}-\d{2})", data)
blocks = [b.strip() for b in blocks if b.strip()]

for block in blocks:
    entry = {}

    # Timestamp extraction (fallback = current time)
    ts_match = re.search(r"\[(\d{4}-\d{2}-\d{2}.*?)\]", block)
    entry["timestamp"] = ts_match.group(1) if ts_match else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Field extraction
    pid_match = re.search(r"PID:\s*(\d+)", block)
    comm_match = re.search(r"COMM:\s*([^\n]+)", block)
    proto_match = re.search(r"Protocol:\s*([A-Za-z0-9\(\)]+)", block)
    len_match = re.search(r"Length:\s*(\d+)", block)
    reason_match = re.search(r"Reason:\s*([A-Z0-9_]+)?", block)
    if_match = re.search(r"IF:\s*([a-zA-Z0-9_]+)?", block)

    entry["pid"] = int(pid_match.group(1)) if pid_match else 0
    entry["comm"] = comm_match.group(1).strip() if comm_match else "unknown"
    entry["protocol"] = proto_match.group(1) if proto_match else "Other(0)"
    entry["length"] = int(len_match.group(1)) if len_match else 0
    entry["reason"] = reason_match.group(1) if reason_match and reason_match.group(1) else "UNKNOWN"
    entry["interface"] = if_match.group(1) if if_match and if_match.group(1) else "unknown"

    entries.append(entry)

df = pd.DataFrame(entries)
print("Parsed entries:", len(df))
print(df.head())

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df["protocol"] = df["protocol"].fillna("Other(0)")
df["reason"] = df["reason"].fillna("UNKNOWN")
df["interface"] = df["interface"].fillna("unknown")
df["comm"] = df["comm"].fillna("unknown")

def save_plot(name):
    plt.tight_layout()
    filepath = os.path.join(OUTPUT_DIR, f"{name}.png")
    plt.savefig(filepath)
    plt.close()
    print(f"Saved plot: {filepath}")

# Plot - Drops by Protocol
plt.figure(figsize=(8, 4))
df["protocol"].value_counts().plot(kind="bar")
plt.title("Packet Drops by Protocol")
plt.ylabel("Drop Count")
plt.xlabel("Protocol")
save_plot("drops_by_protocol")

# Plot - Drops by Reason
plt.figure(figsize=(10, 5))
df["reason"].value_counts().head(15).plot(kind="barh")
plt.title("Top 15 Drop Reasons")
plt.xlabel("Drop Count")
plt.ylabel("Reason")
save_plot("drops_by_reason")

# Plot - Drops by Process (COMM)
plt.figure(figsize=(10, 5))
df["comm"].value_counts().head(10).plot(kind="bar")
plt.title("Top Processes Causing Drops")
plt.xlabel("Process (COMM)")
plt.ylabel("Drop Count")
plt.xticks(rotation=45, ha="right")
save_plot("drops_by_process")

# Plot - Drops by Interface
plt.figure(figsize=(8, 4))
df["interface"].value_counts().plot(kind="bar")
plt.title("Packet Drops by Interface")
plt.xlabel("Interface")
plt.ylabel("Drop Count")
save_plot("drops_by_interface")

# Packet Size Distribution
plt.figure(figsize=(8, 4))
df["length"].plot(kind="hist", bins=20, alpha=0.7)
plt.title("Distribution of Dropped Packet Sizes")
plt.xlabel("Packet Length (bytes)")
plt.ylabel("Frequency")
save_plot("packet_length_distribution")

print("\nAll plots generated successfully in the 'plots/' folder.")
