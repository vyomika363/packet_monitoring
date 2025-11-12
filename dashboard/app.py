from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import subprocess
import threading
import signal
import time
import sys
import re
from collections import deque
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "packet-monitor-secret"
socketio = SocketIO(app, cors_allowed_origins="*")

# Shared data
packet_events = deque(maxlen=1000)
stats = {
    "total_drops": 0,
    "tcp_drops": 0,
    "udp_drops": 0,
    "other_drops": 0
}
monitor_running = False
monitor_process = None


def parse_event_line(line):
    """Parse one line from CLI output into structured fields."""
    line = line.strip()
    if not line or not line.startswith("["):
        return None

    try:
        timestamp_match = re.search(r"\[(.*?)\]", line)
        pid_comm_match = re.search(r"PID:\s*(\d+),\s*COMM:\s*(.*)", line)
        if not pid_comm_match:
            return None

        timestamp = timestamp_match.group(1) if timestamp_match else ""
        pid = pid_comm_match.group(1)
        comm = pid_comm_match.group(2).strip()

        # Expect next 2 lines with IP/protocol info
        next_lines = []
        for _ in range(2):
            try:
                next_line = monitor_process.stdout.readline().strip()
                if next_line:
                    next_lines.append(next_line)
            except Exception:
                pass

        full_block = " ".join(next_lines)

        event = {
            "timestamp": timestamp,
            "pid": pid,
            "comm": comm,
            "ifname": "",
            "src_ip": "",
            "src_port": "",
            "dst_ip": "",
            "dst_port": "",
            "protocol": "",
            "length": "",
            "reason": ""
        }

        ip_match = re.search(
            r"IF:\s*(\S*),\s*([\d\.]+):(\d+)\s*->\s*([\d\.]+):(\d+)", full_block
        )
        proto_match = re.search(
            r"Protocol:\s*([A-Za-z0-9\(\)]+),\s*Length:\s*(\d+).*Reason:\s*(.*)", full_block
        )

        if ip_match:
            event.update({
                "ifname": ip_match.group(1),
                "src_ip": ip_match.group(2),
                "src_port": ip_match.group(3),
                "dst_ip": ip_match.group(4),
                "dst_port": ip_match.group(5)
            })

        if proto_match:
            event.update({
                "protocol": proto_match.group(1),
                "length": proto_match.group(2),
                "reason": proto_match.group(3).strip()
            })

        # Stats counter
        proto = event["protocol"].upper()
        if proto == "TCP":
            stats["tcp_drops"] += 1
        elif proto == "UDP":
            stats["udp_drops"] += 1
        elif proto == "ICMP":
            stats["icmp_drops"] += 1
        else:
            stats["other_drops"] += 1
        stats["total_drops"] += 1

        return event

    except Exception as e:
        print("Parse error:", e)
        return None


def monitor_packets():
    """Run CLI tool in background and stream parsed data to dashboard."""
    global monitor_running, monitor_process
    cmd = ["sudo", "python3", "-u", "../packet_monitoring_cli.py"]
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    monitor_process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env
    )

    print("[INFO] CLI started, waiting for packets...")

    while monitor_running and monitor_process.poll() is None:
        line = monitor_process.stdout.readline()
        if line:
            event = parse_event_line(line)
            if event and any(event.values()):
                packet_events.append(event)
                socketio.emit("packet_event", event)
                print(f"[EMIT] {event}")  # Debug in terminal
        time.sleep(0.05)

    if monitor_process and monitor_process.poll() is None:
        monitor_process.terminate()
    print("[INFO] CLI stopped.")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def get_stats():
    return jsonify(stats)


@app.route("/api/events")
def get_events():
    return jsonify(list(packet_events)[-100:])


@socketio.on("connect")
def on_connect():
    print("Client connected")
    emit("initial_data", {"stats": stats, "events": list(packet_events)[-50:]})


@socketio.on("disconnect")
def on_disconnect():
    print("Client disconnected")


@socketio.on("start_monitor")
def start_monitor():
    global monitor_running
    if not monitor_running:
        monitor_running = True
        thread = threading.Thread(target=monitor_packets, daemon=True)
        thread.start()
        emit("status", {"running": True})


@socketio.on("stop_monitor")
def stop_monitor():
    global monitor_running, monitor_process
    monitor_running = False
    if monitor_process:
        monitor_process.terminate()
        monitor_process = None
    emit("status", {"running": False})


def signal_handler(sig, frame):
    global monitor_running, monitor_process
    monitor_running = False
    if monitor_process:
        monitor_process.terminate()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    print("Starting dashboard on http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
