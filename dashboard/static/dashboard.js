const socket = io();
let isMonitoring = false;

// DOM elements
const statusEl = document.getElementById('status');
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const eventsEl = document.getElementById('events');
const totalDropsEl = document.getElementById('totalDrops');
const tcpDropsEl = document.getElementById('tcpDrops');
const udpDropsEl = document.getElementById('udpDrops');
const otherDropsEl = document.getElementById('otherDrops');

let stats = {
    total_drops: 0,
    tcp_drops: 0,
    udp_drops: 0,
    other_drops: 0
};

// Throttle UI updates
let lastRender = 0;
const RENDER_INTERVAL = 10;

// Socket event handlers
socket.on('connect', () => console.log('Connected to server'));
socket.on('disconnect', () => updateStatus(false));

socket.on('initial_data', (data) => {
    stats = data.stats;
    updateStats();
    data.events.forEach(addEvent);
});

socket.on('packet_event', (event) => {
    stats.total_drops++;

    const proto = (event.protocol || "").toUpperCase();
    if (proto.includes("TCP")) stats.tcp_drops++;
    else if (proto.includes("UDP")) stats.udp_drops++;
    else stats.other_drops++;

    const now = Date.now();
    if (now - lastRender > RENDER_INTERVAL) {
        updateStats();
        addEvent(event);
        lastRender = now;
    }
});

socket.on('status', (data) => updateStatus(data.running));

// Control buttons
function startMonitor() {
    socket.emit('start_monitor');
    updateStatus(true);
}

function stopMonitor() {
    socket.emit('stop_monitor');
    updateStatus(false);
}

function clearEvents() {
    eventsEl.innerHTML = '';
}

// UI update functions
function updateStatus(running) {
    isMonitoring = running;
    statusEl.textContent = running ? 'Running' : 'Stopped';
    statusEl.className = running ? 'status running' : 'status stopped';
    startBtn.disabled = running;
    stopBtn.disabled = !running;
}

function updateStats() {
    totalDropsEl.textContent = stats.total_drops.toLocaleString();
    tcpDropsEl.textContent = stats.tcp_drops.toLocaleString();
    udpDropsEl.textContent = stats.udp_drops.toLocaleString();
    otherDropsEl.textContent = stats.other_drops.toLocaleString();
}

function addEvent(event) {
    const eventEl = document.createElement('div');
    eventEl.className = 'event';

    const colorMap = { TCP: "#00ff99", UDP: "#3399ff", OTHER: "#888" };
    const proto = (event.protocol || "OTHER").toUpperCase();
    eventEl.style.borderLeft = `4px solid ${colorMap[proto] || "#888"}`;

    const timestamp = event.timestamp || new Date().toLocaleTimeString();

    eventEl.innerHTML = `
        <strong>[${timestamp}] ${proto}</strong><br>
        <b>PID:</b> ${event.pid || '—'} | <b>COMM:</b> ${event.comm || '—'}<br>
        <b>Interface:</b> ${event.ifname || '—'}<br>
        <b>Source:</b> ${event.src_ip || '—'}:${event.src_port || '—'}<br>
        <b>Destination:</b> ${event.dst_ip || '—'}:${event.dst_port || '—'}<br>
        <b>Length:</b> ${event.length || 0} bytes<br>
        <b>Reason:</b> ${event.reason || '—'}
    `;

    eventsEl.insertBefore(eventEl, eventsEl.firstChild);
    while (eventsEl.children.length > 100) eventsEl.removeChild(eventsEl.lastChild);
}

// Initialize stats
fetch('/api/stats')
    .then(res => res.json())
    .then(data => {
        stats = data;
        updateStats();
    });
