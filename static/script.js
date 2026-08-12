let monitoring = true;

// The page elements
const ip = document.getElementById("ip");
const connections = document.getElementById("connections");
const ports = document.getElementById("ports");
const attack = document.getElementById("attack");
const severity = document.getElementById("severity");
const status = document.getElementById("status");
const time = document.getElementById("time");

//Refresh Data
function loadData() {

    if (!monitoring) return;

    fetch("/data")
        .then(response => response.json())
        .then(data => {

            if (data.length === 0) return;

            let d = data[0];

            ip.textContent = d.ip;
            connections.textContent = d.connections;
            ports.textContent = d.ports;
            attack.textContent = d.type;

            time.textContent = new Date().toLocaleTimeString();

            if (d.type === "Normal") {

                severity.textContent = "LOW";
                status.textContent = "Monitoring";

            } else if (d.type === "Port Scanning") {

                severity.textContent = "MEDIUM";
                status.textContent = "Threat Detected";

            } else if (d.type === "SSH Brute Force") {

                severity.textContent = "HIGH";
                status.textContent = "Threat Detected";

            } else {

                severity.textContent = "CRITICAL";
                status.textContent = "Threat Detected";
            }

        })
        .catch(err => console.log(err));
}

//Refresh every second
setInterval(loadData, 1000);

//Start Button
document.getElementById("startBtn").addEventListener("click", () => {

    monitoring = true;

});

// Reset Button
document.getElementById("resetBtn").addEventListener("click", () => {

    monitoring = false;

    ip.textContent = "--";
    connections.textContent = "0";
    ports.textContent = "0";
    attack.textContent = "--";
    severity.textContent = "LOW";
    status.textContent = "Monitoring";
    time.textContent = "--:--:--";

});
