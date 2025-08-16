document.addEventListener("DOMContentLoaded", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const currentUrl = tabs[0].url;
        document.getElementById("urlBox").textContent = currentUrl;

        chrome.runtime.sendMessage({ action: "checkUrl" }, (response) => {
            const statusEl = document.getElementById("status");
            const iconEl = document.getElementById("icon");

            if (response.status === "safe") {
                statusEl.innerHTML = `<i class="fa-solid fa-check" style="color: #40e74eff;"></i> Safe Website`;
                statusEl.className = "safe";
                iconEl.src = "icons/safe.png";
                updateRisk(100); // Green bar 
            } else if (response.status === "warning") {
                statusEl.innerHTML = `<i class="fa-solid fa-triangle-exclamation" style="color: #f8be42ff;"></i> Suspicious Website`;
                statusEl.className = "warning";
                iconEl.src = "icons/warning.png";
                updateRisk(50); // Yellow bar
            } else {
                statusEl.innerHTML = `<i class="fa-solid fa-xmark" style="color: #e74040;"></i> Dangerous Website!`;
                statusEl.className = "danger";
                iconEl.src = "icons/danger.png";
                updateRisk(20); // Red bar
            }
        });
    });
});

// Risk Bar Function
function updateRisk(score) {
    const bar = document.getElementById("riskBar");
    bar.style.width = score + "%";

    if (score > 80) {
        bar.style.background = "#27ae60"; // green
    } else if (score > 40) {
        bar.style.background = "#f39c12"; // yellow
    } else {
        bar.style.background = "#e74c3c"; // red
    }
}


// http://testsafebrowsing.appspot.com/s/phishing.html
// http://testsafebrowsing.appspot.com/s/unwanted.html
// http://testsafebrowsing.appspot.com/s/malware.html

