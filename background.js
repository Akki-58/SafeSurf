import { API_KEY } from './config.js';
const API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;

async function checkUrlSafety(url) {
    const body = {
        client: {
            clientId: "url-trust-checker",
            clientVersion: "1.0"
        },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
        }
    };

    const response = await fetch(API_URL, {
        method: "POST",
        body: JSON.stringify(body)
    });

    const data = await response.json();

    if (Object.keys(data).length === 0) {
        return "safe"; // safe
    }

    const threatType = data.matches[0].threatType;

    if (threatType === "UNWANTED_SOFTWARE") {
        return "warning"; // Suspicious
    } else {
        return "danger"; // Dangerous
    }
}

// Listen for popup request
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "checkUrl") {
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            const url = tabs[0].url;
            const status = await checkUrlSafety(url);
            sendResponse({ status });
        });
        return true; // keep channel open
    }
});
