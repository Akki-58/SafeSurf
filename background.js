import { API_KEY } from './config.js';
const API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;

const MAX_CACHE_SIZE = 500; // limit cache to 500 URLs
let urlCache = {};

// Load cache from chrome.storage.local on startup
chrome.storage.local.get("safeSurfCache", (result) => {
    if (result.safeSurfCache) {
        urlCache = result.safeSurfCache;
    }
});

// Save cache back to storage (helper)
function saveCache() {
    chrome.storage.local.set({ safeSurfCache: urlCache });
}

// Ensure cache size doesn't exceed MAX_CACHE_SIZE
function CacheLimit() {
    const keys = Object.keys(urlCache);
    if (keys.length > MAX_CACHE_SIZE) {
        // Sort by oldest timestamp
        keys.sort((a, b) => urlCache[a].timestamp - urlCache[b].timestamp);
        const excess = keys.length - MAX_CACHE_SIZE;

        // Delete oldest entries
        for (let i = 0; i < excess; i++) {
            delete urlCache[keys[i]];
        }
    }
}

async function checkUrlSafety(url) {
    // Check in-memory cache first
    if (urlCache[url]) {
        return urlCache[url].status;
    }

    // If not cached, make API call
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
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body)
    });

    const data = await response.json();

    let status
    if (Object.keys(data).length === 0) {
        status = "safe"; // safe
    }
    else{
        const threatType = data.matches[0].threatType;

        if (threatType === "UNWANTED_SOFTWARE") {
            status = "warning"; // Suspicious
        } else {
            status = "danger"; // Dangerous
        }
    }

    // Store result in cache
    urlCache[url] = { status, timestamp: Date.now() };
    CacheLimit();
    saveCache();

    return status;
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
