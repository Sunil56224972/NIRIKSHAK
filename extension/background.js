const DEFAULT_SERVER = "http://127.0.0.1:8000";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "nirikshak-check-link",
    title: "Inspect link with NIRIKSHAK",
    contexts: ["link"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId === "nirikshak-check-link" && info.linkUrl) {
    const cfg = await chrome.storage.local.get({ server: DEFAULT_SERVER });
    const target = `${cfg.server.replace(/\/$/, "")}/check?u=${encodeURIComponent(info.linkUrl)}`;
    chrome.tabs.create({ url: target });
  }
});
