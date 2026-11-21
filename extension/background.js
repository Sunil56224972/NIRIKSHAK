const DEFAULT_SERVER = "https://nirikshak-ten.vercel.app";

function normalizeServer(raw) {
  const s = (raw || "").trim().replace(/\/+$/, "");
  return /^https?:\/\/[^/\s]+/i.test(s) ? s : DEFAULT_SERVER;
}

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
    const server = normalizeServer(cfg.server);
    const target = `${server}/check?u=${encodeURIComponent(info.linkUrl)}`;
    chrome.tabs.create({ url: target });
  }
});
