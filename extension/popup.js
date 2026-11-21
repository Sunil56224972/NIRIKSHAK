const DEFAULT_SERVER = "http://127.0.0.1:8000";

document.addEventListener("DOMContentLoaded", async () => {
  const input = document.getElementById("u");
  const out = document.getElementById("out");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.url && tab.url.startsWith("http")) {
    input.value = tab.url;
  }

  document.getElementById("full").addEventListener("click", async () => {
    const url = input.value.trim();
    const target = url
      ? `${DEFAULT_SERVER}/check?u=${encodeURIComponent(url)}`
      : `${DEFAULT_SERVER}/report`;
    chrome.tabs.create({ url: target });
  });

  document.getElementById("go").addEventListener("click", async () => {
    const url = input.value.trim();
    if (!url) return;
    out.textContent = "Checking...";
    try {
      const r = await fetch(`${DEFAULT_SERVER}/api/check?u=${encodeURIComponent(url)}`);
      const d = await r.json();
      if (d.error) {
        out.textContent = d.error;
        return;
      }
      out.innerHTML = '';
      const badge = document.createElement("div");
      badge.className = d.level;
      badge.textContent = `${d.level} RISK (${d.score}/100)`;
      out.appendChild(badge);
      (d.reasons || []).forEach((item) => {
        const p = document.createElement("div");
        p.textContent = `• ${item.title}`;
        out.appendChild(p);
      });
    } catch (e) {
      out.textContent = "Server unreachable at " + DEFAULT_SERVER;
    }
  });
});
