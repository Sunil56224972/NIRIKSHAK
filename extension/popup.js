const DEFAULT_SERVER = "https://nirikshak-ten.vercel.app";

function normalizeServer(raw) {
  const s = (raw || "").trim().replace(/\/+$/, "");
  return /^https?:\/\/[^/\s]+/i.test(s) ? s : null;
}

document.addEventListener("DOMContentLoaded", async () => {
  const input = document.getElementById("u");
  const out = document.getElementById("out");
  const srvInput = document.getElementById("srv");
  const srvMsg = document.getElementById("srv-msg");

  const cfg = await chrome.storage.local.get({ server: DEFAULT_SERVER });
  let activeServer = normalizeServer(cfg.server) || DEFAULT_SERVER;
  srvInput.value = activeServer;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.url && tab.url.startsWith("http")) {
    input.value = tab.url;
  }

  document.getElementById("save-srv").addEventListener("click", async () => {
    const parsed = normalizeServer(srvInput.value);
    if (!parsed) {
      srvMsg.textContent = "Enter a valid http:// or https:// server URL.";
      srvMsg.style.color = "#a3201b";
      return;
    }
    activeServer = parsed;
    srvInput.value = parsed;
    await chrome.storage.local.set({ server: parsed });
    srvMsg.textContent = "Saved: " + parsed;
    srvMsg.style.color = "#2f6b2f";
  });

  document.getElementById("full").addEventListener("click", async () => {
    const url = input.value.trim();
    const target = url
      ? `${activeServer}/check?u=${encodeURIComponent(url)}`
      : `${activeServer}/report`;
    chrome.tabs.create({ url: target });
  });

  document.getElementById("go").addEventListener("click", async () => {
    const url = input.value.trim();
    if (!url) return;
    out.textContent = "Checking...";
    try {
      const r = await fetch(`${activeServer}/api/check?u=${encodeURIComponent(url)}`);
      const d = await r.json();
      if (d.error) {
        out.textContent = d.error;
        return;
      }
      out.textContent = "";
      const badge = document.createElement("div");
      badge.className = d.level;
      badge.textContent = `${d.level} RISK (${d.score}/100)`;
      out.appendChild(badge);
      if (d.linked_cases > 0) {
        const linked = document.createElement("div");
        linked.className = "linked";
        linked.textContent = `Previously reported in ${d.linked_cases} case(s)`;
        out.appendChild(linked);
      }
      (d.reasons || []).forEach((item) => {
        const p = document.createElement("div");
        p.textContent = `• ${item.title}`;
        out.appendChild(p);
      });
    } catch (e) {
      out.textContent = "Server unreachable at " + activeServer;
    }
  });
});
