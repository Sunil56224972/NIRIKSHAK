// Small progressive enhancements only; every page works without JavaScript.
(function () {
  // Disable submit buttons while analysis runs (live checks can take ~10-20 s).
  document.querySelectorAll("form[data-busy]").forEach(function (form) {
    form.addEventListener("submit", function () {
      var b = form.querySelector("button[type=submit]");
      if (b) {
        if (!b.dataset.origLabel) b.dataset.origLabel = b.textContent;
        b.disabled = true;
        b.textContent = form.getAttribute("data-busy");
      }
    });
  });

  // Chunked upload staging for large APKs so serverless hosts with tight body limits (e.g. Vercel 4.5 MB) work seamlessly.
  var CHUNK_THRESHOLD = 3.5 * 1024 * 1024;
  var CHUNK_SIZE = 2.5 * 1024 * 1024;

  function showFormError(form, message) {
    var existing = form.parentElement && form.parentElement.querySelector(".note.err[data-chunk-err]");
    if (!existing) {
      existing = document.createElement("div");
      existing.className = "note err";
      existing.setAttribute("data-chunk-err", "1");
      form.parentElement.insertBefore(existing, form);
    }
    existing.textContent = message;
  }

  function randomHex16Bytes() {
    var buf = new Uint8Array(16);
    window.crypto.getRandomValues(buf);
    return Array.from(buf, function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }

  document.querySelectorAll("form[data-chunk-scope]").forEach(function (form) {
    form.addEventListener("submit", async function (e) {
      var fileInput = form.querySelector('input[type="file"][name="file"]');
      var idInput = form.querySelector('input[name="staged_upload_id"]');
      var chunksInput = form.querySelector('input[name="staged_chunks"]');
      var nameInput = form.querySelector('input[name="staged_filename"]');
      if (!fileInput || !fileInput.files || !fileInput.files.length) return;
      var file = fileInput.files[0];
      if (!file || file.size <= CHUNK_THRESHOLD || (idInput && idInput.value)) return;
      if (!window.crypto || !window.crypto.getRandomValues) return;

      e.preventDefault();
      var b = form.querySelector("button[type=submit]");
      var origLabel = (b && b.dataset.origLabel) ? b.dataset.origLabel : (b ? b.textContent : "Submit");
      var csrfInput = form.querySelector('input[name="csrf_token"]');
      var csrfToken = csrfInput ? csrfInput.value : "";
      var scope = form.getAttribute("data-chunk-scope");
      var totalChunks = Math.ceil(file.size / CHUNK_SIZE);
      var uploadId = randomHex16Bytes();

      if (b) b.disabled = true;
      try {
        for (var idx = 0; idx < totalChunks; idx++) {
          if (b) b.textContent = "Uploading file… " + (idx + 1) + "/" + totalChunks;
          var start = idx * CHUNK_SIZE;
          var end = Math.min(file.size, start + CHUNK_SIZE);
          var fd = new FormData();
          fd.append("scope", scope);
          fd.append("upload_id", uploadId);
          fd.append("chunk_index", String(idx));
          fd.append("total_chunks", String(totalChunks));
          fd.append("csrf_token", csrfToken);
          fd.append("chunk", file.slice(start, end), file.name);
          var resp = await fetch("/api/upload/chunk", { method: "POST", body: fd, credentials: "same-origin" });
          var data = null;
          try { data = await resp.json(); } catch (_) {}
          if (!resp.ok || !data || !data.ok) {
            throw new Error((data && data.error) ? data.error : ("Chunk upload failed (HTTP " + resp.status + ")"));
          }
        }
        fileInput.value = "";
        if (idInput) idInput.value = uploadId;
        if (chunksInput) chunksInput.value = String(totalChunks);
        if (nameInput) nameInput.value = file.name;
        if (b) b.textContent = form.getAttribute("data-busy") || "Analysing…";
        HTMLFormElement.prototype.submit.call(form);
      } catch (err) {
        if (b) {
          b.disabled = false;
          b.textContent = origLabel;
        }
        showFormError(form, err && err.message ? err.message : "Upload failed.");
      }
    });
  });

  // Confirmation for destructive or irreversible actions.
  document.querySelectorAll("[data-confirm]").forEach(function (el) {
    el.addEventListener("click", function (e) {
      if (!window.confirm(el.getAttribute("data-confirm"))) e.preventDefault();
    });
  });

  // Status select: warn when closing as fraud (pushes identifiers to blocklist).
  var st = document.getElementById("status-select");
  var hint = document.getElementById("status-hint");
  if (st && hint) {
    var upd = function () { hint.hidden = st.value !== "closed_fraud"; };
    st.addEventListener("change", upd); upd();
  }

  // Citizen form: show only the inputs relevant to the chosen item type.
  var kindSel = document.getElementById("kind-select");
  if (kindSel) {
    var sync = function () {
      document.querySelectorAll("[data-kind]").forEach(function (blk) {
        blk.hidden = blk.getAttribute("data-kind").split(" ").indexOf(kindSel.value) < 0;
      });
    };
    kindSel.addEventListener("change", sync); sync();
  }

  // Copy identifier values.
  document.querySelectorAll("[data-copy]").forEach(function (el) {
    el.addEventListener("click", function () {
      navigator.clipboard && navigator.clipboard.writeText(el.getAttribute("data-copy"));
      var t = el.textContent; el.textContent = "copied"; setTimeout(function () { el.textContent = t; }, 900);
    });
  });
})();
