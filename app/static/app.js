// Small progressive enhancements only; every page works without JavaScript.
(function () {
  // Disable submit buttons while analysis runs (live checks can take ~10-20 s).
  document.querySelectorAll("form[data-busy]").forEach(function (form) {
    form.addEventListener("submit", function () {
      var b = form.querySelector("button[type=submit]");
      if (b) { b.disabled = true; b.textContent = form.getAttribute("data-busy"); }
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
