
(() => {
  const isHostedOnline = /^(www\.)?entropylab\.online$/i.test(location.hostname);
  const isLocalPreview = (
    location.protocol === "file:" || /^(localhost|127\.0\.0\.1|\[::1\])$/i.test(location.hostname)
  ) && new URLSearchParams(location.search).get("online-preview") === "1";
  if (!isHostedOnline && !isLocalPreview) return;

  // The hosted site always warns: the banner cannot be dismissed.
  document.getElementById("online-warning")?.removeAttribute("hidden");

  const row = document.getElementById("home-screen-install");
  if (!row) return;
  const standalone = (typeof navigator !== "undefined" && navigator.standalone === true)
    || (typeof matchMedia === "function" && matchMedia("(display-mode: standalone)").matches);
  if (standalone) {
    row.setAttribute("hidden", "");
    return;
  }
  // Hosted assets/ only. The downloaded HTML never requests this file.
  const placeholder = row.querySelector(".home-screen-icon");
  if (placeholder && placeholder.tagName !== "IMG") {
    const img = document.createElement("img");
    img.className = "home-screen-icon";
    img.src = "assets/pwa-icon-180.png";
    img.width = 60;
    img.height = 60;
    img.alt = "EntropyLab";
    placeholder.replaceWith(img);
  }
})();

function hodlFormatRecoverySheet(text) {
  const lines = text.split("\n");
  if (lines[1] !== "ENTROPYLAB V{{VERSION}}") lines.splice(1, 0, "ENTROPYLAB V{{VERSION}}");
  return lines.join("\n");
}
