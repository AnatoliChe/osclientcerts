const debugCb = document.getElementById("debug");
const status = document.getElementById("status");

browser.storage.local.get(["debug"]).then(({ debug }) => {
  debugCb.checked = !!debug;
});

debugCb.addEventListener("change", () => {
  const enabled = debugCb.checked;
  browser.storage.local.set({ debug: enabled }).then(() => {
    status.textContent = enabled ? "Отладка включена" : "";
  });
});
