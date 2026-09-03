const debugCb      = document.getElementById("debug");
const experimentCb = document.getElementById("experiments");
const status       = document.getElementById("status");

browser.storage.local.get(["debug", "experiments"]).then(({ debug, experiments }) => {
  debugCb.checked      = !!debug;
  experimentCb.checked = !!experiments;
  status.textContent   = experiments ? "Эксперимент включен (внимание: открывает окна)" : "";
});

debugCb.addEventListener("change", () => {
  const enabled = debugCb.checked;
  browser.storage.local.set({ debug: enabled }).then(() => {
    status.textContent = enabled ? "Отладка включена" : "";
  });
});

experimentCb.addEventListener("change", () => {
  const enabled = experimentCb.checked;
  browser.storage.local.set({ experiments: enabled }).then(() => {
    status.textContent = enabled ? "Эксперимент включен (внимание: открывает окна)" : "";
  });
});
