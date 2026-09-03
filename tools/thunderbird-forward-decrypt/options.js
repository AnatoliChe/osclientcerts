const checkbox = document.getElementById("debug");
const status   = document.getElementById("status");

browser.storage.local.get("debug").then(({ debug }) => {
  checkbox.checked = !!debug;
  status.textContent = debug ? "Отладка включена" : "";
});

checkbox.addEventListener("change", () => {
  const enabled = checkbox.checked;
  browser.storage.local.set({ debug: enabled }).then(() => {
    status.textContent = enabled ? "Отладка включена" : "";
  });
});
