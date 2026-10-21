const form = document.querySelector("#scan-form");
const scanButton = document.querySelector("#scan-button");
const results = document.querySelector("#results");
const errorMessage = document.querySelector("#error-message");
const progressMessage = document.querySelector("#scan-progress");

function setLoading(isLoading) {
  scanButton.disabled = isLoading;
  scanButton.classList.toggle("is-loading", isLoading);
  scanButton.querySelector(".button-label").textContent = isLoading ? "Scanning…" : "Start scan";
  progressMessage.hidden = !isLoading;
  progressMessage.textContent = isLoading
    ? "Resolving the host and checking the requested TCP ports…"
    : "";
  form.setAttribute("aria-busy", String(isLoading));
}

function showResults(data) {
  document.querySelector("#result-summary").textContent = data.summary;
  document.querySelector("#result-target").textContent =
    `${data.host} · TCP ports ${data.start_port}–${data.end_port} · ${data.ports_checked} checked`;

  const ports = data.open_ports;
  const portsWrap = document.querySelector("#ports-wrap");
  const emptyResults = document.querySelector("#empty-results");
  const portsList = document.querySelector("#ports-list");
  portsList.replaceChildren(
    ...ports.map((port) => {
      const row = document.createElement("tr");
      for (const value of [port.port, port.service, "Open"]) {
        const cell = document.createElement("td");
        cell.textContent = String(value);
        row.append(cell);
      }
      return row;
    }),
  );

  portsWrap.hidden = ports.length === 0;
  emptyResults.hidden = ports.length !== 0;
  const badge = document.querySelector("#status-badge");
  badge.textContent = `${ports.length} open`;
  results.hidden = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  results.hidden = true;
  setLoading(true);

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        host: document.querySelector("#target-host").value,
        start_port: Number(document.querySelector("#start-port").value),
        end_port: Number(document.querySelector("#end-port").value),
        authorized: document.querySelector("#authorized").checked,
      }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "The scan request could not be completed.");
    }
    showResults(data);
  } catch (error) {
    errorMessage.textContent =
      error instanceof TypeError
        ? "Could not reach the scanner. Check that the application is running and try again."
        : error.message;
    errorMessage.hidden = false;
  } finally {
    setLoading(false);
  }
});
