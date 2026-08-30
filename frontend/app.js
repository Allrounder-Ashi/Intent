// Point this at your deployed FastAPI backend URL once you deploy.
// Covers: opening index.html directly (file://), localhost, or 127.0.0.1 —
// all of these mean "I'm developing locally", so hit the local backend.
const API_BASE = (
  window.location.protocol === "file:" ||
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1"
) ? "http://localhost:8000"
  : "https://YOUR-BACKEND-URL.onrender.com";

let AGENCY_KEY = sessionStorage.getItem("agencyKey") || "";

function riskBadge(label) {
  if (!label) return "";
  return `<span class="risk-badge risk-${label}">${label.toUpperCase()}</span>`;
}

// ---------------------------------------------------------------------
// CITIZEN: SEARCH
// ---------------------------------------------------------------------
async function doSearch() {
  const query = document.getElementById("searchInput").value.trim();
  const box = document.getElementById("searchResult");
  if (!query) return;

  box.classList.remove("hidden");
  box.innerHTML = "Searching…";

  try {
    const res = await fetch(`${API_BASE}/api/search?query=${encodeURIComponent(query)}`);
    const data = await res.json();
    if (!data.found) {
      box.innerHTML = `<strong>No prior reports found</strong> for "${query}". That doesn't guarantee it's safe — stay cautious.`;
      return;
    }
    box.innerHTML = `
      <strong>${query}</strong> has been reported <strong>${data.report_count}</strong> time(s).
      Highest risk seen: ${riskBadge(data.max_risk_label)}
      <ul class="reasoning">
        ${data.recent_reports.map(r => `<li>Report #${r.id} — ${riskBadge(r.risk_label)} (score ${r.risk_score})</li>`).join("")}
      </ul>`;
  } catch (e) {
    box.innerHTML = "Could not reach the server. Please try again.";
  }
}

// ---------------------------------------------------------------------
// CITIZEN: REPORT / ANALYZE
// ---------------------------------------------------------------------
const reportForm = document.getElementById("reportForm");
if (reportForm) {
  reportForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(reportForm);
    document.getElementById("reportLoading").classList.remove("hidden");
    document.getElementById("resultsSection").classList.add("hidden");

    try {
      const res = await fetch(`${API_BASE}/api/report`, { method: "POST", body: formData });
      const data = await res.json();
      renderResults(data);
    } catch (err) {
      console.error(err);
      alert(`Analysis failed: ${err.message}\n\nCheck that the backend is running at ${API_BASE} (open a terminal, run: uvicorn main:app --reload --port 8000)`);
    } finally {
      document.getElementById("reportLoading").classList.add("hidden");
    }
  });
}

function renderResults(data) {
  const section = document.getElementById("resultsSection");
  const box = document.getElementById("resultsBox");
  section.classList.remove("hidden");

  const tactics = (data.tactics_used || []).filter(t => t && t !== "None detected");
  box.innerHTML = `
    <div class="result-box">
      <p>${riskBadge(data.risk_label)} &nbsp; Risk score: <strong>${data.risk_score}/100</strong> &nbsp; Confidence: ${Math.round(data.confidence * 100)}%</p>
      ${data.scam_type && data.scam_type !== "Not a Scam" ? `<p><strong>Scam type:</strong> ${data.scam_type}</p>` : ""}
      <p>${data.ai_analysis.user_warning_message || ""}</p>
      <strong>Why:</strong>
      <ul class="reasoning">${data.reasoning.map(r => `<li>${r}</li>`).join("")}</ul>
      ${tactics.length ? `<strong>Tactics used:</strong><ul class="reasoning">${tactics.map(t => `<li>${t}</li>`).join("")}</ul>` : ""}
    </div>`;
  section.scrollIntoView({ behavior: "smooth" });
}

// ---------------------------------------------------------------------
// AGENCY
// ---------------------------------------------------------------------
function agencyLogin() {
  const key = document.getElementById("agencyKey").value.trim();
  if (!key) return;
  AGENCY_KEY = key;
  sessionStorage.setItem("agencyKey", key);
  document.getElementById("loginSection").classList.add("hidden");
  document.getElementById("dashboard").classList.remove("hidden");
  loadStats();
  loadCases();
}

async function agencyFetch(path, options = {}) {
  options.headers = { ...(options.headers || {}), "X-Agency-Key": AGENCY_KEY };
  const res = await fetch(`${API_BASE}${path}`, options);
  if (res.status === 401) {
    alert("Invalid agency key.");
    sessionStorage.removeItem("agencyKey");
    location.reload();
    throw new Error("unauthorized");
  }
  return res.json();
}

async function loadStats() {
  const data = await agencyFetch("/api/stats");
  document.getElementById("statsBox").innerHTML = `
    <div class="stat-tile"><div class="num">${data.total_reports}</div><div class="label">Total Reports</div></div>
    <div class="stat-tile"><div class="num">${data.high_risk_cases}</div><div class="label">High Risk</div></div>
    <div class="stat-tile"><div class="num">${data.new}</div><div class="label">New</div></div>
    <div class="stat-tile"><div class="num">${data.resolved}</div><div class="label">Resolved</div></div>`;
}

async function loadCases() {
  const status = document.getElementById("filterStatus").value;
  const risk = document.getElementById("filterRisk").value;
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  if (risk) params.set("risk_label", risk);

  const cases = await agencyFetch(`/api/cases?${params.toString()}`);
  const tbody = document.querySelector("#casesTable tbody");
  tbody.innerHTML = cases.map(c => `
    <tr onclick="openCase(${c.id})">
      <td>#${c.id}</td>
      <td>${new Date(c.created_at).toLocaleString()}</td>
      <td>${c.phone_number || "-"}</td>
      <td>${c.reported_url || "-"}</td>
      <td>${riskBadge(c.risk_label)}</td>
      <td>${c.risk_score ?? "-"}</td>
      <td>${c.status}</td>
      <td>→</td>
    </tr>`).join("");
}

async function openCase(id) {
  const c = await agencyFetch(`/api/cases/${id}`);
  const section = document.getElementById("caseDetailSection");
  const box = document.getElementById("caseDetailBox");
  section.classList.remove("hidden");

  const scamType = c.ai_analysis?.scam_type;
  const tactics = (c.ai_analysis?.tactics_used || []).filter(t => t && t !== "None detected");
  const idHits = c.security_check?.identifier_analysis || [];

  box.innerHTML = `
    <p>${riskBadge(c.risk_label)} Score: <strong>${c.risk_score}</strong> · Confidence: ${Math.round((c.risk_confidence||0)*100)}%</p>
    ${scamType && scamType !== "Not a Scam" ? `<p><strong>Scam type:</strong> ${scamType}</p>` : ""}
    <p><strong>Phone:</strong> ${c.phone_number || "-"} &nbsp; <strong>UPI:</strong> ${c.upi_id || "-"} &nbsp; <strong>URL:</strong> ${c.reported_url || "-"}</p>
    <p><strong>Transcript:</strong> ${c.transcript_text || "(none)"}</p>
    <p><strong>SMS:</strong> ${c.sms_text || "(none)"}</p>
    <p><strong>Reasoning:</strong></p>
    <ul class="reasoning">${(c.risk_reasoning||[]).map(r => `<li>${r}</li>`).join("")}</ul>
    ${tactics.length ? `<p><strong>Tactics used:</strong></p><ul class="reasoning">${tactics.map(t => `<li>${t}</li>`).join("")}</ul>` : ""}
    ${idHits.length ? `<p><strong>Flagged identifiers found in evidence:</strong></p><ul class="reasoning">${idHits.map(h => `<li>${h.type}: ${h.identifier} (${h.report_count} report(s))</li>`).join("")}</ul>` : ""}

    <label>Status
      <select id="statusSelect">
        ${["new","investigating","verified","resolved"].map(s => `<option value="${s}" ${s===c.status?"selected":""}>${s}</option>`).join("")}
      </select>
    </label>
    <label>Notes
      <textarea id="notesInput" rows="3">${c.agency_notes || ""}</textarea>
    </label>
    <button onclick="saveCase(${c.id})">Save</button>
  `;
  section.scrollIntoView({ behavior: "smooth" });
}

async function saveCase(id) {
  const status = document.getElementById("statusSelect").value;
  const agency_notes = document.getElementById("notesInput").value;
  const formData = new FormData();
  formData.set("status", status);
  formData.set("agency_notes", agency_notes);

  await agencyFetch(`/api/cases/${id}`, { method: "PATCH", body: formData });
  loadStats();
  loadCases();
  alert("Saved.");
}

// Auto-login if key already stored in this session
if (document.getElementById("dashboard") && AGENCY_KEY) {
  document.getElementById("loginSection").classList.add("hidden");
  document.getElementById("dashboard").classList.remove("hidden");
  loadStats();
  loadCases();
}
