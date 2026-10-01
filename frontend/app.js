// ═══════════════════════════════════════════════════
//  Nuclei Dashboard v2.0 — app.js
// ═══════════════════════════════════════════════════

const API_BASE = "http://localhost:8000/api";
const DEFAULT_API_KEY = "nuclei-secret-key-2024";

let profilesCache = {};
let allowlistCache = [];
let scansCache = [];
let currentFindingsScanId = null;
let rawAiResult = "";

// ─── API KEY ────────────────────────────────────────
function getApiKey() { return localStorage.getItem("nuclei_api_key") || DEFAULT_API_KEY; }
function setApiKey(k) { localStorage.setItem("nuclei_api_key", k && k.trim() ? k.trim() : DEFAULT_API_KEY); updateApiKeyBadge(); }
function getGeminiKey() { return localStorage.getItem("nuclei_gemini_key") || ""; }
function setGeminiKey(k) { localStorage.setItem("nuclei_gemini_key", k && k.trim() ? k.trim() : ""); }

function updateApiKeyBadge() {
  const k = getApiKey();
  const lbl = document.getElementById("apikey-label");
  if (lbl) lbl.textContent = k === DEFAULT_API_KEY ? "API Key: Default" : `API Key: ${k.slice(0,4)}••••`;
}

// ─── FETCH HELPER ────────────────────────────────────
async function apiFetch(endpoint, opts = {}) {
  const headers = opts.headers || {};
  if (!headers["Content-Type"] && !(opts.body instanceof FormData)) headers["Content-Type"] = "application/json";
  headers["X-API-Key"] = getApiKey();
  const res = await fetch(`${API_BASE}${endpoint}`, { ...opts, headers });
  if (res.status === 401) showToast("Auth Gagal: API Key tidak valid.", "error");
  if (res.status === 429) showToast("Rate limit terlampaui. Tunggu sebentar.", "error");
  return res;
}

// ─── TOAST ───────────────────────────────────────────
function showToast(msg, type = "info") {
  const c = document.getElementById("toast-container");
  if (!c) return;
  const t = document.createElement("div");
  t.className = `toast toast-${type}`;
  const icons = { success:"✓", error:"⚠", info:"ℹ" };
  t.innerHTML = `<span>${icons[type]||"ℹ"}</span><span>${msg}</span>`;
  c.appendChild(t);
  setTimeout(() => { t.style.opacity="0"; t.style.transform="translateY(8px)"; setTimeout(()=>t.remove(),300); }, 4000);
}

// ─── PAGE NAVIGATION ─────────────────────────────────
const PAGE_META = {
  overview: { title:"Overview", subtitle:"Ringkasan aktivitas keamanan sistem" },
  scans:    { title:"Scans", subtitle:"Riwayat dan manajemen pemindaian" },
  findings: { title:"Findings", subtitle:"Seluruh temuan kerentanan" },
  ai:       { title:"AI Analysis", subtitle:"Analisis cerdas dengan Gemini AI" },
  targets:  { title:"Targets", subtitle:"Manajemen target allowlist" },
  audit:    { title:"Audit Logs", subtitle:"Log keamanan dan aktivitas sistem" },
  settings: { title:"Settings", subtitle:"Konfigurasi dashboard" },
};
const ALL_PAGES = Object.keys(PAGE_META);

function switchPage(pageId) {
  ALL_PAGES.forEach(p => {
    const pg = document.getElementById(`page-${p}`);
    const nav = document.getElementById(`nav-${p}`);
    if (pg) pg.classList.toggle("active", p === pageId);
    if (nav) nav.classList.toggle("active", p === pageId);
  });
  const meta = PAGE_META[pageId] || {};
  const t = document.getElementById("topbar-title");
  const s = document.getElementById("topbar-subtitle");
  if (t) t.textContent = meta.title || pageId;
  if (s) s.textContent = meta.subtitle || "";

  // Lazy load data on page switch
  if (pageId === "overview") { fetchStats(); fetchScans(); }
  if (pageId === "scans") fetchScans();
  if (pageId === "findings") fetchAllFindings();
  if (pageId === "ai") populateAiScanSelect();
  if (pageId === "targets") fetchAllowlist();
  if (pageId === "audit") fetchAuditLogs();
  if (pageId === "settings") {
    const sa = document.getElementById("settings-apikey");
    const sg = document.getElementById("settings-gemini-key");
    if (sa) sa.value = getApiKey();
    if (sg) sg.value = getGeminiKey();
  }
}

// ─── MODAL HELPERS ────────────────────────────────────
function openModal(id) { document.getElementById(id)?.classList.add("open"); }
function closeModal(id) { document.getElementById(id)?.classList.remove("open"); }

function openNewScanModal() {
  populateModalAllowlist();
  populateModalProfiles();
  openModal("modal-new-scan");
}
function populateModalAllowlist() {
  const sel = document.getElementById("modal-target-select");
  if (!sel) return;
  sel.innerHTML = allowlistCache.length
    ? allowlistCache.map(i=>`<option value="${i.target}">${i.target}${i.label?" — "+i.label:""}</option>`).join("")
    : "<option value='' disabled selected>Belum ada target. Tambahkan di Targets.</option>";
}
function populateModalProfiles() {
  const sel = document.getElementById("modal-profile");
  if (!sel || !Object.keys(profilesCache).length) return;
  sel.innerHTML = Object.entries(profilesCache).map(([k,v])=>`<option value="${k}">[${v.category.toUpperCase()}] ${v.name}</option>`).join("");
  sel.onchange = () => updateModalProfileDetails();
  updateModalProfileDetails();
}
function updateModalProfileDetails() {
  const sel = document.getElementById("modal-profile");
  const box = document.getElementById("modal-profile-details");
  if (!sel || !box) return;
  const v = profilesCache[sel.value];
  if (!v) { box.style.display="none"; return; }
  box.style.display = "block";
  box.innerHTML = `<div style="font-weight:700;color:#fff;margin-bottom:4px">${v.name}</div>
    <div style="font-size:12px;color:var(--text-secondary);margin-bottom:8px">${v.description}</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px">
      ${v.severity.map(s=>`<span class="badge badge-${s}">${s.toUpperCase()}</span>`).join("")}
      ${v.tags.map(t=>`<span class="tag-chip">${t}</span>`).join("")}
    </div>`;
}

async function submitModalScan() {
  const target = document.getElementById("modal-target-select")?.value;
  const profile = document.getElementById("modal-profile")?.value;
  if (!target || !profile) { showToast("Pilih target dan profil.", "error"); return; }
  closeModal("modal-new-scan");
  await doScan(target, profile);
}

// ─── SAVE API KEY FROM MODAL ──────────────────────────
function saveApiKeyFromModal() {
  const v = document.getElementById("input-apikey")?.value;
  setApiKey(v);
  showToast("API Key berhasil disimpan.", "success");
  closeModal("modal-apikey");
  refreshAll();
}
function saveSettings() {
  const v = document.getElementById("settings-apikey")?.value;
  setApiKey(v);
  showToast("API Key disimpan.", "success");
  refreshAll();
}
function resetApiKey() {
  setApiKey(DEFAULT_API_KEY);
  const sa = document.getElementById("settings-apikey");
  if (sa) sa.value = DEFAULT_API_KEY;
  showToast("API Key direset ke default.", "info");
}
function saveGeminiKey() {
  const v = document.getElementById("settings-gemini-key")?.value;
  setGeminiKey(v);
  showToast("Gemini API Key disimpan.", "success");
  // Pre-fill AI page key if empty
  const aiKey = document.getElementById("ai-gemini-key");
  if (aiKey && !aiKey.value) aiKey.value = v;
}

// ─── SET API STATUS ────────────────────────────────────
function setApiStatus(online) {
  const dot = document.getElementById("status-dot");
  const txt = document.getElementById("api-status-text");
  if (dot) dot.className = `status-dot${online?"":" offline"}`;
  if (txt) txt.textContent = online ? "API Connected" : "API Offline";
}

// ─── BADGE HELPERS ────────────────────────────────────
function severityBadge(s) {
  return `<span class="badge badge-${s.toLowerCase()}">${s.toUpperCase()}</span>`;
}
function statusBadge(s) {
  return `<span class="badge badge-${s}">${s.toUpperCase()}</span>`;
}
function auditBadge(action) {
  const cls = `badge-${action}`;
  return `<span class="badge ${cls}" style="text-transform:uppercase;font-size:9.5px;">${action.replace(/_/g," ")}</span>`;
}
function categoryLabel(cat) {
  const m = { web:"🌐 Web", api:"🔌 API", network:"🖥 Network", all:"🛡️ Full Audit" };
  return m[cat] || cat;
}
function timeAgo(dateStr) {
  if (!dateStr) return "—";
  const d = new Date(dateStr);
  const now = new Date();
  const s = Math.floor((now - d) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return d.toLocaleDateString();
}

// ─── 1. PROFILES ─────────────────────────────────────
async function fetchProfiles() {
  try {
    const res = await apiFetch("/profiles");
    if (!res.ok) throw new Error();
    profilesCache = await res.json();
    populateProfileSelect();
    populateModalProfiles();
    setApiStatus(true);
  } catch { setApiStatus(false); }
}

function populateProfileSelect() {
  const sel = document.getElementById("profile");
  if (!sel) return;
  sel.innerHTML = Object.entries(profilesCache).map(([k,v])=>
    `<option value="${k}">[${v.category.toUpperCase()}] ${v.name}</option>`
  ).join("");
  updateProfileDetails();
}

function updateProfileDetails() {
  const sel = document.getElementById("profile");
  const box = document.getElementById("profile-details");
  if (!sel || !box) return;
  const v = profilesCache[sel.value];
  if (!v) return;
  box.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
      <div style="font-weight:700;color:#fff;font-size:14px">${v.name}</div>
      <span style="font-size:11px;color:var(--text-muted)">${categoryLabel(v.category)}</span>
    </div>
    <div style="font-size:12.5px;color:var(--text-secondary);margin-bottom:12px">${v.description}</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">
      ${v.severity.map(s=>`<span class="badge badge-${s}">${s.toUpperCase()}</span>`).join("")}
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11.5px;font-family:'JetBrains Mono',monospace">
      <div style="background:var(--bg-hover);padding:8px;border-radius:6px;border:1px solid var(--border-light)">
        <div style="color:var(--text-muted);font-size:9.5px;margin-bottom:3px">RATE LIMIT</div>
        <div style="color:var(--accent)">${v.rate_limit} req/s</div>
      </div>
      <div style="background:var(--bg-hover);padding:8px;border-radius:6px;border:1px solid var(--border-light)">
        <div style="color:var(--text-muted);font-size:9.5px;margin-bottom:3px">CONCURRENCY</div>
        <div style="color:#c4b5fd">${v.concurrency} threads</div>
      </div>
    </div>
    <div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:3px">
      ${(v.tags||[]).map(t=>`<span class="tag-chip">${t}</span>`).join("")}
    </div>`;
  const hint = document.getElementById("selected-target-hint");
  if (hint && document.getElementById("target-select")?.value) hint.textContent = `Target: ${document.getElementById("target-select").value}`;
}

// ─── 2. ALLOWLIST ─────────────────────────────────────
async function fetchAllowlist() {
  try {
    const res = await apiFetch("/allowlist");
    if (!res.ok) throw new Error();
    allowlistCache = await res.json();
    renderAllowlistTable();
    populateTargetSelect();
    const b = document.getElementById("badge-targets");
    if (b) b.textContent = allowlistCache.length;
  } catch(e) { console.error("fetchAllowlist:", e); }
}

function renderAllowlistTable() {
  const tb = document.getElementById("allowlist-tbody");
  if (!tb) return;
  if (!allowlistCache.length) {
    tb.innerHTML = `<tr><td colspan="4"><div class="empty-state"><div class="empty-state-icon">🎯</div><div>Belum ada target yang terdaftar.</div></div></td></tr>`;
    return;
  }
  tb.innerHTML = allowlistCache.map(i=>`
    <tr>
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent)">${escHTML(i.target)}</td>
      <td style="color:var(--text-secondary)">${escHTML(i.label||"—")}</td>
      <td style="font-size:11.5px;color:var(--text-muted)">${timeAgo(i.added_at)}</td>
      <td style="text-align:right">
        <button class="btn btn-danger" style="padding:4px 10px;font-size:11.5px;" onclick="deleteAllowlistTarget(${i.id},'${escHTML(i.target)}')">🗑️</button>
      </td>
    </tr>`).join("");
}

function populateTargetSelect() {
  const sel = document.getElementById("target-select");
  if (!sel) return;
  sel.innerHTML = allowlistCache.length
    ? allowlistCache.map(i=>`<option value="${escHTML(i.target)}">${escHTML(i.target)}${i.label?" — "+escHTML(i.label):""}</option>`).join("")
    : `<option value="" disabled selected>Belum ada target. Tambahkan di Targets.</option>`;
  updateProfileDetails();
}

async function deleteAllowlistTarget(id, name) {
  if (!confirm(`Hapus target '${name}' dari allowlist?`)) return;
  try {
    const res = await apiFetch(`/allowlist/${id}`, { method:"DELETE" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail||"Gagal.");
    showToast(`Target '${name}' dihapus.`, "info");
    await fetchAllowlist();
  } catch(e) { showToast(`Error: ${e.message}`, "error"); }
}

// Submit allowlist form
document.getElementById("allowlist-form")?.addEventListener("submit", async e => {
  e.preventDefault();
  const target = document.getElementById("al-target")?.value.trim();
  const label  = document.getElementById("al-label")?.value.trim();
  const btn = document.getElementById("btn-allowlist-submit");
  btn.disabled = true; btn.textContent = "Menyimpan...";
  try {
    const res = await apiFetch("/allowlist", { method:"POST", body: JSON.stringify({target, label}) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail||"Gagal.");
    showToast(`Target '${data.target}' ditambahkan!`, "success");
    document.getElementById("al-target").value = "";
    document.getElementById("al-label").value = "";
    await fetchAllowlist();
  } catch(e) { showToast(`Error: ${e.message}`, "error"); }
  finally { btn.disabled=false; btn.textContent="✅ Simpan ke Allowlist"; }
});

// ─── 3. SCAN SUBMISSION ───────────────────────────────
async function doScan(target, profile) {
  try {
    const res = await apiFetch("/scans", { method:"POST", body: JSON.stringify({target, profile}) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail||"Gagal.");
    showToast("Scan dijadwalkan dan masuk antrean! 🔍", "success");
    await fetchScans();
    await fetchStats();
  } catch(e) { showToast(`Gagal: ${e.message}`, "error"); }
}

document.getElementById("scan-form")?.addEventListener("submit", async e => {
  e.preventDefault();
  const target = document.getElementById("target-select")?.value;
  const profile = document.getElementById("profile")?.value;
  if (!target) { showToast("Pilih target dari allowlist.", "error"); return; }
  const btn = document.getElementById("btn-submit");
  btn.disabled=true; btn.innerHTML="⏳ Memproses...";
  await doScan(target, profile);
  btn.disabled=false; btn.innerHTML="🔍 Mulai Scan";
});

// ─── 4. SCANS ─────────────────────────────────────────
async function fetchScans() {
  try {
    const res = await apiFetch("/scans");
    if (!res.ok) throw new Error();
    scansCache = await res.json();
    renderScansTable(scansCache);
    renderOverviewRecent(scansCache.slice(0,5));
    populateAiScanSelect();
    const running = scansCache.filter(s=>s.status==="running"||s.status==="queued").length;
    const badgeR = document.getElementById("badge-running");
    if (badgeR) { badgeR.textContent=running; badgeR.className=`nav-badge${running>0?" live":""}`; }
    setApiStatus(true);
  } catch { setApiStatus(false); }
}

function renderScansTable(scans) {
  const tb = document.getElementById("scans-tbody");
  if (!tb) return;
  if (!scans.length) {
    tb.innerHTML = `<tr><td colspan="7"><div class="empty-state"><div class="empty-state-icon">🔍</div><div>Belum ada riwayat pemindaian.</div></div></td></tr>`;
    return;
  }
  tb.innerHTML = scans.map(s=>`
    <tr>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-muted)" title="${s.scan_id}">${s.scan_id.slice(0,8)}…</td>
      <td style="font-size:12.5px">${escHTML(s.target)}</td>
      <td style="font-size:12px;color:var(--text-secondary)">${s.profile}</td>
      <td>${statusBadge(s.status)}</td>
      <td style="text-align:center;font-family:'JetBrains Mono',monospace;font-weight:700;color:${s.total_findings>0?"#fcd34d":"var(--text-muted)"}">${s.total_findings}</td>
      <td style="font-size:11.5px;color:var(--text-muted)">${timeAgo(s.started_at)}</td>
      <td style="text-align:right">
        ${s.total_findings>0
          ? `<button class="btn btn-ghost" style="padding:4px 10px;font-size:11.5px;" onclick="viewFindings('${s.scan_id}','${escHTML(s.target)}')">Lihat Temuan</button>`
          : `<span style="font-size:11.5px;color:var(--text-muted)">${s.status==="completed"?"Bersih ✓":"—"}</span>`
        }
      </td>
    </tr>`).join("");
}

function renderOverviewRecent(scans) {
  const tb = document.getElementById("overview-recent-tbody");
  if (!tb) return;
  if (!scans.length) {
    tb.innerHTML = `<tr><td colspan="6"><div class="empty-state"><div class="empty-state-icon">🔍</div><div>Belum ada scan.</div></div></td></tr>`;
    return;
  }
  tb.innerHTML = scans.map(s=>`
    <tr>
      <td style="font-size:12.5px">${escHTML(s.target)}</td>
      <td style="font-size:12px;color:var(--text-secondary)">${s.profile}</td>
      <td>${statusBadge(s.status)}</td>
      <td style="text-align:center;font-family:'JetBrains Mono',monospace;font-weight:700;color:${s.total_findings>0?"#fcd34d":"var(--text-muted)"}">${s.total_findings}</td>
      <td style="font-size:11.5px;color:var(--text-muted)">${timeAgo(s.started_at)}</td>
      <td style="text-align:right">
        ${s.total_findings>0
          ? `<button class="btn btn-ghost" style="padding:4px 10px;font-size:11.5px;" onclick="switchPage('scans');setTimeout(()=>viewFindings('${s.scan_id}','${escHTML(s.target)}'),300)">Lihat →</button>`
          : `<span style="font-size:11.5px;color:var(--text-muted)">${s.status==="completed"?"Bersih ✓":"—"}</span>`
        }
      </td>
    </tr>`).join("");
}

// ─── 5. FINDINGS PANEL ────────────────────────────────
async function viewFindings(scanId, target) {
  currentFindingsScanId = scanId;
  const section = document.getElementById("findings-section");
  const subtitle = document.getElementById("findings-subtitle");
  const tb = document.getElementById("findings-tbody");
  if (subtitle) subtitle.textContent = `Target: ${target} | Scan ID: ${scanId.slice(0,8)}…`;
  section.classList.add("open");
  tb.innerHTML = `<tr><td colspan="4"><div class="empty-state"><div class="empty-state-icon">⏳</div><div>Memuat temuan...</div></div></td></tr>`;
  section.scrollIntoView({ behavior:"smooth", block:"start" });
  try {
    const res = await apiFetch(`/scans/${scanId}/findings`);
    const findings = await res.json();
    if (!findings.length) {
      tb.innerHTML = `<tr><td colspan="4"><div class="empty-state" style="color:#86efac"><div style="font-size:24px">✓</div><div>Tidak ada kerentanan terdeteksi.</div></div></td></tr>`;
      return;
    }
    tb.innerHTML = findings.map(f=>`
      <tr>
        <td>${severityBadge(f.severity)}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-secondary)">${escHTML(f.template_id)}</td>
        <td style="font-weight:600">${escHTML(f.name)}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-muted);word-break:break-all">${escHTML(f.matched_at)}</td>
      </tr>`).join("");
  } catch { tb.innerHTML = `<tr><td colspan="4"><div class="empty-state" style="color:#fca5a5"><div>Gagal memuat temuan.</div></div></td></tr>`; }
}

// ─── 6. ALL FINDINGS PAGE ─────────────────────────────
async function fetchAllFindings() {
  const tb = document.getElementById("all-findings-tbody");
  if (!tb) return;
  tb.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-state-icon">⏳</div><div>Memuat...</div></div></td></tr>`;
  try {
    // Fetch all completed scans and collect findings
    const scansRes = await apiFetch("/scans");
    const scans = await scansRes.json();
    const completedWithFindings = scans.filter(s=>s.status==="completed"&&s.total_findings>0);
    
    let allFindings = [];
    for (const scan of completedWithFindings.slice(0,20)) {
      const fr = await apiFetch(`/scans/${scan.scan_id}/findings`);
      const fs = await fr.json();
      fs.forEach(f=>{ f._target=scan.target; allFindings.push(f); });
    }

    // Severity counts
    const counts = { critical:0, high:0, medium:0, low:0, info:0 };
    allFindings.forEach(f=>{ const s=f.severity.toLowerCase(); if(counts[s]!==undefined)counts[s]++; else counts.info++; });
    const el = id => document.getElementById(id);
    if (el("all-critical")) el("all-critical").textContent = counts.critical;
    if (el("all-high"))     el("all-high").textContent     = counts.high;
    if (el("all-medium"))   el("all-medium").textContent   = counts.medium;
    if (el("all-low"))      el("all-low").textContent      = counts.low + counts.info;
    const totalF = document.getElementById("badge-findings");
    if (totalF) totalF.textContent = allFindings.length;

    if (!allFindings.length) {
      tb.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-state-icon" style="color:#86efac">✓</div><div>Tidak ada temuan dari semua scan.</div></div></td></tr>`;
      return;
    }
    // Sort by severity
    const sevOrder = {critical:0,high:1,medium:2,low:3,info:4};
    allFindings.sort((a,b)=>(sevOrder[a.severity.toLowerCase()]||4)-(sevOrder[b.severity.toLowerCase()]||4));
    tb.innerHTML = allFindings.map(f=>`
      <tr>
        <td>${severityBadge(f.severity)}</td>
        <td style="font-weight:600">${escHTML(f.name)}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-secondary)">${escHTML(f.template_id)}</td>
        <td style="font-size:12px;color:var(--text-secondary)">${escHTML(f._target||"—")}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-muted);word-break:break-all">${escHTML(f.matched_at)}</td>
      </tr>`).join("");
  } catch(e) { tb.innerHTML=`<tr><td colspan="5"><div class="empty-state" style="color:#fca5a5"><div>Gagal memuat.</div></div></td></tr>`; }
}

// ─── 7. STATS / OVERVIEW ─────────────────────────────
async function fetchStats() {
  try {
    const res = await apiFetch("/stats");
    if (!res.ok) return;
    const d = await res.json();
    const el = id => document.getElementById(id);
    if (el("stat-total-scans"))    el("stat-total-scans").textContent    = d.total_scans;
    if (el("stat-running-sub"))    el("stat-running-sub").textContent    = `${d.running_scans} running · ${d.completed_scans} completed`;
    if (el("stat-critical"))       el("stat-critical").textContent       = d.critical_findings;
    if (el("stat-high-sub"))       el("stat-high-sub").textContent       = `${d.high_findings} high`;
    if (el("stat-total-findings")) el("stat-total-findings").textContent = d.total_findings;
    if (el("stat-completed-sub"))  el("stat-completed-sub").textContent  = `${d.completed_scans} scan selesai`;
    if (el("stat-targets"))        el("stat-targets").textContent        = d.targets_monitored;
    if (el("badge-targets"))       el("badge-targets").textContent       = d.targets_monitored;
  } catch {}
}

// ─── 8. AUDIT LOGS ────────────────────────────────────
async function fetchAuditLogs() {
  const tb = document.getElementById("audit-tbody");
  if (!tb) return;
  try {
    const res = await apiFetch("/audit-logs?limit=100");
    if (!res.ok) throw new Error();
    const logs = await res.json();
    if (!logs.length) {
      tb.innerHTML = `<tr><td colspan="5"><div class="empty-state"><div class="empty-state-icon">📋</div><div>Belum ada aktivitas.</div></div></td></tr>`;
      return;
    }
    tb.innerHTML = logs.map(l=>`
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-muted);white-space:nowrap">${l.timestamp?new Date(l.timestamp).toLocaleString():"—"}</td>
        <td>${auditBadge(l.action)}</td>
        <td style="font-size:12px;color:var(--text-secondary);word-break:break-all">${escHTML(l.target||"—")}</td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-muted)">${escHTML(l.source_ip||"—")}</td>
        <td style="font-size:11.5px;color:var(--text-muted)">${escHTML(l.detail||"—")}</td>
      </tr>`).join("");
  } catch { tb.innerHTML=`<tr><td colspan="5"><div class="empty-state" style="color:#fca5a5"><div>Gagal memuat.</div></div></td></tr>`; }
}

// ─── 9. AI ANALYSIS ──────────────────────────────────
function populateAiScanSelect() {
  const sel = document.getElementById("ai-scan-select");
  if (!sel) return;
  const completed = scansCache.filter(s=>s.status==="completed");
  if (!completed.length) {
    sel.innerHTML = "<option value='' disabled selected>Belum ada scan selesai...</option>";
    return;
  }
  sel.innerHTML = completed.map(s=>
    `<option value="${s.scan_id}">[${s.total_findings} findings] ${s.target} — ${s.profile} — ${timeAgo(s.started_at)}</option>`
  ).join("");
  // Pre-fill gemini key from storage
  const gk = document.getElementById("ai-gemini-key");
  if (gk && !gk.value) gk.value = getGeminiKey();
}

function openAiFromFindings() {
  if (!currentFindingsScanId) { showToast("Pilih scan terlebih dahulu.", "error"); return; }
  switchPage("ai");
  setTimeout(() => {
    const sel = document.getElementById("ai-scan-select");
    if (sel) sel.value = currentFindingsScanId;
    const gk = document.getElementById("ai-gemini-key");
    if (gk && !gk.value) gk.value = getGeminiKey();
  }, 200);
}

async function runAiAnalysis() {
  const scanId   = document.getElementById("ai-scan-select")?.value;
  const gemKey   = document.getElementById("ai-gemini-key")?.value?.trim();

  if (!scanId)  { showToast("Pilih scan yang akan dianalisis.", "error"); return; }
  if (!gemKey)  { showToast("Masukkan Gemini API Key terlebih dahulu.", "error"); return; }

  // Save key to storage for convenience
  setGeminiKey(gemKey);

  document.getElementById("ai-result-container").style.display = "none";
  document.getElementById("ai-loading-container").style.display = "block";
  document.getElementById("btn-run-ai").disabled = true;

  try {
    const res = await apiFetch("/ai/analyze", {
      method: "POST",
      body: JSON.stringify({ scan_id: scanId, gemini_api_key: gemKey })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Gagal analisis.");

    rawAiResult = data.analysis;
    document.getElementById("ai-result-body").innerHTML = marked.parse(data.analysis);
    document.getElementById("ai-result-meta").textContent = `Target: ${data.target} | ${data.findings_analyzed} findings dianalisis`;
    document.getElementById("ai-result-container").style.display = "block";
    document.getElementById("ai-result-container").scrollIntoView({ behavior:"smooth" });
    showToast("Analisis AI selesai! ✨", "success");
  } catch(e) {
    showToast(`AI Error: ${e.message}`, "error");
  } finally {
    document.getElementById("ai-loading-container").style.display = "none";
    document.getElementById("btn-run-ai").disabled = false;
  }
}

function clearAiResult() {
  document.getElementById("ai-result-container").style.display = "none";
  document.getElementById("ai-loading-container").style.display = "none";
  rawAiResult = "";
}

function copyAiResult() {
  if (!rawAiResult) { showToast("Tidak ada hasil untuk disalin.", "info"); return; }
  navigator.clipboard.writeText(rawAiResult)
    .then(()=>showToast("Hasil analisis disalin!", "success"))
    .catch(()=>showToast("Gagal menyalin.", "error"));
}

// ─── UTILITY ─────────────────────────────────────────
function escHTML(str) {
  if (!str) return "";
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function refreshAll() {
  fetchProfiles();
  fetchAllowlist();
  fetchScans();
  fetchStats();
  fetchAuditLogs();
}

// ─── EVENT LISTENERS ──────────────────────────────────
document.getElementById("profile")?.addEventListener("change", updateProfileDetails);
document.getElementById("target-select")?.addEventListener("change", () => {
  const hint = document.getElementById("selected-target-hint");
  if (hint) hint.textContent = document.getElementById("target-select").value ? `Target: ${document.getElementById("target-select").value}` : "";
});
document.getElementById("btn-refresh")?.addEventListener("click", fetchScans);
document.getElementById("btn-refresh-allowlist")?.addEventListener("click", fetchAllowlist);
document.getElementById("btn-refresh-audit")?.addEventListener("click", fetchAuditLogs);
document.getElementById("btn-close-findings")?.addEventListener("click", () => {
  document.getElementById("findings-section")?.classList.remove("open");
});
document.getElementById("btn-open-apikey")?.addEventListener("click", () => {
  const inp = document.getElementById("input-apikey");
  if (inp) inp.value = getApiKey();
  openModal("modal-apikey");
});

// Close modals on overlay click
document.querySelectorAll(".modal-overlay").forEach(o => {
  o.addEventListener("click", e => { if (e.target === o) o.classList.remove("open"); });
});

// ─── INIT ─────────────────────────────────────────────
updateApiKeyBadge();
fetchProfiles();
fetchAllowlist();
fetchScans();
fetchStats();
fetchAuditLogs();

// Auto-refresh every 5 seconds
setInterval(() => { fetchScans(); fetchStats(); }, 5000);
