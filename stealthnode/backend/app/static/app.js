/* ============================================================
 * StealthNode — логика веб-панели (vanilla JS, без фреймворков).
 * Относительные пути -> работа под секретным префиксом Caddy.
 * Access-токен в памяти, refresh-токен в localStorage (ротация).
 * ============================================================ */
"use strict";

/* ---------------- Состояние ---------------- */
const state = {
  accessToken: null,
  ws: null,
  wsData: null,          // последний пакет WebSocket
  chartBuffers: {},      // буферы спарклайнов по пирам
  chartsPaused: false,
};

const basePath = () => {
  let p = window.location.pathname;
  if (!p.endsWith("/")) p = p.slice(0, p.lastIndexOf("/") + 1);
  return p;
};

/* ---------------- Утилиты ---------------- */
const $ = (sel) => document.querySelector(sel);

function toast(msg, isErr = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "toast" + (isErr ? " toast-err" : "");
  setTimeout(() => el.classList.add("hidden"), 4000);
  el.classList.remove("hidden");
}

function fmtBytes(bytes, perSec = false) {
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let v = Number(bytes) || 0, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(v >= 100 || i === 0 ? 0 : 1) + " " + units[i] + (perSec ? "/с" : "");
}

function fmtMb(mb) { return mb == null ? "∞" : mb + " МБ"; }
function fmtMbps(mb) { return mb == null ? "∞" : mb + " Мбит/с"; }

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ---------------- HTTP с авторизацией и обновлением токена ---------------- */
async function refreshAccessToken() {
  const refresh = localStorage.getItem("sn_refresh");
  if (!refresh) return false;
  const res = await fetch(basePath() + "api/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refresh }),
  });
  if (!res.ok) { localStorage.removeItem("sn_refresh"); return false; }
  const data = await res.json();
  state.accessToken = data.access_token;
  localStorage.setItem("sn_refresh", data.refresh_token);
  return true;
}

async function api(path, options = {}, retried = false) {
  const headers = { ...(options.headers || {}) };
  if (state.accessToken) headers["Authorization"] = "Bearer " + state.accessToken;
  const res = await fetch(basePath() + "api/" + path, { ...options, headers });
  if (res.status === 401 && !retried) {
    if (await refreshAccessToken()) return api(path, options, true);
    showLogin();
    throw new Error("Сессия истекла. Войдите заново.");
  }
  if (res.status === 204) return null;
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { detail: text }; }
  if (!res.ok) throw new Error((data && data.detail) || ("Ошибка " + res.status));
  return data;
}

/* Скачивание файла с авторизацией (QR/CSV/бэкап) через blob */
async function downloadAuthed(path, filename) {
  const res = await fetch(basePath() + "api/" + path, {
    headers: { Authorization: "Bearer " + state.accessToken },
  });
  if (!res.ok) throw new Error("Ошибка загрузки: " + res.status);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  if (filename) a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  return blob;
}

/* ---------------- Вход/выход ---------------- */
function showLogin() {
  state.accessToken = null;
  disconnectWs();
  $("#app").classList.add("hidden");
  $("#login-screen").classList.remove("hidden");
}

function showApp() {
  $("#login-screen").classList.add("hidden");
  $("#app").classList.remove("hidden");
  connectWs();
  route();
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  try {
    const res = await fetch(basePath() + "api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: $("#login-username").value.trim(),
        password: $("#login-password").value,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Ошибка входа");
    state.accessToken = data.access_token;
    localStorage.setItem("sn_refresh", data.refresh_token);
    showApp();
  } catch (err) {
    $("#login-error").textContent = err.message;
  }
});

$("#logout-btn").addEventListener("click", async () => {
  const refresh = localStorage.getItem("sn_refresh");
  try {
    if (refresh) await api("auth/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refresh }),
    });
  } catch { /* игнорируем */ }
  localStorage.removeItem("sn_refresh");
  showLogin();
});

/* ---------------- WebSocket ---------------- */
function connectWs() {
  disconnectWs();
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${proto}//${window.location.host}${basePath()}api/ws?token=${encodeURIComponent(state.accessToken)}`;
  const ws = new WebSocket(url);
  state.ws = ws;
  ws.onopen = () => { $("#conn-indicator").className = "dot dot-green"; };
  ws.onclose = () => {
    $("#conn-indicator").className = "dot dot-red";
    // Переподключение с обновлением токена (мог протухнуть)
    setTimeout(async () => {
      if (!state.accessToken) return;
      await refreshAccessToken();
      connectWs();
    }, 5000);
  };
  ws.onerror = () => {};
  ws.onmessage = (ev) => {
    state.wsData = JSON.parse(ev.data);
    if (!state.chartsPaused && currentPage() === "dashboard") updateDashboardLive();
  };
}

function disconnectWs() {
  if (state.ws) { try { state.ws.close(); } catch {} state.ws = null; }
}

/* ---------------- Навигация (hash-router) ---------------- */
const PAGES = ["dashboard", "devices", "guests", "bot", "settings", "audit"];

function currentPage() {
  const hash = window.location.hash.replace("#/", "") || "dashboard";
  return PAGES.includes(hash) ? hash : "dashboard";
}

function route() {
  const page = currentPage();
  state.chartsPaused = page !== "dashboard";
  document.querySelectorAll(".nav-link").forEach((a) =>
    a.classList.toggle("active", a.dataset.page === page));
  $("#sidebar").classList.remove("open");
  ({ dashboard: renderDashboard, devices: renderDevices, guests: renderGuests,
     bot: renderBot, settings: renderSettings, audit: renderAudit })[page]();
}

window.addEventListener("hashchange", route);
$("#menu-toggle").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
$("#modal-close").addEventListener("click", () => $("#modal").classList.add("hidden"));

function openModal(html) {
  $("#modal-body").innerHTML = html;
  $("#modal").classList.remove("hidden");
}

/* ---------------- Спарклайны (canvas, без библиотек) ---------------- */
function pushBuffer(key, value, maxLen = 60) {
  const buf = state.chartBuffers[key] || (state.chartBuffers[key] = []);
  buf.push(value);
  if (buf.length > maxLen) buf.shift();
  return buf;
}

function drawSpark(canvas, data, color) {
  const ctx = canvas.getContext("2d");
  const w = (canvas.width = canvas.clientWidth * 2);
  const h = (canvas.height = canvas.clientHeight * 2);
  ctx.clearRect(0, 0, w, h);
  if (data.length < 2) return;
  const max = Math.max(...data, 1);
  const step = w / (data.length - 1);
  ctx.beginPath();
  ctx.strokeStyle = color;
  ctx.lineWidth = 3;
  ctx.lineJoin = "round";
  data.forEach((v, i) => {
    const x = i * step, y = h - (v / max) * (h - 6) - 3;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
}

/* ================= СТРАНИЦЫ ================= */

/* ---------- Дашборд ---------- */
async function renderDashboard() {
  state.chartBuffers = {};
  $("#content").innerHTML = `
    <div class="cards" id="sys-cards"></div>
    <div class="section">
      <h2>Онлайн-устройства (real-time)</h2>
      <div class="chart-grid" id="peer-charts"></div>
      <p class="muted" id="no-peers" style="margin-top:8px"></p>
    </div>
    <div class="section">
      <h2>Суммарный трафик</h2>
      <div style="margin-bottom:10px">
        <select id="traffic-period" style="width:auto">
          <option value="day">За день</option><option value="week">За неделю</option>
          <option value="month">За месяц</option><option value="all">За всё время</option>
        </select>
      </div>
      <div class="table-wrap"><table id="traffic-table">
        <thead><tr><th>Устройство</th><th>↓ Скачано</th><th>↑ Отправлено</th><th>Всего</th></tr></thead>
        <tbody></tbody>
      </table></div>
    </div>
    <div class="section">
      <h2>Сервисы</h2>
      <div class="table-wrap"><table id="services-table">
        <thead><tr><th></th><th>Сервис</th><th>Состояние</th><th>Health</th><th>CPU</th><th>RAM</th></tr></thead>
        <tbody></tbody>
      </table></div>
    </div>`;
  $("#traffic-period").addEventListener("change", loadTraffic);
  await Promise.all([loadSystemCards(), loadTraffic(), loadServicesTable()]);
  updateDashboardLive();
}

async function loadSystemCards() {
  try {
    const s = await api("stats/overview");
    $("#sys-cards").innerHTML = `
      <div class="card"><h3>CPU</h3><div class="big">${s.cpu_pct}%</div></div>
      <div class="card"><h3>RAM</h3><div class="big">${s.mem_pct}%</div>
        <div class="sub">${s.mem_used_mb}/${s.mem_total_mb} МБ</div></div>
      <div class="card"><h3>Диск</h3><div class="big">${s.disk_pct}%</div>
        <div class="sub">${s.disk_used_gb}/${s.disk_total_gb} ГБ</div></div>
      <div class="card"><h3>Аптайм</h3><div class="big">${s.uptime_hours} ч</div></div>
      <div class="card"><h3>Сеть (всего)</h3><div class="big">↓${fmtBytes(s.net_rx_bytes)}</div>
        <div class="sub">↑${fmtBytes(s.net_tx_bytes)}</div></div>`;
  } catch (e) { toast(e.message, true); }
}

async function loadTraffic() {
  try {
    const period = $("#traffic-period").value;
    const t = await api("stats/traffic?period=" + period);
    const rows = t.devices.map((d) =>
      `<tr><td>${escapeHtml(d.name)}</td><td>${fmtBytes(d.tx)}</td>
       <td>${fmtBytes(d.rx)}</td><td>${fmtBytes(d.total)}</td></tr>`).join("");
    $("#traffic-table tbody").innerHTML = rows +
      `<tr style="font-weight:700"><td>ИТОГО</td><td>${fmtBytes(t.total_tx)}</td>
       <td>${fmtBytes(t.total_rx)}</td><td>${fmtBytes(t.total)}</td></tr>`;
  } catch (e) { toast(e.message, true); }
}

async function loadServicesTable() {
  try {
    const services = await api("stats/services");
    $("#services-table tbody").innerHTML = services.map((s) => {
      const ok = s.state === "running";
      const short = s.name.replace("stealthnode-", "");
      return `<tr>
        <td><span class="dot ${ok ? "dot-green" : "dot-red"}"></span></td>
        <td>${escapeHtml(short)}</td>
        <td>${escapeHtml(s.state)}</td>
        <td>${escapeHtml(s.health)}</td>
        <td>${s.cpu_pct}%</td><td>${s.mem_mb} МБ</td></tr>`;
    }).join("");
  } catch (e) { toast(e.message, true); }
}

let peerNamesCache = {};
async function updateDashboardLive() {
  const data = state.wsData;
  if (!data) return;
  if (Object.keys(peerNamesCache).length === 0) {
    try {
      const devices = await api("devices");
      peerNamesCache = Object.fromEntries(devices.map((d) => [d.public_key, d.name]));
    } catch { return; }
  }
  // Живые индикаторы системы (карточки обновляем лёгким способом)
  if (data.system) {
    const cards = $("#sys-cards");
    if (cards && cards.children.length >= 2) {
      cards.children[0].querySelector(".big").textContent = data.system.cpu_pct + "%";
      cards.children[1].querySelector(".big").textContent = data.system.mem_pct + "%";
      cards.children[1].querySelector(".sub").textContent =
        `${data.system.mem_used_mb}/${data.system.mem_total_mb} МБ`;
    }
  }
  // Сервисы приходят раз в ~10 сек
  if (data.services) {
    const tbody = $("#services-table tbody");
    if (tbody) tbody.innerHTML = data.services.map((s) => {
      const ok = s.state === "running";
      return `<tr><td><span class="dot ${ok ? "dot-green" : "dot-red"}"></span></td>
        <td>${escapeHtml(s.name.replace("stealthnode-", ""))}</td>
        <td>${escapeHtml(s.state)}</td><td>${escapeHtml(s.health)}</td>
        <td>${s.cpu_pct}%</td><td>${s.mem_mb} МБ</td></tr>`;
    }).join("");
  }
  // Графики пиров
  const grid = $("#peer-charts");
  const np = $("#no-peers");
  if (!grid) return;
  np.textContent = data.peers.length === 0 ? "Пока нет пиров — данные появятся после подключения устройств." : "";
  const seen = new Set();
  data.peers.forEach((p) => {
    const name = peerNamesCache[p.public_key] || p.public_key.slice(0, 8) + "…";
    seen.add(name);
    const sum = p.rx_rate + p.tx_rate;
    pushBuffer(name, sum);
    let card = grid.querySelector(`[data-peer="${CSS.escape(name)}"]`);
    if (!card) {
      card = document.createElement("div");
      card.className = "spark-card";
      card.dataset.peer = name;
      card.innerHTML = `<div class="title"><span>${escapeHtml(name)}
          <span class="dot ${p.online ? "dot-green" : "dot-gray"}" style="margin-left:6px"></span></span>
          <span class="rate mono"></span></div>
        <canvas class="spark"></canvas>
        <div class="sub muted small"></div>`;
      grid.appendChild(card);
    }
    card.querySelector(".rate").textContent = `↓${fmtBytes(p.tx_rate, true)} ↑${fmtBytes(p.rx_rate, true)}`;
    card.querySelector(".dot").className = "dot " + (p.online ? "dot-green" : "dot-gray");
    card.querySelector(".small").textContent =
      (p.endpoint ? `Внешний IP: ${p.endpoint.split(":")[0]} · ` : "") +
      `Всего ↓${fmtBytes(p.cum_tx)} ↑${fmtBytes(p.cum_rx)}`;
    drawSpark(card.querySelector("canvas"), state.chartBuffers[name],
      p.online ? "#4c9aff" : "#2d333b");
  });
  // Удаляем карточки пропавших пиров
  grid.querySelectorAll(".spark-card").forEach((c) => {
    if (!seen.has(c.dataset.peer)) { delete state.chartBuffers[c.dataset.peer]; c.remove(); }
  });
}

/* ---------- Устройства ---------- */
async function renderDevices() {
  $("#content").innerHTML = `
    <div class="section">
      <h2>Создать устройство</h2>
      <div class="form-grid">
        <label>Имя <input id="dev-name" placeholder="iphone-anna"></label>
        <label>Протокол <select id="dev-kind">
          <option value="awg">AmneziaWG (основной)</option>
          <option value="xray">Xray VLESS+REALITY (резервный)</option>
        </select></label>
      </div>
      <button id="dev-create" class="btn btn-primary">Создать</button>
      <p class="muted" style="margin-top:8px">Импортируйте .conf в AmneziaVPN (ПК)
        или отсканируйте QR в приложении (смартфон).</p>
    </div>
    <div class="section">
      <h2>Устройства</h2>
      <div class="table-wrap"><table id="dev-table">
        <thead><tr><th></th><th>Имя</th><th>Протокол</th><th>IP туннеля</th>
          <th>Гость</th><th style="width:270px">Действия</th></tr></thead>
        <tbody></tbody>
      </table></div>
    </div>`;
  $("#dev-create").addEventListener("click", createDevice);
  await loadDevices();
}

async function loadDevices() {
  try {
    const devices = await api("devices");
    $("#dev-table tbody").innerHTML = devices.map((d) => `
      <tr>
        <td><span class="dot ${d.enabled ? "dot-green" : "dot-red"}"></span></td>
        <td>${escapeHtml(d.name)}${d.is_admin_device ? ' <span class="badge badge-ok">админ</span>' : ""}</td>
        <td><span class="badge">${d.kind === "awg" ? "AmneziaWG" : "Xray"}</span></td>
        <td class="mono">${d.tunnel_ip || "—"}</td>
        <td>${d.guest_id ? '<span class="badge badge-warn">гость #' + d.guest_id + "</span>" : "—"}</td>
        <td>
          <button class="btn btn-small" onclick="showConfig(${d.id})">Конфиг/QR</button>
          <button class="btn btn-small" onclick="downloadConfig(${d.id}, '${escapeHtml(d.name)}')">⬇</button>
          <button class="btn btn-small" onclick="toggleDevice(${d.id}, ${d.enabled})">${d.enabled ? "Выключить" : "Включить"}</button>
          <button class="btn btn-small btn-danger" onclick="deleteDevice(${d.id})">✕</button>
        </td>
      </tr>`).join("");
  } catch (e) { toast(e.message, true); }
}

async function createDevice() {
  const name = $("#dev-name").value.trim();
  const kind = $("#dev-kind").value;
  if (!name) return toast("Введите имя устройства", true);
  try {
    const dev = await api("devices", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, kind }),
    });
    toast("Устройство «" + name + "» создано");
    await loadDevices();
    showConfig(dev.id);
  } catch (e) { toast(e.message, true); }
}

window.showConfig = async function (id) {
  try {
    const data = await api(`devices/${id}/config`);
    const qrBlob = await downloadAuthed(`devices/${id}/qr`);
    const qrUrl = URL.createObjectURL(qrBlob);
    const isXray = data.config.startsWith("vless://");
    openModal(`
      <h2>Конфиг: ${escapeHtml(data.name)}</h2>
      <img class="qr" src="${qrUrl}" alt="QR-код">
      <p class="muted">${isXray
        ? "Отсканируйте QR или вставьте ссылку в клиент (v2rayNG, Streisand, Nekoray)."
        : "Отсканируйте QR в AmneziaVPN или импортируйте файл .conf ниже."}</p>
      <pre class="mono">${escapeHtml(data.config)}</pre>`);
  } catch (e) { toast(e.message, true); }
};

window.downloadConfig = async function (id, name) {
  try {
    const data = await api(`devices/${id}/config`);
    const isXray = data.config.startsWith("vless://");
    const blob = new Blob([data.config], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name + (isXray ? ".txt" : ".conf");
    a.click(); URL.revokeObjectURL(url);
  } catch (e) { toast(e.message, true); }
};

window.toggleDevice = async function (id, enabled) {
  try {
    await api(`devices/${id}/${enabled ? "disable" : "enable"}`, { method: "POST" });
    toast(enabled ? "Устройство отключено" : "Устройство включено");
    await loadDevices();
  } catch (e) { toast(e.message, true); }
};

window.deleteDevice = async function (id) {
  if (!confirm("Удалить устройство и все его ключи безвозвратно?")) return;
  try {
    await api(`devices/${id}`, { method: "DELETE" });
    toast("Устройство удалено");
    await loadDevices();
  } catch (e) { toast(e.message, true); }
};

/* ---------- Гости ---------- */
async function renderGuests() {
  $("#content").innerHTML = `
    <div class="section">
      <h2>Создать гостя (максимум 5)</h2>
      <div class="form-grid">
        <label>Имя * <input id="g-name" placeholder="guest-ivan"></label>
        <label>Лимит/день, МБ <input id="g-daily" type="number" min="1" placeholder="∞"></label>
        <label>Лимит/неделю, МБ <input id="g-weekly" type="number" min="1" placeholder="∞"></label>
        <label>Лимит/месяц, МБ <input id="g-monthly" type="number" min="1" placeholder="∞"></label>
        <label>Общий лимит, МБ <input id="g-total" type="number" min="1" placeholder="∞"></label>
        <label>Скорость ↓, Мбит/с <input id="g-down" type="number" min="1" max="1000" placeholder="∞"></label>
        <label>Скорость ↑, Мбит/с <input id="g-up" type="number" min="1" max="1000" placeholder="∞"></label>
        <label>Окно доступа с <input id="g-wstart" placeholder="08:00"></label>
        <label>Окно доступа до <input id="g-wend" placeholder="23:00"></label>
        <label>Действует до <input id="g-exp" type="datetime-local"></label>
        <label>Приоритет QoS <select id="g-prio">
          <option value="low">Низкий</option>
          <option value="normal" selected>Средний</option>
          <option value="high">Высокий</option></select></label>
      </div>
      <button id="g-create" class="btn btn-primary">Создать гостя</button>
    </div>
    <div class="section">
      <h2>Гостевые аккаунты</h2>
      <div class="table-wrap"><table id="g-table">
        <thead><tr><th></th><th>Имя</th><th>IP</th><th>Лимиты</th><th>Скорость</th>
          <th>Окно</th><th>Статус</th><th></th></tr></thead>
        <tbody></tbody>
      </table></div>
    </div>`;
  $("#g-create").addEventListener("click", createGuest);
  await loadGuests();
}

function numOrNull(id) {
  const v = $(id).value.trim();
  return v === "" ? null : Number(v);
}

async function createGuest() {
  const name = $("#g-name").value.trim();
  if (!name) return toast("Введите имя гостя", true);
  const exp = $("#g-exp").value;
  const body = {
    name,
    quota_daily_mb: numOrNull("#g-daily"), quota_weekly_mb: numOrNull("#g-weekly"),
    quota_monthly_mb: numOrNull("#g-monthly"), quota_total_mb: numOrNull("#g-total"),
    speed_down_mbps: numOrNull("#g-down"), speed_up_mbps: numOrNull("#g-up"),
    window_start: $("#g-wstart").value.trim() || null,
    window_end: $("#g-wend").value.trim() || null,
    expires_at: exp ? new Date(exp).toISOString() : null,
    priority: $("#g-prio").value,
  };
  try {
    await api("guests", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    toast("Гость «" + name + "» создан — конфиг на вкладке «Устройства»");
    await loadGuests();
  } catch (e) { toast(e.message, true); }
}

const GUEST_STATUS = {
  active: ["Активен", "badge-ok"], disabled_admin: ["Выключен админом", "badge-err"],
  expired: ["Истёк срок", "badge-err"], quota: ["Лимит исчерпан", "badge-warn"],
  window: ["Вне окна", "badge-warn"],
};

async function loadGuests() {
  try {
    const guests = await api("guests");
    $("#g-table tbody").innerHTML = guests.map((g) => {
      const st = GUEST_STATUS[g.status] || [g.status, ""];
      const limits = [g.quota_daily_mb && "д:" + g.quota_daily_mb,
        g.quota_weekly_mb && "н:" + g.quota_weekly_mb,
        g.quota_monthly_mb && "м:" + g.quota_monthly_mb,
        g.quota_total_mb && "всего:" + g.quota_total_mb].filter(Boolean).join(", ") || "∞";
      return `<tr>
        <td><span class="dot ${g.enabled ? "dot-green" : "dot-red"}"></span></td>
        <td>${escapeHtml(g.name)}</td>
        <td class="mono">${g.tunnel_ip}</td>
        <td>${limits} МБ</td>
        <td>↓${fmtMbps(g.speed_down_mbps)} ↑${fmtMbps(g.speed_up_mbps)}</td>
        <td>${g.window_start ? g.window_start + "–" + g.window_end : "—"}</td>
        <td><span class="badge ${st[1]}" title="${escapeHtml(g.status_detail)}">${st[0]}</span></td>
        <td>
          <button class="btn btn-small" onclick="guestCsv(${g.id})">CSV</button>
          <button class="btn btn-small btn-danger" onclick="deleteGuest(${g.id})">✕</button>
        </td></tr>`;
    }).join("");
  } catch (e) { toast(e.message, true); }
}

window.guestCsv = async function (id) {
  try { await downloadAuthed(`guests/${id}/export.csv`); }
  catch (e) { toast(e.message, true); }
};

window.deleteGuest = async function (id) {
  if (!confirm("Удалить гостя, его ключи и лимиты?")) return;
  try {
    await api(`guests/${id}`, { method: "DELETE" });
    toast("Гость удалён");
    await loadGuests();
  } catch (e) { toast(e.message, true); }
};

/* ---------- Торговый бот ---------- */
async function renderBot() {
  $("#content").innerHTML = `
    <div class="cards" id="bot-cards"></div>
    <div class="section">
      <h2>Управление</h2>
      <button class="btn" onclick="botAction('start')">▶ Старт</button>
      <button class="btn" onclick="botAction('stop')">⏹ Стоп</button>
      <button class="btn" onclick="botAction('restart')">↻ Рестарт</button>
      <button class="btn" onclick="loadBotPage()">Обновить</button>
    </div>
    <div class="section"><h2>Логи (последние 100 строк)</h2>
      <div class="logbox mono" id="bot-logs">…</div></div>
    <div class="section"><h2>Настройки бота (bot.env)</h2>
      <div id="bot-env-form" class="form-grid"></div>
      <button class="btn btn-primary" onclick="saveBotEnv()">Сохранить и перезапустить</button>
      <p class="muted" style="margin-top:6px">Замаскированные ключи (••••••••) останутся без изменений,
        если поле не редактировать.</p></div>`;
  await loadBotPage();
}

async function loadBotPage() {
  try {
    const [st, logs, env] = await Promise.all([
      api("bot/status"), api("bot/logs?tail=100"), api("bot/env")]);
    const c = st.container || {};
    const ok = c.state === "running";
    $("#bot-cards").innerHTML = `
      <div class="card"><h3>Состояние</h3>
        <div class="big"><span class="dot ${ok ? "dot-green" : "dot-red"}"></span>
          ${ok ? "Онлайн" : "Офлайн"}</div>
        <div class="sub">CPU ${c.cpu_pct ?? 0}% · RAM ${c.mem_mb ?? 0} МБ</div></div>
      <div class="card"><h3>Режим</h3>
        <div class="big">${st.dry_run ? "СИМУЛЯЦИЯ" : "БОЕВОЙ"}</div>
        <div class="sub">${escapeHtml(st.symbol || "—")}</div></div>
      <div class="card"><h3>PnL за день</h3>
        <div class="big" style="color:${(st.pnl_day_usdt ?? 0) >= 0 ? "var(--ok)" : "var(--err)"}">
          ${st.pnl_day_usdt ?? "—"} USDT</div>
        <div class="sub">Всего: ${st.pnl_total_usdt ?? "—"} USDT</div></div>
      <div class="card"><h3>Сделок сегодня</h3><div class="big">${st.trades_day ?? "—"}</div>
        <div class="sub">Всего: ${st.trades_total ?? "—"}</div></div>
      <div class="card"><h3>Капитал</h3><div class="big">${st.equity_usdt ?? "—"}</div>
        <div class="sub">Последняя цена: ${st.last_price ?? "—"}</div></div>`;
    $("#bot-logs").textContent = logs.logs || "(логов пока нет)";
    const box = $("#bot-logs"); box.scrollTop = box.scrollHeight;
    $("#bot-env-form").innerHTML = Object.entries(env).map(([k, v]) =>
      `<label>${k} <input data-env-key="${k}" value="${escapeHtml(v)}"
        ${k.includes("SECRET") ? 'type="password"' : ""}></label>`).join("") ||
      '<p class="muted">bot.env не найден</p>';
  } catch (e) { toast(e.message, true); }
}

window.botAction = async function (action) {
  try {
    await api(`bot/${action}`, { method: "POST" });
    toast("Бот: " + action + " выполнен");
    setTimeout(loadBotPage, 2000);
  } catch (e) { toast(e.message, true); }
};

window.saveBotEnv = async function () {
  const values = {};
  document.querySelectorAll("[data-env-key]").forEach((el) => {
    values[el.dataset.envKey] = el.value;
  });
  try {
    const res = await api("bot/env", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ values, restart: true }),
    });
    toast(res.message);
  } catch (e) { toast(e.message, true); }
};

/* ---------- Настройки ---------- */
async function renderSettings() {
  $("#content").innerHTML = `
    <div class="section"><h2>Обфускация AmneziaWG</h2>
      <div class="form-grid" id="awg-form"></div>
      <button class="btn btn-primary" onclick="saveAwg()">Применить (перезапуск AWG)</button>
      <p class="muted" style="margin-top:6px">⚠️ После изменения перевыпустите клиентские конфиги!</p></div>
    <div class="section"><h2>Маскировка Xray REALITY</h2>
      <div class="form-grid"><label>Домен маскировки (SNI) <input id="reality-sni"></label></div>
      <button class="btn btn-primary" onclick="saveReality()">Применить (перезапуск Xray)</button>
      <p class="muted" style="margin-top:6px">Требования к домену: TLS 1.3 + HTTP/2, не google/microsoft,
        популярен у провайдеров (банк, e-commerce).</p></div>
    <div class="section"><h2>Смена пароля</h2>
      <div class="form-grid">
        <label>Текущий пароль <input id="pw-old" type="password"></label>
        <label>Новый пароль (мин. 16) <input id="pw-new" type="password"></label>
      </div>
      <button class="btn btn-primary" onclick="changePassword()">Сменить пароль</button></div>
    <div class="section"><h2>Резервное копирование</h2>
      <button class="btn" onclick="doBackup()">⬇ Скачать бэкап (ZIP)</button>
      <label class="btn" style="margin-left:8px">⬆ Восстановить ZIP
        <input id="restore-file" type="file" accept=".zip" class="hidden"></label>
      <p class="muted" style="margin-top:6px">Бэкап содержит ключи — храните его в безопасном месте!</p></div>`;
  try {
    const [awg, reality] = await Promise.all([api("settings/awg"), api("settings/reality")]);
    $("#awg-form").innerHTML = Object.entries(awg.params).map(([k, v]) =>
      `<label>${k} <input data-awg="${k}" value="${escapeHtml(v)}"></label>`).join("") +
      `<label>Порт UDP <input value="${awg.awg_port}" disabled></label>
       <label>MTU <input value="${awg.awg_mtu}" disabled></label>`;
    $("#reality-sni").value = reality.sni;
  } catch (e) { toast(e.message, true); }
  $("#restore-file").addEventListener("change", doRestore);
}

window.saveAwg = async function () {
  const params = {};
  document.querySelectorAll("[data-awg]").forEach((el) => { params[el.dataset.awg] = el.value.trim(); });
  try {
    const res = await api("settings/awg", {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ params }),
    });
    toast(res.message);
  } catch (e) { toast(e.message, true); }
};

window.saveReality = async function () {
  try {
    const res = await api("settings/reality", {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sni: $("#reality-sni").value.trim() }),
    });
    toast(res.message);
  } catch (e) { toast(e.message, true); }
};

window.changePassword = async function () {
  try {
    await api("settings/password", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        current_password: $("#pw-old").value, new_password: $("#pw-new").value,
      }),
    });
    toast("Пароль изменён — войдите заново");
    localStorage.removeItem("sn_refresh");
    setTimeout(showLogin, 1500);
  } catch (e) { toast(e.message, true); }
};

window.doBackup = async function () {
  try { await downloadAuthed("settings/backup"); toast("Бэкап скачан"); }
  catch (e) { toast(e.message, true); }
};

async function doRestore(e) {
  const file = e.target.files[0];
  if (!file) return;
  if (!confirm("Восстановление заменит текущие конфиги и базу. Продолжить?")) return;
  const fd = new FormData();
  fd.append("file", file);
  try {
    const res = await fetch(basePath() + "api/settings/restore", {
      method: "POST",
      headers: { Authorization: "Bearer " + state.accessToken },
      body: fd,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Ошибка восстановления");
    toast(data.message);
  } catch (err) { toast(err.message, true); }
}

/* ---------- Аудит ---------- */
async function renderAudit() {
  $("#content").innerHTML = `
    <div class="section"><h2>Журнал аудита (последние 200 событий)</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>Время (UTC)</th><th>Действие</th><th>Детали</th><th>IP</th></tr></thead>
        <tbody id="audit-body"></tbody>
      </table></div></div>`;
  try {
    const rows = await api("audit?limit=200");
    $("#audit-body").innerHTML = rows.map((r) =>
      `<tr><td class="mono">${escapeHtml((r.ts || "").replace("T", " ").slice(0, 19))}</td>
       <td><span class="badge">${escapeHtml(r.action)}</span></td>
       <td>${escapeHtml(r.detail)}</td><td class="mono">${escapeHtml(r.ip)}</td></tr>`
    ).join("") || '<tr><td colspan="4" class="muted">Журнал пуст</td></tr>';
  } catch (e) { toast(e.message, true); }
}

/* ---------------- Инициализация ---------------- */
(async function init() {
  // Пробуем восстановить сессию по refresh-токену
  if (await refreshAccessToken()) {
    showApp();
  } else {
    showLogin();
  }
  // Периодическое обновление access-токена (за 5 минут до истечения)
  setInterval(refreshAccessToken, 25 * 60 * 1000);
})();
