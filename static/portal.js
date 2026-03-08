const state = {
  summary: null,
  user: null,
  workspace: null,
  page: "dashboard",
};

const dom = {
  byId(id) {
    return document.getElementById(id);
  },
};

function setText(id, value) {
  const element = dom.byId(id);
  if (element) {
    element.textContent = value;
  }
}

function showBlock(id, visible) {
  const element = dom.byId(id);
  if (!element) {
    return;
  }
  element.classList.toggle("hidden-block", !visible);
}

function showNotice(id, message, kind = "info") {
  const element = dom.byId(id);
  if (!element) {
    return;
  }
  element.className = `notice ${kind}`;
  element.textContent = message;
  element.classList.remove("hidden-block");
}

function formatDateTime(value) {
  if (!value) {
    return "--";
  }
  const normalized = String(value).replace(" ", "T");
  const date = new Date(normalized.endsWith("Z") ? normalized : `${normalized}Z`);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString("zh-CN", { hour12: false });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function statusClass(status) {
  const text = String(status || "").toLowerCase();
  if (text.includes("success")) return "success";
  if (text.includes("fail") || text.includes("error")) return "error";
  if (text.includes("cancel") || text.includes("timeout")) return "warning";
  return "info";
}

function isAuthenticated() {
  return !!state.user;
}

async function requestJson(url, options = {}) {
  const headers = {
    Accept: "application/json",
    ...(options.headers || {}),
  };
  let body;
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }

  const response = await fetch(url, {
    method: options.method || "GET",
    headers,
    body,
    credentials: "same-origin",
  });

  const rawText = await response.text();
  let payload = {};
  if (rawText) {
    try {
      payload = JSON.parse(rawText);
    } catch (_) {
      payload = { raw: rawText };
    }
  }

  if (!response.ok) {
    throw new Error(payload.detail || payload.message || rawText || `HTTP ${response.status}`);
  }
  return payload;
}

function renderAuthTab(tab) {
  document.querySelectorAll(".auth-tab").forEach((button) => {
    button.classList.toggle("active", button.dataset.authTab === tab);
  });
  dom.byId("loginPane")?.classList.toggle("active", tab === "login");
  dom.byId("registerPane")?.classList.toggle("active", tab === "register");
}

function switchPage(page) {
  state.page = page;
  document.querySelectorAll(".nav-btn").forEach((button) => {
    button.classList.toggle("active", button.dataset.page === page);
  });
  ["dashboard", "apiKeys", "redeem", "logs", "account"].forEach((name) => {
    dom.byId(`page${name.charAt(0).toUpperCase()}${name.slice(1)}`)?.classList.toggle("active", name === page);
  });
}

function renderShell() {
  showBlock("guestView", !isAuthenticated());
  showBlock("appView", isAuthenticated());
}

function getRegisterLocation() {
  return window.location.pathname === "/" ? "/" : "master-portal";
}

function renderSummaryHints() {
  const role = state.summary?.service?.role || state.summary?.meta?.role || "unknown";
  const registerButton = dom.byId("registerSubmitBtn");
  const locationHint = dom.byId("registerLocationHint");

  if (locationHint) {
    locationHint.textContent = role === "master"
      ? "当前会校验是否从主节点门户注册。"
      : "当前不是主节点门户，自注册可能被后端拒绝。";
  }
  if (registerButton) {
    registerButton.disabled = false;
  }
}

async function loadSummary() {
  try {
    state.summary = await requestJson("/api/portal/summary");
  } catch (_) {
    state.summary = null;
  }
  renderSummaryHints();
}

function renderHeader() {
  const user = state.user || {};
  const usage = state.workspace?.usage || {};
  setText("headerTitle", `你好，${user.username || "用户"}`);
  setText("headerSubtitle", "这里只展示当前账号自己的信息与操作。")
  setText("headerUsername", user.username || "--");
  setText("headerQuota", `剩余次数 ${user.quota_remaining ?? 0}`);
}

function renderDashboard() {
  const user = state.workspace?.user || state.user || {};
  const usage = state.workspace?.usage || {};
  const recentRedeems = Array.isArray(state.workspace?.recent_redeems) ? state.workspace.recent_redeems : [];
  const latestRedeem = recentRedeems.length > 0 ? recentRedeems[0] : null;

  setText("statQuotaRemaining", user.quota_remaining ?? 0);
  setText("statQuotaUsed", user.quota_used ?? 0);
  setText("statSolveSuccess", usage.solve_success_total ?? 0);
  setText("statSolveFailed", usage.solve_failed_total ?? 0);
  setText("statSuccessRate", usage.success_rate == null ? "--" : `${Number(usage.success_rate).toFixed(2)}%`);
  setText("statLastRequest", formatDateTime(usage.last_request_at));
  setText("usageRuleText", "成功 solve 才扣减 1 次，失败不扣次。")

  showBlock("latestRedeemEmpty", !latestRedeem);
  showBlock("latestRedeemCard", !!latestRedeem);
  if (latestRedeem) {
    setText("latestRedeemCode", latestRedeem.code || "--");
    setText("latestRedeemQuota", latestRedeem.quota_times ?? "--");
    setText("latestRedeemTime", formatDateTime(latestRedeem.redeemed_at));
  }
}

function renderApiKeys() {
  const tbody = dom.byId("apiKeysTableBody");
  if (!tbody) {
    return;
  }
  const items = Array.isArray(state.workspace?.api_keys) ? state.workspace.api_keys : [];
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">暂无 API Key。</td></tr>';
    return;
  }
  tbody.innerHTML = items.map((item) => `
    <tr>
      <td>${escapeHtml(item.name || "--")}</td>
      <td>${escapeHtml(item.key_prefix || "--")}</td>
      <td><span class="status-chip ${item.enabled ? "success" : "warning"}">${item.enabled ? "启用中" : "已禁用"}</span></td>
      <td>${escapeHtml(String(item.quota_used ?? 0))}</td>
      <td>${escapeHtml(formatDateTime(item.last_used_at))}</td>
      <td>
        <button class="btn subtle mini-btn" type="button" data-action="toggle-api-key" data-id="${item.id}" data-enabled="${item.enabled ? 1 : 0}">${item.enabled ? "禁用" : "启用"}</button>
        <button class="btn ghost mini-btn" type="button" data-action="delete-api-key" data-id="${item.id}">软删除</button>
      </td>
    </tr>
  `).join("");
}

function renderTransactions() {
  const tbody = dom.byId("transactionsTableBody");
  if (!tbody) {
    return;
  }
  const items = Array.isArray(state.workspace?.recent_transactions) ? state.workspace.recent_transactions : [];
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">暂无消费记录。</td></tr>';
    return;
  }
  tbody.innerHTML = items.map((item) => {
    const amount = Number(item.change_amount || 0);
    return `
      <tr>
        <td>${escapeHtml(formatDateTime(item.created_at))}</td>
        <td>${escapeHtml(amount > 0 ? `+${amount}` : String(amount))}</td>
        <td>${escapeHtml(String(item.balance_after ?? "--"))}</td>
        <td>${escapeHtml(item.source_type || "--")}</td>
        <td>${escapeHtml(item.note || item.source_ref || "-")}</td>
      </tr>
    `;
  }).join("");
}

function renderRedeems() {
  const tbody = dom.byId("redeemTableBody");
  if (!tbody) {
    return;
  }
  const items = Array.isArray(state.workspace?.recent_redeems) ? state.workspace.recent_redeems : [];
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-cell">暂无兑换记录。</td></tr>';
    return;
  }
  tbody.innerHTML = items.map((item) => `
    <tr>
      <td>${escapeHtml(item.code || "--")}</td>
      <td>${escapeHtml(String(item.quota_times ?? "--"))}</td>
      <td>${escapeHtml(formatDateTime(item.redeemed_at))}</td>
      <td>${escapeHtml(item.note || "-")}</td>
    </tr>
  `).join("");
}

function renderLogs(items) {
  const tbody = dom.byId("logsTableBody");
  if (!tbody) {
    return;
  }
  if (!items || !items.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">暂无日志记录。</td></tr>';
    return;
  }
  tbody.innerHTML = items.map((item) => `
    <tr>
      <td>${escapeHtml(formatDateTime(item.created_at))}</td>
      <td><span class="status-chip ${statusClass(item.status)}">${escapeHtml(item.status || "--")}</span></td>
      <td>${escapeHtml(item.project_id || "--")}</td>
      <td>${escapeHtml(item.action || "--")}</td>
      <td>${escapeHtml(item.api_key_prefix || item.api_key_name || "--")}</td>
      <td>${escapeHtml(item.error_reason || "-")}</td>
    </tr>
  `).join("");
}

function renderAccount() {
  const user = state.workspace?.user || state.user || {};
  setText("accountUsernameValue", user.username || "--");
  setText("accountRegisteredValue", isAuthenticated() ? "已注册" : "未注册");
  setText("accountLocationValue", user.register_location || "--");
  setText("accountEnabledValue", user.enabled ? "启用中" : "已禁用");
  setText("accountCreatedAtValue", formatDateTime(user.created_at));
  setText("accountLastLoginValue", formatDateTime(user.last_login_at));
}

function renderWorkspace() {
  renderShell();
  if (!isAuthenticated()) {
    return;
  }
  renderHeader();
  renderDashboard();
  renderApiKeys();
  renderRedeems();
  renderTransactions();
  renderAccount();
}

async function loadAuthMe() {
  try {
    const payload = await requestJson("/api/portal/auth/me");
    state.workspace = payload;
    state.user = payload.user || null;
  } catch (_) {
    state.workspace = null;
    state.user = null;
  }
  renderWorkspace();
}

async function loadWorkspace(showNoticeMessage = false) {
  if (!isAuthenticated()) {
    return;
  }
  state.workspace = await requestJson("/api/portal/user/overview");
  state.user = state.workspace.user || state.user;
  renderWorkspace();
  if (showNoticeMessage) {
    showNotice("appNotice", "数据已刷新。", "success");
  }
}

async function loadLogs(showNoticeMessage = false) {
  if (!isAuthenticated()) {
    renderLogs([]);
    return;
  }
  const status = String(dom.byId("logStatusFilter")?.value || "").trim();
  const projectId = String(dom.byId("logProjectFilter")?.value || "").trim();
  const params = new URLSearchParams({ limit: "20", offset: "0" });
  if (status) params.set("status", status);
  if (projectId) params.set("project_id", projectId);
  const payload = await requestJson(`/api/portal/user/logs?${params.toString()}`);
  renderLogs(payload.items || []);
  if (showNoticeMessage) {
    showNotice("appNotice", "日志已刷新。", "success");
  }
}

async function checkRegisterStatus(showSuccess = false) {
  const username = String(dom.byId("registerUsername")?.value || "").trim();
  if (!username) {
    showNotice("registerCheckHint", "输入用户名后会自动检查是否已注册。", "info");
    return null;
  }
  const result = await requestJson(`/api/portal/auth/check?username=${encodeURIComponent(username)}`);
  if (result.registered) {
    showNotice("registerCheckHint", result.message || "该用户名已注册，请直接登录。", "warning");
  } else if (showSuccess) {
    showNotice("registerCheckHint", result.message || "该用户名尚未注册，可以继续创建账号。", "success");
  } else {
    showNotice("registerCheckHint", result.message || "该用户名尚未注册。", "info");
  }
  return result;
}

async function handleLogin(event) {
  event.preventDefault();
  const username = String(dom.byId("loginUsername")?.value || "").trim();
  const password = String(dom.byId("loginPassword")?.value || "");
  if (!username || !password) {
    throw new Error("请输入用户名和密码");
  }
  await requestJson("/api/portal/auth/login", {
    method: "POST",
    body: { username, password },
  });
  await loadAuthMe();
  await loadWorkspace(false);
  await loadLogs(false);
  switchPage("dashboard");
  showNotice("appNotice", "登录成功。", "success");
}

async function handleRegister(event) {
  event.preventDefault();
  const username = String(dom.byId("registerUsername")?.value || "").trim();
  const password = String(dom.byId("registerPassword")?.value || "");
  if (!username || !password) {
    throw new Error("用户名和密码不能为空");
  }
  if ((state.summary?.service?.role || state.summary?.meta?.role) === "subnode") {
    throw new Error("当前入口不开放用户自注册");
  }
  const checked = await checkRegisterStatus(false);
  if (checked?.registered) {
    throw new Error(checked.message || "该用户名已注册，请直接登录");
  }
  await requestJson("/api/portal/auth/register", {
    method: "POST",
    body: {
      username,
      password,
      register_location: getRegisterLocation(),
    },
  });
  await loadAuthMe();
  await loadWorkspace(false);
  await loadLogs(false);
  switchPage("dashboard");
  showNotice("appNotice", `注册成功，当前账号 ${username} 已登录。`, "success");
}

async function handleLogout() {
  await requestJson("/api/portal/auth/logout", { method: "POST" });
  state.user = null;
  state.workspace = null;
  renderShell();
  renderAuthTab("login");
  showNotice("guestNotice", "你已退出登录。", "info");
}

async function handleCreateApiKey(event) {
  event.preventDefault();
  const name = String(dom.byId("newApiKeyName")?.value || "").trim();
  if (!name) {
    throw new Error("请填写 API Key 名称");
  }
  const result = await requestJson("/api/portal/user/api-keys", {
    method: "POST",
    body: { name },
  });
  dom.byId("newApiKeyName").value = "";
  showBlock("newApiKeyCard", true);
  setText("newApiKeyValue", result.api_key || "--");
  setText("newApiKeyLabel", result.item?.name || name);
  showNotice("apiKeyNotice", result.message || "API Key 已创建。", "success");
  await loadWorkspace(false);
}

async function handleApiKeyAction(action, apiKeyId, enabled) {
  if (action === "toggle") {
    const result = await requestJson(`/api/portal/user/api-keys/${apiKeyId}`, {
      method: "PATCH",
      body: { enabled: !enabled },
    });
    await loadWorkspace(false);
    showNotice("apiKeyNotice", `API Key ${result.item?.enabled ? "已启用" : "已禁用"}。`, "success");
    return;
  }
  if (action === "delete") {
    await requestJson(`/api/portal/user/api-keys/${apiKeyId}`, { method: "DELETE" });
    await loadWorkspace(false);
    showNotice("apiKeyNotice", `API Key #${apiKeyId} 已软删除。`, "warning");
  }
}

async function handleRedeem(event) {
  event.preventDefault();
  const code = String(dom.byId("redeemCodeInput")?.value || "").trim();
  if (!code) {
    throw new Error("请输入兑换码");
  }
  const result = await requestJson("/api/portal/redeem", {
    method: "POST",
    body: { code },
  });
  dom.byId("redeemCodeInput").value = "";
  await loadWorkspace(false);
  showNotice("redeemNotice", result.message || "兑换成功。", "success");
  showNotice("appNotice", result.message || "兑换成功。", "success");
}

function wireEvents() {
  dom.byId("tabLoginBtn")?.addEventListener("click", () => renderAuthTab("login"));
  dom.byId("tabRegisterBtn")?.addEventListener("click", () => renderAuthTab("register"));

  dom.byId("loginForm")?.addEventListener("submit", async (event) => {
    try {
      await handleLogin(event);
    } catch (error) {
      showNotice("guestNotice", error.message || "登录失败", "error");
    }
  });

  dom.byId("registerUsername")?.addEventListener("blur", async () => {
    try {
      await checkRegisterStatus(false);
    } catch (_) {}
  });

  dom.byId("registerForm")?.addEventListener("submit", async (event) => {
    try {
      await handleRegister(event);
    } catch (error) {
      showNotice("guestNotice", error.message || "注册失败", "error");
    }
  });

  dom.byId("logoutBtn")?.addEventListener("click", async () => {
    try {
      await handleLogout();
    } catch (error) {
      showNotice("appNotice", error.message || "退出失败", "error");
    }
  });

  document.querySelectorAll(".nav-btn[data-page]").forEach((button) => {
    button.addEventListener("click", async () => {
      const page = button.dataset.page || "dashboard";
      switchPage(page);
      if (page === "logs") {
        try {
          await loadLogs(false);
        } catch (error) {
          showNotice("appNotice", error.message || "日志加载失败", "error");
        }
      }
    });
  });

  dom.byId("refreshUserBtn")?.addEventListener("click", async () => {
    try {
      await loadWorkspace(true);
    } catch (error) {
      showNotice("appNotice", error.message || "刷新失败", "error");
    }
  });

  dom.byId("refreshApiKeysBtn")?.addEventListener("click", async () => {
    try {
      await loadWorkspace(true);
      switchPage("apiKeys");
      showNotice("apiKeyNotice", "API Key 列表已刷新。", "success");
    } catch (error) {
      showNotice("apiKeyNotice", error.message || "刷新 API Key 失败", "error");
    }
  });

  dom.byId("createApiKeyForm")?.addEventListener("submit", async (event) => {
    try {
      await handleCreateApiKey(event);
      switchPage("apiKeys");
    } catch (error) {
      showNotice("apiKeyNotice", error.message || "申请 API Key 失败", "error");
    }
  });


  dom.byId("redeemForm")?.addEventListener("submit", async (event) => {
    try {
      await handleRedeem(event);
    } catch (error) {
      showNotice("redeemNotice", error.message || "兑换失败", "error");
    }
  });

  const refreshLogs = async () => {
    try {
      await loadLogs(true);
    } catch (error) {
      showNotice("appNotice", error.message || "日志刷新失败", "error");
    }
  };
  dom.byId("refreshLogsBtn")?.addEventListener("click", refreshLogs);
  dom.byId("logStatusFilter")?.addEventListener("change", refreshLogs);
  dom.byId("logProjectFilter")?.addEventListener("keydown", async (event) => {
    if (event.key !== "Enter") {
      return;
    }
    event.preventDefault();
    await refreshLogs();
  });
}

async function bootstrap() {
  renderShell();
  renderAuthTab("login");
  wireEvents();
  await loadSummary();
  await loadAuthMe();
  if (isAuthenticated()) {
    await loadWorkspace(false);
    await loadLogs(false);
    switchPage("dashboard");
  }
}


document.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }
  if (target.dataset.action === "toggle-api-key") {
    try {
      await handleApiKeyAction("toggle", Number(target.dataset.id), target.dataset.enabled === "1");
    } catch (error) {
      showNotice("apiKeyNotice", error.message || "更新 API Key 失败", "error");
    }
  }
  if (target.dataset.action === "delete-api-key") {
    const apiKeyId = Number(target.dataset.id);
    const ok = window.confirm(`确定软删除 API Key #${apiKeyId} 吗？软删除后该 Key 会被禁用。`);
    if (!ok) return;
    try {
      await handleApiKeyAction("delete", apiKeyId, false);
    } catch (error) {
      showNotice("apiKeyNotice", error.message || "软删除 API Key 失败", "error");
    }
  }
});

window.addEventListener("DOMContentLoaded", bootstrap);
