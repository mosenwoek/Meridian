// Panel IP access control page: allowlist / denylist by IP or CIDR, optional
// country codes, and a redirect URL for blocked visitors. The /entry escape
// hatch is documented here because it is the only way back in after a mistake.
let ipAccessCleanup = null;

function renderIPAccessSettings() {
  const page = document.getElementById('page-settings-ip-access');
  if (!page) return;
  if (typeof ipAccessCleanup === 'function') ipAccessCleanup();
  page.innerHTML = `<div class="settings-layout fade-up">${globalSettingsNav('ip-access')}<main class="settings-content">
    <section class="settings-panel">
      <header><h2>面板访问控制</h2></header>
      <p class="settings-panel-help">只限制管理面板（含 /api）。站点反代与播放不受影响。被拦时可跳转或显示禁用页。</p>
      <label class="settings-field"><span>模式</span>
        <select class="form-select" id="ip-mode">
          <option value="off">关闭（所有人可访问）</option>
          <option value="allow">白名单（仅列表内放行）</option>
          <option value="deny">黑名单（列表内拦截）</option>
        </select>
      </label>
      <label class="settings-field"><span>IP / CIDR 列表</span>
        <textarea class="form-input" id="ip-networks" rows="6" spellcheck="false" placeholder="每行一个：&#10;1.2.3.4&#10;10.0.0.0/8&#10;2001:db8::/32"></textarea>
        <small>裸 IP 会自动补 /32 或 /128。</small>
      </label>
      <label class="settings-field"><span>国家码（可选）</span>
        <input class="form-input" id="ip-countries" placeholder="CN, HK, JP（需前置代理透传 cf-ipcountry 或 x-country）">
      </label>
      <label class="settings-field"><span>被拦跳转地址（可选）</span>
        <input class="form-input" id="ip-redirect" placeholder="https://example.com/blocked">
        <small>留空则显示“你的 IP 已被禁用”页面。</small>
      </label>
      <div class="settings-save-bar">
        <button class="telegram-btn" id="ip-save" type="button">保存</button>
      </div>
      <p class="form-help" id="ip-result" role="status"></p>
    </section>
    <section class="settings-panel">
      <header><h2>逃生入口</h2></header>
      <p class="settings-panel-help">如果把自己锁在外面，访问面板的 <span class="mono">/entry</span> 页面（或用下方表单），输入面板账号密码，当前 IP 会被永久加入放行名单。此入口只认密码，不认已登录的 Cookie。</p>
      <div class="settings-grid">
        <label class="settings-field"><span>用户名</span><input class="form-input" id="entry-user" autocomplete="username"></label>
        <label class="settings-field"><span>密码</span><input class="form-input" id="entry-pass" type="password" autocomplete="current-password"></label>
      </div>
      <div class="settings-save-bar"><button class="telegram-btn" id="entry-submit" type="button">解锁当前 IP</button></div>
      <p class="form-help" id="entry-result" role="status"></p>
      <div id="entry-list"></div>
    </section>
  </main></div>`;
  bindGlobalSettingsNav(page);
  const get = id => page.querySelector('#ip-' + id);
  const result = get('result'), entryResult = page.querySelector('#entry-result'), entryList = page.querySelector('#entry-list');
  let policy = null;

  const paint = data => {
    policy = data || { mode: 'off', networks: [], countries: [], redirect_url: '', escaped_networks: [] };
    get('mode').value = policy.mode || 'off';
    get('networks').value = (policy.networks || []).join('\n');
    get('countries').value = (policy.countries || []).join(', ');
    get('redirect').value = policy.redirect_url || '';
    const escaped = policy.escaped_networks || [];
    entryList.innerHTML = escaped.length
      ? `<p class="form-help">已放行的逃生地址（${escaped.length}）：</p><ul class="form-help">${escaped.map(v => `<li class="mono">${esc(v)}</li>`).join('')}</ul>`
      : '<p class="form-help">尚无逃生地址记录。</p>';
  };

  get('save').onclick = async () => {
    get('save').disabled = true;
    result.textContent = '正在保存…';
    const payload = {
      mode: get('mode').value,
      networks: get('networks').value.split('\n').map(v => v.trim()).filter(Boolean),
      countries: get('countries').value.split(/[,，\s]+/).map(v => v.trim()).filter(Boolean),
      redirect_url: get('redirect').value.trim(),
    };
    try {
      paint(await API.saveIPAccess(payload));
      result.textContent = payload.mode === 'off' ? '已保存：访问控制已关闭' : '已保存并立即生效';
    } catch (error) {
      result.textContent = '保存失败：' + (error.message || '请求异常');
    } finally { get('save').disabled = false; }
  };

  page.querySelector('#entry-submit').onclick = async () => {
    const user = page.querySelector('#entry-user').value.trim();
    const pass = page.querySelector('#entry-pass').value;
    if (!user || !pass) { entryResult.textContent = '请填写用户名和密码'; return; }
    entryResult.textContent = '正在验证…';
    try {
      const res = await fetch('/api/entry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || '验证失败');
      entryResult.textContent = `已放行 ${data.ip || '当前 IP'}`;
      page.querySelector('#entry-pass').value = '';
      API.getIPAccess().then(paint).catch(() => {});
    } catch (error) {
      entryResult.textContent = error.message || '验证失败';
    }
  };

  API.getIPAccess().then(data => {
    if (Router.current !== 'settings-ip-access') return;
    paint(data);
  }).catch(error => { result.textContent = '读取配置失败：' + (error.message || '请求异常'); });

  ipAccessCleanup = () => { get('save').onclick = null; };
}
