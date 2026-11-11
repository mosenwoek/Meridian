// Cloudflare credentials page: store the DNS API token once, reuse it for all
// future certificate issuance and renewal. Rendered as a settings child page.
let cloudflarePageCleanup = null;

function renderCloudflareSettings() {
  const page = document.getElementById('page-settings-cloudflare');
  if (!page) return;
  if (typeof cloudflarePageCleanup === 'function') cloudflarePageCleanup();
  page.innerHTML = `<div class="settings-layout fade-up">${globalSettingsNav('cloudflare')}<main class="settings-content">
    <section class="settings-panel">
      <header><h2>Cloudflare</h2></header>
      <p class="settings-panel-help">保存一次 DNS API Token，之后申请泛域名证书、自动续期都不再需要重新填写。Token 加密后存于本地数据库，不会在页面回显。</p>
      <div class="settings-grid">
        <label class="settings-field"><span>DNS API Token</span>
          <input class="form-input" id="cf-token" type="password" autocomplete="new-password" maxlength="512" placeholder="填写新的 Token（留空则保留现有）">
          <small>权限要求：Zone → Zone → Read 与 Zone → DNS → Edit；Zone Resources 选中你的域名。</small>
        </label>
        <label class="settings-field"><span>ACME 邮箱</span>
          <input class="form-input" id="cf-email" type="email" autocomplete="email" placeholder="admin@example.com">
          <small>Let's Encrypt 到期通知与账户标识。</small>
        </label>
      </div>
      <div class="settings-save-bar">
        <button class="telegram-btn" id="cf-test" type="button">测试连接</button>
        <button class="telegram-btn primary" id="cf-save" type="button">保存</button>
      </div>
      <p class="form-help" id="cf-result" role="status"></p>
      <div id="cf-zones"></div>
    </section>
  </main></div>`;
  bindGlobalSettingsNav(page);
  const get = id => page.querySelector('#cf-' + id);
  const result = get('result'), zoneBox = get('zones');
  let busy = false;
  let status = { configured: false };

  const setBusy = state => {
    busy = state;
    get('test').disabled = state;
    get('save').disabled = state;
  };

  const showZones = zones => {
    if (!Array.isArray(zones) || !zones.length) { zoneBox.innerHTML = ''; return; }
    zoneBox.innerHTML = `<p class="form-help">此 Token 可见的 Zone（${zones.length}）：</p>
      <ul class="form-help">${zones.map(z => `<li><span class="mono">${esc(z.name)}</span> · ${esc(z.status || '')}</li>`).join('')}</ul>`;
  };

  get('test').onclick = async () => {
    if (busy) return;
    setBusy(true);
    result.textContent = '正在连接 Cloudflare…';
    try {
      const data = await API.testCloudflareSettings({ dns_api_token: get('token').value.trim() });
      if (data && data.success) {
        result.textContent = `连接正常${Array.isArray(data.zones) ? `，可见 ${data.zones.length} 个 Zone` : ''}`;
        showZones(data.zones);
      } else {
        result.textContent = `连接失败：${(data && data.message) || '未知错误'}`;
        zoneBox.innerHTML = '';
      }
    } catch (error) {
      result.textContent = '连接失败：' + (error.message || '请求异常');
      zoneBox.innerHTML = '';
    } finally {
      setBusy(false);
    }
  };

  get('save').onclick = async () => {
    if (busy) return;
    const token = get('token').value.trim();
    const email = get('email').value.trim();
    if (!token && !status.configured) { result.textContent = '请填写 DNS API Token'; return; }
    if (!token && !email) { /* keep stored values */ }
    setBusy(true);
    result.textContent = '正在保存…';
    try {
      const payload = {};
      if (token) payload.dns_api_token = token;
      if (email) payload.email = email;
      const data = await API.saveCloudflareSettings(payload);
      status = Object.assign({}, status, data || {});
      result.textContent = data && data.configured ? '已保存，证书申请与续期将使用此 Token' : '已保存';
      get('token').value = '';
    } catch (error) {
      result.textContent = '保存失败：' + (error.message || '请求异常');
    } finally {
      setBusy(false);
    }
  };

  API.cloudflareSettings().then(data => {
    if (Router.current !== 'settings-cloudflare') return;
    status = data || status;
    get('email').value = (data && data.email) || '';
    result.textContent = data && data.configured
      ? `已保存 Token${data.email ? `（${data.email}）` : ''}；留空保存可保留现有 Token`
      : '尚未保存 Token。填写后可保存，也可直接测试连接。';
  }).catch(error => {
    result.textContent = '读取配置失败：' + (error.message || '请求异常');
  });

  cloudflarePageCleanup = () => { get('test').onclick = null; get('save').onclick = null; };
}
