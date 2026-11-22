/* 格式互转页交互：全部本地完成，不发请求 */
(function () {
  var el = function (id) { return document.getElementById(id); };
  var input = el('input'), drop = el('drop'), fileInput = el('file');
  var srcPass = el('srcPass'), dstPass = el('dstPass'), aliasInput = el('alias');
  var statusEl = el('status'), notesEl = el('notes'), summaryEl = el('summary');
  var outList = el('outList'), toastEl = el('toast'), dstPassLabel = el('dstPassLabel');
  var btnRead = el('btnRead'), btnGo = el('btnGo'), btnClear = el('btnClear');

  var st = { bytes: null, fileName: '', bundle: null };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  var toastTimer = null;
  function toast(msg, bad) {
    toastEl.textContent = msg;
    toastEl.className = 'toast show' + (bad ? ' bad' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.className = 'toast'; }, bad ? 4200 : 2400);
  }

  /* ---------- 输入 ---------- */

  function setDropFile(f) {
    if (!f) return;
    if (f.size > 4 * 1024 * 1024) { toast('文件超过 4MB，正常证书不会这么大', true); return; }
    var reader = new FileReader();
    reader.onload = function () {
      st.bytes = new Uint8Array(reader.result);
      st.fileName = f.name;
      input.value = '';
      statusEl.textContent = f.name + ' · ' + (f.size < 1024 ? f.size + ' B' : Math.round(f.size / 1024) + ' KB');
      toast('已载入口令按需填写，然后点「读取」');
    };
    reader.onerror = function () { toast('文件读取失败', true); };
    reader.readAsArrayBuffer(f);
  }

  drop.addEventListener('click', function () { fileInput.click(); });
  fileInput.addEventListener('change', function () {
    setDropFile(fileInput.files && fileInput.files[0]);
    fileInput.value = '';
  });
  ['dragenter', 'dragover'].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('over'); });
  });
  drop.addEventListener('drop', function (e) {
    var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    setDropFile(f);
  });

  input.addEventListener('input', function () {
    if (input.value.trim()) {
      st.bytes = null;
      st.fileName = '';
      statusEl.textContent = '文本内容 · ' + input.value.length + ' 字符';
    } else if (!st.bytes) {
      statusEl.textContent = '还没有内容';
    }
  });

  btnClear.addEventListener('click', function () {
    input.value = '';
    st.bytes = null;
    st.fileName = '';
    st.bundle = null;
    statusEl.textContent = '还没有内容';
    notesEl.classList.add('hidden');
    summaryEl.classList.add('hidden');
    outList.innerHTML = '';
  });

  /* ---------- 读取 ---------- */

  btnRead.addEventListener('click', function () {
    var pass = srcPass.value || '';
    var payload = st.bytes || input.value;
    if (st.bytes && st.bytes.length < 8) { toast('文件看起来是空的', true); return; }
    if (!st.bytes && !input.value.trim()) { toast('先贴点内容，或者选个文件', true); return; }

    btnRead.disabled = true;
    btnRead.textContent = '读取中…';

    Convert.load(payload, pass).then(function (res) {
      st.bundle = res.value;
      renderSummary(res);
      renderNotes(res.notes);
      outList.innerHTML = '';
      if (!res.value.certs.length) {
        toast('只有私钥没有证书，导出的密钥库里不会有证书', true);
      } else {
        toast('读取成功，接着选目标格式');
      }
    }).catch(function (e) {
      st.bundle = null;
      summaryEl.classList.add('hidden');
      renderNotes([e.message]);
      toast(e.message, true);
    }).then(function () {
      btnRead.disabled = false;
      btnRead.textContent = '读取';
    });
  });

  function renderNotes(list) {
    if (!list || !list.length) { notesEl.classList.add('hidden'); notesEl.innerHTML = ''; return; }
    notesEl.innerHTML = list.map(function (n) {
      return '<div class="note-line">' + esc(n) + '</div>';
    }).join('');
    notesEl.classList.remove('hidden');
  }

  var KIND_NAME = { pem: 'PEM 文本', jks: 'JKS 密钥库', pkcs12: 'PKCS#12 密钥库', der: 'DER 证书' };

  function renderSummary(res) {
    var b = res.value, parts = [];
    parts.push('证书 <b>' + b.certs.length + '</b> 张');
    if (b.privateKeyDer) {
      parts.push('私钥 <b>1</b> 个' + (b.privateAlias ? '（别名 ' + esc(b.privateAlias) + '）' : ''));
    } else {
      parts.push('没有私钥，只能导出证书');
    }
    if (b.certs.length) {
      try {
        var c = CertTool.parseCertificate(b.certs[0].der);
        var alg = c.spki && c.spki.alg ? '，' + esc(c.spki.alg) + (c.spki.bits ? ' ' + c.spki.bits + ' 位' : '') : '';
        parts.push('第一张主体 <b>' + esc(c.subject) + '</b>' + alg);
      } catch (e) { }
    }
    summaryEl.innerHTML = '<div class="sm-title">✓ 已读取 · ' + (KIND_NAME[b.kind] || esc(b.kind)) +
      '</div><div class="sm-body">' + parts.join('；') + '</div>';
    summaryEl.classList.remove('hidden');
  }

  /* ---------- 目标格式 ---------- */

  var fmtLabels = Array.prototype.slice.call(document.querySelectorAll('.fmt'));
  function bindFmt() {
    fmtLabels.forEach(function (f) {
      var radio = f.querySelector('input[type=radio]');
      radio.addEventListener('change', function () {
        fmtLabels.forEach(function (x) { x.classList.toggle('active', x.contains(radio) && radio.checked); });
        var t = radio.value;
        dstPass.disabled = (t === 'pem');
        dstPassLabel.textContent = t === 'pem' ? '口令（PEM 不需要）' : '目标口令';
        dstPass.parentNode.style.opacity = t === 'pem' ? '.55' : '';
      });
      if (radio.checked) f.classList.add('active');
    });
  }
  bindFmt();
  dstPass.disabled = true;
  dstPass.parentNode.style.opacity = '.55';

  /* ---------- 生成 ---------- */

  function baseName() {
    var b = st.bundle;
    if (b && b.certs.length) {
      try {
        var c = CertTool.parseCertificate(b.certs[0].der);
        var m = /CN=([^,]+)/.exec(c.subject || '');
        if (m) {
          var v = m[1].trim().replace(/^\*\./, 'wildcard.').replace(/[^A-Za-z0-9._-]/g, '-');
          if (v) return v;
        }
      } catch (e) { }
    }
    if (st.fileName) return st.fileName.replace(/\.[A-Za-z0-9]+$/, '');
    return 'keystore';
  }

  function download(name, data, mime) {
    var blob = new Blob([data], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
  }

  function renderOut(rows) {
    outList.innerHTML = rows.map(function (r, i) {
      return '<div class="outrow"><div class="or-name"><b>' + esc(r.name) + '</b><span>' +
        esc(r.label) + '</span></div><button class="btn primary small" data-i="' + i + '">下载</button></div>';
    }).join('');
    Array.prototype.forEach.call(outList.querySelectorAll('button[data-i]'), function (btn) {
      btn.addEventListener('click', function () {
        var r = rows[Number(btn.dataset.i)];
        download(r.name, r.data, r.mime);
        toast('已下载 ' + r.name);
      });
    });
  }

  btnGo.addEventListener('click', function () {
    if (!st.bundle) { toast('先点上面的「读取」，确认内容能解析再来转', true); return; }
    var target = (document.querySelector('input[name=target]:checked') || {}).value || 'pem';
    var pass = dstPass.value || '';
    var alias = (aliasInput.value || '').trim();
    var base = baseName();

    btnGo.disabled = true;
    btnGo.textContent = '生成中…';

    var task = Promise.resolve();
    if (target === 'pem') {
      task = Convert.toPem(st.bundle).then(function (r) {
        var rows = [];
        if (r.fullchain) {
          rows.push({ name: base + '-fullchain.pem', label: '证书链，全部证书按顺序拼在一起', data: r.fullchain, mime: 'application/x-pem-file' });
        }
        if (r.privateKey) {
          rows.push({ name: base + '-private.key', label: '私钥，PKCS#8 未加密（别外传）', data: r.privateKey, mime: 'application/x-pem-file' });
        }
        if (!rows.length) throw new Error('没有可导出的内容');
        return rows;
      });
    } else if (target === 'jks') {
      if (pass.length < 6) throw new Error('JKS 的口令至少 6 个字符（keytool 的硬要求）');
      task = Convert.toJks(st.bundle, pass, pass).then(function (bytes) {
        return [{ name: base + '.jks', label: 'JKS 密钥库，口令就是你填的那个', data: bytes, mime: 'application/octet-stream' }];
      });
    } else {
      if (pass.length < 6) throw new Error('PKCS#12 的口令至少 6 个字符');
      task = Promise.resolve().then(function () {
        var bytes = Convert.toPkcs12(st.bundle, pass, alias || undefined);
        var nm = base + '.p12';
        return [{ name: nm, label: 'PKCS#12（.p12 / .pfx），口令就是你填的那个', data: bytes, mime: 'application/x-pkcs12' }];
      });
    }

    task.then(function (rows) {
      renderOut(rows);
      toast('已生成 ' + rows.length + ' 个文件，点下载取走');
    }).catch(function (e) {
      outList.innerHTML = '';
      toast(e.message, true);
      renderNotes([e.message]);
    }).then(function () {
      btnGo.disabled = false;
      btnGo.textContent = '生成';
    });
  });
})();
