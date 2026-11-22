/* 国密工具箱 · 全部计算在浏览器本地完成，不发送任何请求 */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const sm2lib = window.sm2;
const sm3hash = window.sm3;
const sm4lib = window.sm4;

/* ============================================================ 基础工具 */

let toastTimer;
function toast(msg, bad = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "toast show" + (bad ? " bad" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.className = "toast"), 2200);
}

const hexToBytes = (h) => new Uint8Array((h.match(/../g) || []).map((x) => parseInt(x, 16)));
const bytesToHex = (a) => [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
const utf8Bytes = (s) => new TextEncoder().encode(s);

function hexToBase64(hex) {
  let bin = "";
  for (let i = 0; i < hex.length; i += 2) bin += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  return btoa(bin);
}

function base64ToHex(b64) {
  const bin = atob(String(b64).trim());
  return [...bin].map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
}

function cleanHex(v) {
  return String(v || "").replace(/[\s:,\-]/g, "").replace(/^0x/i, "").toLowerCase();
}

function normHex(v, len, label) {
  const h = cleanHex(v);
  if (!h) throw new Error(`请填写${label}`);
  if (!/^[0-9a-f]+$/.test(h)) throw new Error(`${label}含有非十六进制字符`);
  if (len && h.length !== len) throw new Error(`${label}应为 ${len} 位 hex，当前 ${h.length} 位`);
  return h;
}

/* 公钥：支持 130(04+XY) / 128(XY) / 66(02|03+X 压缩) */
function normPub(v, label = "公钥") {
  const h = cleanHex(v);
  if (!h) throw new Error(`请填写${label}`);
  if (!/^[0-9a-f]+$/.test(h)) throw new Error(`${label}含有非十六进制字符`);
  if (h.length === 130 && h.startsWith("04")) return h;
  if (h.length === 128) return "04" + h;
  if (h.length === 66 && (h.startsWith("02") || h.startsWith("03"))) return h;
  throw new Error(`${label}长度异常（${h.length} 位），应为 128 / 130 / 66 位 hex`);
}

function normPriv(v, label = "私钥") {
  let h = cleanHex(v);
  if (!h) throw new Error(`请填写${label}`);
  if (!/^[0-9a-f]+$/.test(h)) throw new Error(`${label}含有非十六进制字符`);
  if (h.length === 66 && h.startsWith("00")) h = h.slice(2);
  if (h.length !== 64) throw new Error(`${label}应为 64 位 hex，当前 ${h.length} 位`);
  return h;
}

const radioVal = (name) => ($(`input[name="${name}"]:checked`) || {}).value;

/* 密文格式自动识别：优先 hex，否则按 base64 */
function decodeCipher(text, label = "密文") {
  const raw = String(text || "").trim();
  if (!raw) throw new Error(`请填写${label}`);
  const noSpace = raw.replace(/\s/g, "");
  if (/^[0-9a-fA-F]+$/.test(noSpace) && noSpace.length % 2 === 0) return noSpace.toLowerCase();
  try {
    const h = base64ToHex(noSpace);
    if (h && /^[0-9a-f]+$/.test(h)) return h;
  } catch (_) { /* fallthrough */ }
  throw new Error(`${label}既不是 hex 也不是 base64`);
}

function setOut(id, text) {
  $(`#${id}`).value = text;
}

async function copyText(text) {
  if (!text) return toast("没有内容可复制", true);
  try {
    await navigator.clipboard.writeText(text);
    toast("已复制到剪贴板");
  } catch (_) {
    const t = document.createElement("textarea");
    t.value = text;
    document.body.appendChild(t);
    t.select();
    document.execCommand("copy");
    t.remove();
    toast("已复制");
  }
}

/* 统一的错误收口：把异常变成一句人话，而不是堆栈 */
function guard(btn, fn) {
  const old = btn.textContent;
  btn.disabled = true;
  try {
    fn();
  } catch (e) {
    toast(e.message || String(e), true);
  } finally {
    btn.disabled = false;
    btn.textContent = old;
  }
}

/* ============================================================ 导航 */

$("#nav").addEventListener("click", (e) => {
  const item = e.target.closest(".nav-item");
  if (!item) return;
  $$(".nav-item").forEach((n) => n.classList.toggle("active", n === item));
  $$(".panel").forEach((p) => p.classList.toggle("hidden", p.dataset.panel !== item.dataset.panel));
  window.scrollTo({ top: 0, behavior: "smooth" });
});

/* ============================================================ 复制 / 回填 */

document.addEventListener("click", async (e) => {
  const c = e.target.closest("[data-copy]");
  if (c) {
    const src = $(`#${c.dataset.copy}`);
    if (src) await copyText(src.value);
    return;
  }
  const f = e.target.closest("[data-fill-from]");
  if (f) {
    const from = $(`#${f.dataset.fillFrom}`);
    const to = $(`#${f.dataset.target}`);
    if (from && to) {
      to.value = from.value;
      toast("已填入上方内容");
    }
  }
});

/* ============================================================ SM2 密钥 */

$("#genKey").addEventListener("click", () =>
  guard($("#genKey"), () => {
    const kp = sm2lib.generateKeyPairHex();
    $("#sm2-pub").value = kp.publicKey;
    $("#sm2-priv").value = kp.privateKey;
    toast("已生成新的 SM2 密钥对");
  })
);

$("#pubFromPriv").addEventListener("click", () =>
  guard($("#pubFromPriv"), () => {
    const priv = normPriv($("#sm2-priv").value);
    $("#sm2-pub").value = sm2lib.getPublicKeyFromPrivateKey(priv);
    toast("已根据私钥推导公钥");
  })
);

/* ============================================================ SM2 加解密 */

$("#sm2-encrypt").addEventListener("click", () =>
  guard($("#sm2-encrypt"), () => {
    const plain = $("#sm2-plain").value;
    if (!plain) throw new Error("请输入要加密的明文");
    const pub = normPub($("#sm2-pub").value);
    const mode = Number(radioVal("sm2mode"));
    const t0 = performance.now();
    const ct = sm2lib.doEncrypt(plain, pub, mode);
    setOut("sm2-ct", ct);
    toast(`加密完成 ${(performance.now() - t0).toFixed(0)} ms · ${ct.length} 位 hex`);
  })
);

$("#sm2-decrypt").addEventListener("click", () =>
  guard($("#sm2-decrypt"), () => {
    const ct = cleanHex($("#sm2-ct-in").value);
    if (!ct) throw new Error("请填写要解密的密文");
    const priv = normPriv($("#sm2-priv").value);
    const mode = Number(radioVal("sm2mode"));
    const pt = sm2lib.doDecrypt(ct, priv, mode, { output: "string" });
    if (!pt) throw new Error("解密失败：私钥不匹配，或密文顺序（C1C3C2 / C1C2C3）选反了");
    setOut("sm2-pt", pt);
    toast("解密完成");
  })
);

$("#sm2-plain").addEventListener("input", (e) => {
  const n = e.target.value.length;
  const el = $("#sm2-plain-len");
  el.textContent = n
    ? `${n} 个字符 · SM2 加密会随长度变慢${n > 1000 ? "，建议改用数字信封" : ""}`
    : "SM2 加密大段文本很慢，超过 1000 字建议用「数字信封」";
});

/* ============================================================ SM2 签名验签 */

$("#doSign").addEventListener("click", () =>
  guard($("#doSign"), () => {
    const msg = $("#sign-msg").value;
    if (!msg) throw new Error("请输入要签名的消息");
    const priv = normPriv($("#sign-priv").value.trim() || $("#sm2-priv").value, "私钥");
    const der = $("#sign-der").checked;
    const sig = sm2lib.doSignature(msg, priv, { hash: true, der });
    setOut("sign-out", sig);
    toast(`签名完成 · ${der ? "DER" : "RS"} 格式 · ${sig.length} 位 hex`);
  })
);

$("#doVerify").addEventListener("click", () =>
  guard($("#doVerify"), () => {
    const msg = $("#verify-msg").value;
    const pub = normPub($("#verify-pub").value.trim() || $("#sm2-pub").value);
    const sig = cleanHex($("#verify-sig").value);
    if (!sig) throw new Error("请填写签名串");
    const der = $("#verify-der").checked;
    const ok = sm2lib.doVerifySignature(msg, sig, pub, { hash: true, der });
    const box = $("#verify-result");
    box.className = "result " + (ok ? "ok" : "bad");
    box.textContent = ok ? "✓ 验签通过：签名与消息、公钥匹配" : "✗ 验签失败：消息或签名或公钥不一致";
  })
);

/* ============================================================ SM4 */

function sm4Params() {
  const key = hexToBytes(normHex($("#sm4-key").value, 32, "SM4 密钥"));
  const mode = radioVal("sm4mode");
  const iv = mode === "cbc" ? hexToBytes(normHex($("#sm4-iv").value, 32, "IV")) : null;
  const padding = radioVal("sm4pad");
  return { key, mode, iv, padding };
}

$("#genSm4Key").addEventListener("click", () =>
  guard($("#genSm4Key"), () => {
    const k = crypto.getRandomValues(new Uint8Array(16));
    const i = crypto.getRandomValues(new Uint8Array(16));
    $("#sm4-key").value = bytesToHex(k);
    $("#sm4-iv").value = bytesToHex(i);
    toast("已生成随机密钥与 IV");
  })
);

$$('input[name="sm4mode"]').forEach((r) =>
  r.addEventListener("change", () => {
    $("#sm4-iv-wrap").classList.toggle("hidden", radioVal("sm4mode") === "ecb");
  })
);

$("#sm4-encrypt").addEventListener("click", () =>
  guard($("#sm4-encrypt"), () => {
    const p = sm4Params();
    const raw = $("#sm4-plain").value;
    if (!raw) throw new Error("请输入要加密的内容");

    let input;
    if (p.padding === "none") {
      const h = cleanHex(raw);
      if (!h || !/^[0-9a-f]+$/.test(h)) throw new Error("无填充模式需要 hex 明文");
      if (h.length % 32 !== 0) throw new Error("无填充模式的明文长度必须是 16 字节（32 位 hex）的整数倍");
      input = hexToBytes(h);
    } else {
      input = raw;
    }

    const opt = { mode: p.mode, padding: p.padding };
    if (p.iv) opt.iv = p.iv;
    const ct = sm4lib.encrypt(input, p.key, opt);
    const out = radioVal("sm4out") === "base64" ? hexToBase64(ct) : ct;
    setOut("sm4-ct", out);
    toast(`SM4-${p.mode.toUpperCase()} 加密完成 · ${ct.length / 2} 字节`);
  })
);

$("#sm4-decrypt").addEventListener("click", () =>
  guard($("#sm4-decrypt"), () => {
    const p = sm4Params();
    const ctHex = decodeCipher($("#sm4-ct-in").value);
    const opt = { mode: p.mode, padding: p.padding, output: "string" };
    if (p.iv) opt.iv = p.iv;

    if (p.padding === "none") {
      const arr = sm4lib.decrypt(hexToBytes(ctHex), p.key, { mode: p.mode, iv: p.iv || [], padding: "none", output: "array" });
      setOut("sm4-pt", bytesToHex(arr));
      toast("解密完成（无填充，输出 hex）");
      return;
    }
    const pt = sm4lib.decrypt(hexToBytes(ctHex), p.key, opt);
    setOut("sm4-pt", pt);
    toast("解密完成");
  })
);

$("#sm4-plain").addEventListener("input", (e) => {
  const n = utf8Bytes(e.target.value).length;
  $("#sm4-plain-len").textContent = n ? `${n} 字节 · 补齐到 ${Math.ceil((n || 1) / 16) * 16} 字节` : "";
});

/* ============================================================ SM3 + HMAC */

function hmacSm3(msg, key) {
  const BS = 64;
  const kb = utf8Bytes(key);
  const k = kb.length > BS ? hexToBytes(sm3hash(kb)) : kb;
  const kPad = new Uint8Array(BS);
  kPad.set(k);
  const ipad = new Uint8Array(BS), opad = new Uint8Array(BS);
  for (let i = 0; i < BS; i++) {
    ipad[i] = kPad[i] ^ 0x36;
    opad[i] = kPad[i] ^ 0x5c;
  }
  const mb = utf8Bytes(msg);
  const inner = new Uint8Array(BS + mb.length);
  inner.set(ipad);
  inner.set(mb, BS);
  const ih = hexToBytes(sm3hash(inner));
  const outer = new Uint8Array(BS + 32);
  outer.set(opad);
  outer.set(ih, BS);
  return sm3hash(outer);
}

$("#doSm3").addEventListener("click", () =>
  guard($("#doSm3"), () => {
    const msg = $("#sm3-in").value;
    if (!msg) throw new Error("请输入要计算摘要的文本");
    const key = $("#sm3-hmac-key").value;
    const out = key ? hmacSm3(msg, key) : sm3hash(msg);
    setOut("sm3-out", out);
    toast(key ? "HMAC-SM3 计算完成" : "SM3 摘要计算完成");
  })
);

/* ============================================================ 数字信封 */

$("#env-seal").addEventListener("click", () =>
  guard($("#env-seal"), () => {
    const plain = $("#env-plain").value;
    if (!plain) throw new Error("请输入要封装的明文");
    const pub = normPub($("#env-pub").value.trim() || $("#sm2-pub").value, "接收方公钥");

    const key = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const keyHex = bytesToHex(key);

    const data = sm4lib.encrypt(plain, key, { mode: "cbc", iv });
    const sealedKey = sm2lib.doEncrypt(keyHex, pub, 1);

    const env = {
      v: 1,
      alg: "SM2+SM4/CBC/PKCS7",
      c1: "C1C3C2",
      iv: bytesToHex(iv),
      key: sealedKey,
      data,
      at: new Date().toISOString().slice(0, 19).replace("T", " "),
    };
    setOut("env-out", JSON.stringify(env, null, 2));
    toast(`封装完成 · ${utf8Bytes(plain).length} 字节明文，信封 ${JSON.stringify(env).length} 字节`);
  })
);

$("#env-open").addEventListener("click", () =>
  guard($("#env-open"), () => {
    const raw = $("#env-in").value.trim();
    if (!raw) throw new Error("请粘贴信封内容");
    let env;
    try {
      env = JSON.parse(raw);
    } catch (_) {
      throw new Error("信封不是合法 JSON，请完整复制花括号内的内容");
    }
    if (!env.key || !env.data || !env.iv) throw new Error("信封缺少 key / iv / data 字段");

    const priv = normPriv($("#env-priv").value.trim() || $("#sm2-priv").value, "接收方私钥");
    const keyHex = sm2lib.doDecrypt(cleanHex(env.key), priv, 1, { output: "string" });
    if (!keyHex || keyHex.length !== 32) throw new Error("解封失败：私钥与信封不匹配");

    const plain = sm4lib.decrypt(hexToBytes(cleanHex(env.data)), hexToBytes(keyHex), {
      mode: "cbc",
      iv: hexToBytes(cleanHex(env.iv)),
      output: "string",
    });
    setOut("env-pt", plain);
    toast(`解封完成 · ${utf8Bytes(plain).length} 字节`);
  })
);

/* ============================================================ 清空 */

$("#clearAll").addEventListener("click", () => {
  $$("textarea").forEach((t) => (t.value = ""));
  $$('input[type="text"]').forEach((i) => (i.value = ""));
  const box = $("#verify-result");
  box.className = "result";
  box.textContent = "等待验证";
  toast("已清空全部内容");
});

/* ============================================================ 启动 */

// 首次打开给一对密钥，省得用户空手点
try {
  const kp = sm2lib.generateKeyPairHex();
  $("#sm2-pub").value = kp.publicKey;
  $("#sm2-priv").value = kp.privateKey;
  const k = crypto.getRandomValues(new Uint8Array(16));
  $("#sm4-key").value = bytesToHex(k);
  $("#sm4-iv").value = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
} catch (e) {
  console.error(e);
}
