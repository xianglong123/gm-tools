/* 通用加解密扩展：AES / DES·3DES / RSA / 摘要 / 编码 / JWT
   全部计算在浏览器本地完成，页面没有任何后端请求。依赖 app.js 里的公共工具函数。 */

const CJ = window.CryptoJS;

/* ============================================================ 通用小工具 */

function runAsync(btn, fn) {
  const old = btn.textContent;
  btn.disabled = true;
  Promise.resolve()
    .then(fn)
    .catch((e) => toast(e && e.message ? e.message : String(e), true))
    .finally(() => {
      btn.disabled = false;
      btn.textContent = old;
    });
}

function bytesToB64(a) {
  let bin = "";
  for (let i = 0; i < a.length; i++) bin += String.fromCharCode(a[i]);
  return btoa(bin);
}

function b64ToBytes(b64) {
  const s = String(b64).replace(/[^A-Za-z0-9+/=]/g, "");
  const bin = atob(s);
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let p = 0;
  for (const a of arrs) {
    out.set(a, p);
    p += a.length;
  }
  return out;
}

function bytesToPem(bytes, label) {
  const b64 = bytesToB64(bytes);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/* ============================================================ 摘要 / HMAC */

const HASH_LABEL = { sm3: "SM3", sha256: "SHA-256", sha512: "SHA-512", sha384: "SHA-384", sha1: "SHA-1", md5: "MD5" };
const HASH_FN = { sha256: () => CJ.SHA256, sha512: () => CJ.SHA512, sha384: () => CJ.SHA384, sha1: () => CJ.SHA1, md5: () => CJ.MD5 };
const HMAC_FN = { sha256: () => CJ.HmacSHA256, sha512: () => CJ.HmacSHA512, sha384: () => CJ.HmacSHA384, sha1: () => CJ.HmacSHA1, md5: () => CJ.HmacMD5 };

function hashLabel(alg) {
  return HASH_LABEL[alg] || alg.toUpperCase();
}

function hashHex(alg, msg) {
  if (alg === "sm3") return sm3hash(msg);
  const get = HASH_FN[alg];
  if (!get) throw new Error("不支持的摘要算法：" + alg);
  if (!CJ) throw new Error("crypto-js 未加载，无法计算 " + hashLabel(alg));
  return get()(msg).toString(CJ.enc.Hex);
}

function hmacHex(alg, msg, key) {
  if (alg === "sm3") return hmacSm3(msg, key);
  const get = HMAC_FN[alg];
  if (!get) throw new Error("不支持的 HMAC 算法：" + alg);
  if (!CJ) throw new Error("crypto-js 未加载，无法计算 HMAC-" + hashLabel(alg));
  return get()(msg, key).toString(CJ.enc.Hex);
}

/* ============================================================ AES */

const AES_MODES = () => ({ cbc: CJ.mode.CBC, ecb: CJ.mode.ECB, ctr: CJ.mode.CTR, cfb: CJ.mode.CFB, ofb: CJ.mode.OFB });
const STREAM_MODES = ["ctr", "cfb", "ofb", "gcm"];

function aesCtx() {
  const keyHex = cleanHex($("#aes-key").value);
  if (!keyHex) throw new Error("请填写 AES 密钥");
  if (!/^[0-9a-f]+$/.test(keyHex)) throw new Error("AES 密钥含有非十六进制字符");
  if (![32, 48, 64].includes(keyHex.length)) throw new Error(`AES 密钥应为 32 / 48 / 64 位 hex（对应 128 / 192 / 256 位），当前 ${keyHex.length} 位`);

  const mode = $("#aes-mode").value;
  let ivHex = "";
  if (mode === "gcm") {
    ivHex = cleanHex($("#aes-iv").value);
    if (ivHex.length !== 24) throw new Error(`GCM 的 IV 应为 12 字节（24 位 hex），当前 ${ivHex.length} 位`);
  } else if (mode !== "ecb") {
    ivHex = cleanHex($("#aes-iv").value);
    if (ivHex.length !== 32) throw new Error(`该模式的 IV 应为 16 字节（32 位 hex），当前 ${ivHex.length} 位`);
  }

  const pad = STREAM_MODES.includes(mode) ? "none" : radioVal("aespad");
  return { keyHex, ivHex, mode, pad, out: radioVal("aesout") };
}

function syncAesIv() {
  const mode = $("#aes-mode").value;
  $("#aes-iv-wrap").classList.toggle("hidden", mode === "ecb");
  const hint = {
    gcm: "GCM 模式：IV 用 12 字节，密文尾部自带 16 字节认证标签，解密失败会明确提示。",
    ctr: "CTR 模式：流式，不需要填充，IV 可复用但明文重复时不要重用同一 IV。",
    cfb: "CFB 模式：流式，不需要填充。",
    ofb: "OFB 模式：流式，不需要填充。",
    ecb: "ECB 模式：相同明文块得到相同密文块，生产环境不推荐，仅作兼容。",
    cbc: "CBC 模式：最常用，需要 16 字节 IV，PKCS#7 填充。",
  }[mode];
  $("#aes-hint").textContent = hint || "";
  $$('input[name="aespad"]').forEach((r) => (r.disabled = STREAM_MODES.includes(mode)));
  $$('input[name="aespad"]').forEach((r) => (r.parentElement.style.opacity = STREAM_MODES.includes(mode) ? 0.45 : 1));
}

$("#aes-mode").addEventListener("change", syncAesIv);

$("#genAesKey").addEventListener("click", () =>
  guard($("#genAesKey"), () => {
    $("#aes-key").value = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    $("#aes-iv").value = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    toast("已生成 AES-256 密钥与 16 字节 IV（选 GCM 请按「生成」再取 IV 前 12 字节，或手动改）");
  })
);

$("#aes-plain").addEventListener("input", (e) => {
  const n = utf8Bytes(e.target.value).length;
  $("#aes-plain-len").textContent = n
    ? `${n} 字节${STREAM_MODES.includes($("#aes-mode").value) ? "" : ` · 补齐到 ${Math.ceil(n / 16) * 16} 字节`}`
    : "";
});

$("#aes-encrypt").addEventListener("click", (e) =>
  runAsync(e.currentTarget, async () => {
    const c = aesCtx();
    const raw = $("#aes-plain").value;
    if (!raw) throw new Error("请输入要加密的内容");

    let ctHex = "";
    if (c.mode === "gcm") {
      const key = await crypto.subtle.importKey("raw", hexToBytes(c.keyHex), "AES-GCM", false, ["encrypt"]);
      const buf = await crypto.subtle.encrypt({ name: "AES-GCM", iv: hexToBytes(c.ivHex) }, key, utf8Bytes(raw));
      ctHex = bytesToHex(new Uint8Array(buf));
    } else {
      let input;
      if (c.pad === "none") {
        const h = cleanHex(raw);
        if (!h || !/^[0-9a-f]+$/.test(h)) throw new Error("无填充模式请填 hex 明文");
        if (h.length % 32 !== 0) throw new Error("无填充模式的明文必须是 16 字节（32 位 hex）的整数倍");
        input = CJ.enc.Hex.parse(h);
      } else {
        input = CJ.enc.Utf8.parse(raw);
      }
      const opt = { mode: AES_MODES()[c.mode], padding: c.pad === "none" ? CJ.pad.NoPadding : CJ.pad.Pkcs7 };
      if (c.ivHex) opt.iv = CJ.enc.Hex.parse(c.ivHex);
      const enc = CJ.AES.encrypt(input, CJ.enc.Hex.parse(c.keyHex), opt);
      ctHex = enc.ciphertext.toString(CJ.enc.Hex);
    }

    setOut("aes-ct", c.out === "base64" ? hexToBase64(ctHex) : ctHex);
    toast(`AES-${c.keyHex.length * 4}-${c.mode.toUpperCase()} 加密完成 · ${ctHex.length / 2} 字节`);
  })
);

$("#aes-decrypt").addEventListener("click", (e) =>
  runAsync(e.currentTarget, async () => {
    setOut("aes-pt", "");
    const c = aesCtx();
    const ctHex = decodeCipher($("#aes-ct-in").value);

    if (c.mode === "gcm") {
      let plain;
      try {
        const key = await crypto.subtle.importKey("raw", hexToBytes(c.keyHex), "AES-GCM", false, ["decrypt"]);
        plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(c.ivHex) }, key, hexToBytes(ctHex));
      } catch (err) {
        throw new Error("GCM 解密失败：密钥 / IV / 密文任一不匹配，或密文被篡改（认证标签校验不通过）");
      }
      setOut("aes-pt", new TextDecoder().decode(plain));
      toast("解密完成（GCM 认证通过）");
      return;
    }

    const opt = { mode: AES_MODES()[c.mode], padding: c.pad === "none" ? CJ.pad.NoPadding : CJ.pad.Pkcs7 };
    if (c.ivHex) opt.iv = CJ.enc.Hex.parse(c.ivHex);
    const wa = CJ.AES.decrypt({ ciphertext: CJ.enc.Hex.parse(ctHex) }, CJ.enc.Hex.parse(c.keyHex), opt);

    if (c.pad === "none") {
      const hexOut = wa.toString(CJ.enc.Hex);
      if (!hexOut) throw new Error("解密失败：密钥或 IV 不匹配");
      setOut("aes-pt", hexOut);
      toast("解密完成（无填充，输出 hex）");
      return;
    }

    let txt = "";
    try {
      txt = wa.toString(CJ.enc.Utf8);
    } catch (_) {
      throw new Error("解密失败：密钥或 IV 不匹配（PKCS#7 填充校验不通过）");
    }
    if (!txt) throw new Error("解密失败：密钥或 IV 不匹配");
    setOut("aes-pt", txt);
    toast("解密完成");
  })
);

/* ============================================================ DES / 3DES */

function desCtx() {
  const alg = $("#des-alg").value;
  const keyHex = cleanHex($("#des-key").value);
  if (!keyHex) throw new Error("请填写密钥");
  if (!/^[0-9a-f]+$/.test(keyHex)) throw new Error("密钥含有非十六进制字符");
  const need = alg === "des" ? [16] : [32, 48];
  if (!need.includes(keyHex.length)) {
    throw new Error(alg === "des" ? `DES 密钥应为 16 位 hex（8 字节），当前 ${keyHex.length} 位` : `3DES 密钥应为 32 或 48 位 hex（16 或 24 字节），当前 ${keyHex.length} 位`);
  }
  const mode = radioVal("desmode");
  const ivHex = mode === "cbc" ? cleanHex($("#des-iv").value) : "";
  if (mode === "cbc" && ivHex.length !== 16) throw new Error(`CBC 的 IV 应为 8 字节（16 位 hex），当前 ${ivHex.length} 位`);
  return { alg, keyHex, ivHex, mode, out: radioVal("desout") };
}

function syncDesIv() {
  $("#des-iv-wrap").classList.toggle("hidden", radioVal("desmode") === "ecb");
}

$$('input[name="desmode"]').forEach((r) => r.addEventListener("change", syncDesIv));

$("#des-alg").addEventListener("change", () => {
  const isDes = $("#des-alg").value === "des";
  $("#des-key-hint").textContent = isDes ? "（DES：16 位 hex = 8 字节）" : "（3DES：48 位 hex = 24 字节）";
});

$("#genDesKey").addEventListener("click", () =>
  guard($("#genDesKey"), () => {
    const isDes = $("#des-alg").value === "des";
    $("#des-key").value = bytesToHex(crypto.getRandomValues(new Uint8Array(isDes ? 8 : 24)));
    $("#des-iv").value = bytesToHex(crypto.getRandomValues(new Uint8Array(8)));
    toast(isDes ? "已生成 DES 密钥" : "已生成 3DES 24 字节密钥");
  })
);

$("#des-encrypt").addEventListener("click", () =>
  guard($("#des-encrypt"), () => {
    const c = desCtx();
    const raw = $("#des-plain").value;
    if (!raw) throw new Error("请输入要加密的内容");
    const lib = c.alg === "des" ? CJ.DES : CJ.TripleDES;
    const opt = { mode: c.mode === "cbc" ? CJ.mode.CBC : CJ.mode.ECB, padding: CJ.pad.Pkcs7 };
    if (c.ivHex) opt.iv = CJ.enc.Hex.parse(c.ivHex);
    const enc = lib.encrypt(CJ.enc.Utf8.parse(raw), CJ.enc.Hex.parse(c.keyHex), opt);
    const ctHex = enc.ciphertext.toString(CJ.enc.Hex);
    setOut("des-ct", c.out === "base64" ? hexToBase64(ctHex) : ctHex);
    toast(`${c.alg === "des" ? "DES" : "3DES"}-${c.mode.toUpperCase()} 加密完成 · ${ctHex.length / 2} 字节`);
  })
);

$("#des-decrypt").addEventListener("click", () =>
  guard($("#des-decrypt"), () => {
    setOut("des-pt", "");
    const c = desCtx();
    const ctHex = decodeCipher($("#des-ct-in").value);
    const lib = c.alg === "des" ? CJ.DES : CJ.TripleDES;
    const opt = { mode: c.mode === "cbc" ? CJ.mode.CBC : CJ.mode.ECB, padding: CJ.pad.Pkcs7 };
    if (c.ivHex) opt.iv = CJ.enc.Hex.parse(c.ivHex);
    const wa = lib.decrypt({ ciphertext: CJ.enc.Hex.parse(ctHex) }, CJ.enc.Hex.parse(c.keyHex), opt);
    let txt = "";
    try {
      txt = wa.toString(CJ.enc.Utf8);
    } catch (_) {
      throw new Error("解密失败：密钥或 IV 不匹配（填充校验不通过）");
    }
    if (!txt) throw new Error("解密失败：密钥或 IV 不匹配");
    setOut("des-pt", txt);
    toast("解密完成");
  })
);

/* ============================================================ DER / PEM 工具 */

function derLen(n) {
  if (n < 0x80) return [n];
  const parts = [];
  let t = n;
  while (t > 0) {
    parts.unshift(t & 0xff);
    t = Math.floor(t / 256);
  }
  return [0x80 | parts.length, ...parts];
}

function derWrap(tag, content) {
  return concatBytes(Uint8Array.from([tag, ...derLen(content.length)]), content);
}

function derNode(buf, pos) {
  let len = buf[pos + 1];
  let off = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + i];
    off += n;
  }
  return { tag: buf[pos], start: off, len, end: off + len };
}

function derChildren(buf) {
  const top = derNode(buf, 0);
  const out = [];
  let pos = top.start;
  while (pos < top.end) {
    const n = derNode(buf, pos);
    out.push(n);
    pos = n.end;
    if (n.end <= n.start) break;
  }
  return out;
}

const RSA_ALGID = Uint8Array.from([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);

/* 把任意 PKCS#1 / PKCS#8 / SPKI 的密钥文本统一成 { shape, der, pkcs1 } */
function parseKey(text) {
  const raw = String(text || "").trim();
  if (!raw) throw new Error("密钥为空");

  let body = raw.replace(/\s+/g, "");
  const m = raw.match(/-----BEGIN ([^-]+)-----/);
  if (m) {
    body = raw.split(/-----BEGIN [^-]+-----/)[1].split(/-----END/)[0].replace(/\s+/g, "");
  }

  let der;
  if (/^[0-9a-fA-F]+$/.test(body) && body.length % 2 === 0) der = hexToBytes(body.toLowerCase());
  else der = b64ToBytes(body);
  if (!der.length) throw new Error("密钥解析为空，检查是否完整粘贴");

  const kids = derChildren(der);
  const tags = kids.map((k) => k.tag);
  let shape = null;

  if (tags.length >= 3 && tags[0] === 0x02 && tags[1] === 0x30 && tags[2] === 0x04) shape = "priv-pkcs8";
  else if (tags.length >= 2 && tags[0] === 0x30 && tags[1] === 0x03) shape = "pub-spki";
  else if (tags.length >= 6 && tags[0] === 0x02 && tags[1] === 0x02) shape = "priv-pkcs1";
  else if (tags.length === 2 && tags[0] === 0x02 && tags[1] === 0x02) shape = "pub-pkcs1";

  if (!shape) {
    if (m) {
      const label = m[1];
      if (/RSA PRIVATE KEY/.test(label)) shape = "priv-pkcs1";
      else if (/RSA PUBLIC KEY/.test(label)) shape = "pub-pkcs1";
      else if (/PRIVATE KEY/.test(label)) shape = "priv-pkcs8";
      else if (/PUBLIC KEY/.test(label)) shape = "pub-spki";
    }
  }
  if (!shape) throw new Error("无法识别密钥结构，请确认是 RSA 的 PEM（PKCS#1 / PKCS#8 / SPKI）");

  let pkcs1 = der;
  if (shape === "priv-pkcs8") {
    const oct = derChildren(der)[2];
    pkcs1 = der.subarray(oct.start, oct.end);
  } else if (shape === "pub-spki") {
    const bit = derChildren(der)[1];
    pkcs1 = der.subarray(bit.start + 1, bit.end);
  }

  return { shape, der, pkcs1, isPriv: shape.startsWith("priv") };
}

function pkcs1ToSpki(der) {
  return derWrap(0x30, concatBytes(RSA_ALGID, derWrap(0x03, concatBytes(Uint8Array.of(0), der))));
}

function pkcs1ToPkcs8(der) {
  return derWrap(0x30, concatBytes(Uint8Array.of(0x02, 0x01, 0x00), RSA_ALGID, derWrap(0x04, der)));
}

function spkiOf(parsed) {
  if (!parsed.isPriv) return parsed.shape === "pub-spki" ? parsed.der : pkcs1ToSpki(parsed.pkcs1);
  throw new Error("这里需要公钥，你填入的是私钥");
}

function pkcs8Of(parsed) {
  if (!parsed.isPriv) throw new Error("这里需要私钥，你填入的是公钥");
  return parsed.shape === "priv-pkcs8" ? parsed.der : pkcs1ToPkcs8(parsed.pkcs1);
}

/* 从 PKCS#1 里取 n / e / d；size 按模数的真实位宽算（DER 的 INTEGER 可能多补一个 0x00，不能直接用节点长度） */
function rsaNumbers(parsed) {
  const body = parsed.pkcs1;
  const kids = derChildren(body);
  const intOf = (node) => BigInt("0x" + (bytesToHex(body.subarray(node.start, node.end)) || "0"));
  const n = intOf(parsed.isPriv ? kids[1] : kids[0]);
  const size = Math.ceil(n.toString(2).length / 8);
  if (parsed.isPriv) return { n, e: intOf(kids[2]), d: intOf(kids[3]), size };
  return { n, e: intOf(kids[1]), size };
}

function bigToBytes(x, size) {
  let h = x.toString(16);
  if (h.length % 2) h = "0" + h;
  let a = hexToBytes(h);
  if (size) {
    if (a.length > size) a = a.subarray(a.length - size);
    const out = new Uint8Array(size);
    out.set(a, size - a.length);
    return out;
  }
  return a;
}

function modPow(base, exp, mod) {
  let r = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return r;
}

/* PKCS#1 v1.5 加密（WebCrypto 不支持这个方案，自己算） */
function rsaEncryptPkcs1(pubText, msgBytes) {
  const parsed = parseKey(pubText);
  if (parsed.isPriv) throw new Error("加密需要公钥，你填入的是私钥");
  const { n, e, size } = rsaNumbers(parsed);
  if (msgBytes.length > size - 11) throw new Error(`明文过长：RSA-${size * 8} 最多 ${size - 11} 字节，当前 ${msgBytes.length} 字节`);

  const ps = new Uint8Array(size - msgBytes.length - 3);
  const rnd = crypto.getRandomValues(ps);
  for (let i = 0; i < ps.length; i++) while (rnd[i] === 0) rnd[i] = crypto.getRandomValues(new Uint8Array(1))[0];

  const em = concatBytes(Uint8Array.of(0x00, 0x02), rnd, Uint8Array.of(0x00), msgBytes);
  return bigToBytes(modPow(BigInt("0x" + bytesToHex(em)), e, n), size);
}

function rsaDecryptPkcs1(privText, ctBytes) {
  const parsed = parseKey(privText);
  if (!parsed.isPriv) throw new Error("解密需要私钥，你填入的是公钥");
  const { n, d, size } = rsaNumbers(parsed);
  const em = bigToBytes(modPow(BigInt("0x" + bytesToHex(ctBytes)), d, n), size);
  if (em[0] !== 0x00 || em[1] !== 0x02) throw new Error("解密失败：私钥与密文不匹配，或密文被篡改");
  let i = 2;
  while (i < em.length && em[i] !== 0x00) i++;
  if (i >= em.length - 1) throw new Error("解密失败：填充结构损坏");
  return em.subarray(i + 1);
}

async function rsaOaepEncrypt(pubText, msgBytes) {
  const key = await crypto.subtle.importKey("spki", spkiOf(parseKey(pubText)), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  return new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, msgBytes));
}

async function rsaOaepDecrypt(privText, ctBytes) {
  const key = await crypto.subtle.importKey("pkcs8", pkcs8Of(parseKey(privText)), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, ctBytes));
  } catch (_) {
    throw new Error("解密失败：私钥与密文不匹配，或密文被篡改");
  }
}

/* ============================================================ RSA 面板 */

$("#rsa-plain").addEventListener("input", (e) => {
  const n = utf8Bytes(e.target.value).length;
  $("#rsa-plain-hint").textContent = n ? `${n} 字节${n > 200 ? " · 超过 200 字节必须改用 AES + RSA 混合加密" : ""}` : "";
});

$("#rsa-encrypt").addEventListener("click", (e) =>
  runAsync(e.currentTarget, async () => {
    const msg = $("#rsa-plain").value;
    if (!msg) throw new Error("请输入要加密的内容");
    const pub = $("#rsa-pub").value;
    if (!pub.trim()) throw new Error("请填写 RSA 公钥");
    const scheme = $("#rsa-enc-scheme").value;
    const bytes = scheme === "oaep" ? await rsaOaepEncrypt(pub, utf8Bytes(msg)) : rsaEncryptPkcs1(pub, utf8Bytes(msg));
    setOut("rsa-ct", bytesToB64(bytes));
    toast(`RSA 加密完成 · ${scheme === "oaep" ? "OAEP-SHA256" : "PKCS#1 v1.5"} · ${bytes.length} 字节`);
  })
);

$("#rsa-decrypt").addEventListener("click", (e) =>
  runAsync(e.currentTarget, async () => {
    setOut("rsa-pt", "");
    const ctRaw = $("#rsa-ct-in").value.trim();
    if (!ctRaw) throw new Error("请粘贴密文");
    const priv = $("#rsa-priv").value;
    if (!priv.trim()) throw new Error("请填写 RSA 私钥");
    const ct = /^[0-9a-fA-F\s]+$/.test(ctRaw) && ctRaw.replace(/\s/g, "").length % 2 === 0 ? hexToBytes(cleanHex(ctRaw)) : b64ToBytes(ctRaw);
    if (!ct.length) throw new Error("密文解析为空");
    const scheme = $("#rsa-enc-scheme").value;
    const out = scheme === "oaep" ? await rsaOaepDecrypt(priv, ct) : rsaDecryptPkcs1(priv, ct);
    setOut("rsa-pt", new TextDecoder().decode(out));
    toast("解密完成");
  })
);

$("#rsa-sign").addEventListener("click", (e) =>
  runAsync(e.currentTarget, async () => {
    const msg = $("#rsa-sign-msg").value;
    if (!msg) throw new Error("请输入要签名的消息");
    const priv = $("#rsa-priv").value;
    if (!priv.trim()) throw new Error("请先填写 RSA 私钥");
    const isPss = $("#rsa-sig-scheme").value === "pss";
    const key = await crypto.subtle.importKey("pkcs8", pkcs8Of(parseKey(priv)), isPss ? { name: "RSA-PSS", hash: "SHA-256" } : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
    const alg = isPss ? { name: "RSA-PSS", saltLength: 32 } : { name: "RSASSA-PKCS1-v1_5" };
    const sig = new Uint8Array(await crypto.subtle.sign(alg, key, utf8Bytes(msg)));
    setOut("rsa-sign-out", bytesToB64(sig));
    toast(`签名完成 · ${isPss ? "PSS" : "PKCS#1 v1.5"} · SHA-256`);
  })
);

$("#rsa-verify").addEventListener("click", (e) =>
  runAsync(e.currentTarget, async () => {
    const msg = $("#rsa-verify-msg").value;
    const sigRaw = $("#rsa-verify-sig").value.trim();
    if (!msg) throw new Error("请输入待验签的消息");
    if (!sigRaw) throw new Error("请粘贴签名");
    const pub = $("#rsa-pub").value;
    if (!pub.trim()) throw new Error("请先填写 RSA 公钥");
    const sig = /^[0-9a-fA-F\s]+$/.test(sigRaw) && sigRaw.replace(/\s/g, "").length % 2 === 0 ? hexToBytes(cleanHex(sigRaw)) : b64ToBytes(sigRaw);
    const isPss = $("#rsa-sig-scheme").value === "pss";
    const key = await crypto.subtle.importKey("spki", spkiOf(parseKey(pub)), isPss ? { name: "RSA-PSS", hash: "SHA-256" } : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const alg = isPss ? { name: "RSA-PSS", saltLength: 32 } : { name: "RSASSA-PKCS1-v1_5" };
    const ok = await crypto.subtle.verify(alg, key, sig, utf8Bytes(msg));
    const box = $("#rsa-verify-result");
    box.className = "result " + (ok ? "ok" : "bad");
    box.textContent = ok ? "✓ 验签通过：签名、消息、公钥三者匹配" : "✗ 验签失败：签名 / 消息 / 公钥不一致，或签名方案选错";
  })
);

$("#rsaGenKey").addEventListener("click", (e) =>
  runAsync(e.currentTarget, async () => {
    const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256" }, true, ["sign", "verify"]);
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
    $("#rsa-pub").value = bytesToPem(spki, "PUBLIC KEY");
    $("#rsa-priv").value = bytesToPem(pkcs8, "PRIVATE KEY");
    toast("已生成 RSA-2048 密钥对（PKCS#8 私钥 / SPKI 公钥，两个方案通用）");
  })
);

/* ============================================================ 密钥对生成 */

/* SM2 的 AlgorithmIdentifier：OpenSSL / BouncyCastle 都是 id-ecPublicKey + sm2 双 OID */
const EC_PUBLIC_KEY_OID = Uint8Array.of(0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01);
const SM2_CURVE_OID = Uint8Array.of(0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d);

function sm2AlgId() {
  return derWrap(0x30, concatBytes(EC_PUBLIC_KEY_OID, SM2_CURVE_OID));
}

/* 由 hex 私钥 / 公钥构造标准 PKCS#8 与 SPKI，结构与 openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 一致 */
function sm2DerKeyPair(privHex, pubHex) {
  const priv = hexToBytes(privHex);
  if (priv.length !== 32) throw new Error(`SM2 私钥应为 32 字节，当前 ${priv.length} 字节`);
  const pub = hexToBytes(normPub(pubHex, "SM2 公钥"));

  const ecPriv = derWrap(0x30, concatBytes(
    Uint8Array.of(0x02, 0x01, 0x01),
    derWrap(0x04, priv),
    derWrap(0xa1, derWrap(0x03, concatBytes(Uint8Array.of(0x00), pub)))
  ));

  const pkcs8 = derWrap(0x30, concatBytes(Uint8Array.of(0x02, 0x01, 0x00), sm2AlgId(), derWrap(0x04, ecPriv)));
  const spki = derWrap(0x30, concatBytes(sm2AlgId(), derWrap(0x03, concatBytes(Uint8Array.of(0x00), pub))));
  return { pkcs8, spki };
}

async function sha256Fp(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return "SHA256:" + bytesToB64(d).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function saveTextFile(name, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function syncKeygenFmt() {
  const isRsa = $("#keygen-alg").value.startsWith("rsa");
  ["keygen-priv-fmt", "keygen-pub-fmt"].forEach((id) => {
    const sel = $("#" + id);
    [...sel.options].forEach((o) => {
      if (o.value === "pkcs1") o.disabled = !isRsa;
    });
    if (!isRsa && sel.value === "pkcs1") sel.value = "pkcs8";
  });
}

$("#keygen-alg").addEventListener("change", syncKeygenFmt);

$("#keygen-gen").addEventListener("click", (e) =>
  runAsync(e.currentTarget, async () => {
    const alg = $("#keygen-alg").value;
    const privFmt = $("#keygen-priv-fmt").value;
    const pubFmt = $("#keygen-pub-fmt").value;
    const t0 = performance.now();

    let privDer = null;
    let pubDer = null;
    let sm2Hex = null;
    let label = "";

    if (alg === "sm2") {
      const kp = sm2lib.generateKeyPairHex();
      const der = sm2DerKeyPair(kp.privateKey, kp.publicKey);
      privDer = der.pkcs8;
      pubDer = der.spki;
      sm2Hex = { priv: kp.privateKey, pub: kp.publicKey };
      label = "SM2";
    } else if (alg === "ed25519") {
      let kp;
      try {
        kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
      } catch (_) {
        throw new Error("当前浏览器不支持 Ed25519（Chrome 113+ / Safari 17+ 才有），请改用 RSA 或 SM2");
      }
      privDer = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
      pubDer = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
      label = "Ed25519";
    } else {
      const bits = { rsa2048: 2048, rsa3072: 3072, rsa4096: 4096 }[alg];
      if (bits === 4096) $("#keygen-meta").textContent = "正在生成 RSA-4096，可能要十几秒…";
      const kp = await crypto.subtle.generateKey(
        { name: "RSASSA-PKCS1-v1_5", modulusLength: bits, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256" },
        true,
        ["sign", "verify"]
      );
      privDer = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
      pubDer = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
      label = "RSA-" + bits;
    }

    const isRsa = alg.startsWith("rsa");
    let privOut;
    let pubOut;

    if (privFmt === "hex") {
      privOut = sm2Hex ? sm2Hex.priv : bytesToHex(privDer);
    } else if (privFmt === "pkcs1") {
      if (!isRsa) throw new Error("PKCS#1 是 RSA 专有格式，SM2 / Ed25519 请选 PKCS#8");
      privOut = bytesToPem(parseKey(bytesToPem(privDer, "PRIVATE KEY")).pkcs1, "RSA PRIVATE KEY");
    } else {
      privOut = bytesToPem(privDer, "PRIVATE KEY");
    }

    if (pubFmt === "hex") {
      pubOut = sm2Hex ? sm2Hex.pub : bytesToHex(pubDer);
    } else if (pubFmt === "pkcs1") {
      if (!isRsa) throw new Error("PKCS#1 是 RSA 专有格式，SM2 / Ed25519 请选 SPKI");
      pubOut = bytesToPem(parseKey(bytesToPem(pubDer, "PUBLIC KEY")).pkcs1, "RSA PUBLIC KEY");
    } else {
      pubOut = bytesToPem(pubDer, "PUBLIC KEY");
    }

    setOut("keygen-priv", privOut);
    setOut("keygen-pub", pubOut);

    const fp = await sha256Fp(pubDer);
    $("#keygen-fp").textContent = `公钥 SHA-256 指纹：${fp}`;
    $("#keygen-meta").textContent = `${label} · ${(privDer.length)} 字节私钥 DER · ${(performance.now() - t0).toFixed(0)} ms`;
    toast(`${label} 密钥对已生成`);
  })
);

$("#keygen-dl-priv").addEventListener("click", () => {
  const v = $("#keygen-priv").value;
  if (!v) return toast("先生成密钥再下载", true);
  saveTextFile(v.includes("-----BEGIN") ? "private.pem" : "private-key.txt", v);
});

$("#keygen-dl-pub").addEventListener("click", () => {
  const v = $("#keygen-pub").value;
  if (!v) return toast("先生成密钥再下载", true);
  saveTextFile(v.includes("-----BEGIN") ? "public.pem" : "public-key.txt", v);
});

/* ============================================================ 编码转换 */

const CODECS = {
  b64e: (s) => bytesToB64(utf8Bytes(s)),
  b64d: (s) => new TextDecoder().decode(b64ToBytes(s)),
  b64ue: (s) => bytesToB64(utf8Bytes(s)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
  b64ud: (s) => {
    let t = s.trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
    while (t.length % 4) t += "=";
    return new TextDecoder().decode(b64ToBytes(t));
  },
  hexe: (s) => bytesToHex(utf8Bytes(s)),
  hexd: (s) => {
    const h = cleanHex(s);
    if (!h || !/^[0-9a-f]+$/.test(h) || h.length % 2) throw new Error("不是合法的 hex（需偶数位十六进制）");
    return new TextDecoder().decode(hexToBytes(h));
  },
  urle: (s) => encodeURIComponent(s),
  urld: (s) => {
    try {
      return decodeURIComponent(s.replace(/\+/g, " "));
    } catch (_) {
      throw new Error("不是合法的 URL 编码（存在 %XX 转义错误）");
    }
  },
  unie: (s) =>
    [...s]
      .map((ch) => {
        const cp = ch.codePointAt(0);
        if (cp <= 0x7f) return ch;
        if (cp > 0xffff) {
          const v = cp - 0x10000;
          const hi = 0xd800 + (v >> 10);
          const lo = 0xdc00 + (v & 0x3ff);
          return "\\u" + hi.toString(16).padStart(4, "0") + "\\u" + lo.toString(16).padStart(4, "0");
        }
        return "\\u" + cp.toString(16).padStart(4, "0");
      })
      .join(""),
  unid: (s) => s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))),
};

const CODEC_HINT = {
  b64e: "标准 Base64，带 = 补位",
  b64d: "自动忽略换行与空格",
  b64ue: "Base64URL：+ / 换成 - _，去掉 = 补位，JWT 用这个",
  b64ud: "会自动补回 = 与 + /",
  hexe: "UTF-8 字节转小写 hex",
  hexd: "大小写均可，可带空格 / 冒号分隔",
  urle: "encodeURIComponent，适合 query 参数值",
  urld: "会把 + 当作空格处理",
  unie: "中文等非 ASCII 字符转 \\uXXXX，ASCII 原样保留",
  unid: "把 \\uXXXX 还原成字符",
};

$("#codec-mode").addEventListener("change", () => {
  $("#codec-hint").textContent = CODEC_HINT[$("#codec-mode").value] || "";
});

$("#codec-run").addEventListener("click", () =>
  guard($("#codec-run"), () => {
    const raw = $("#codec-in").value;
    if (!raw) throw new Error("请输入要转换的内容");
    const fn = CODECS[$("#codec-mode").value];
    const out = fn(raw);
    setOut("codec-out", out);
    toast(`转换完成 · ${out.length} 字符`);
  })
);

$("#codecSwap").addEventListener("click", () => {
  const out = $("#codec-out").value;
  if (!out) return toast("没有结果可回填", true);
  $("#codec-in").value = out;
  setOut("codec-out", "");
  toast("已把结果放回输入框");
});

/* ============================================================ JWT */

function b64uToBytes(s) {
  let t = String(s).replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  while (t.length % 4) t += "=";
  return b64ToBytes(t);
}

function b64uToText(s) {
  return new TextDecoder().decode(b64uToBytes(s));
}

function fmtTime(sec) {
  if (typeof sec !== "number") return "";
  const d = new Date(sec * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function jwtParse() {
  const raw = $("#jwt-in").value.trim();
  if (!raw) throw new Error("请粘贴一个 JWT");
  const parts = raw.split(".");
  if (parts.length !== 3) throw new Error(`JWT 应有三段（用 . 分隔），当前 ${parts.length} 段`);
  const header = JSON.parse(b64uToText(parts[0]));
  const payload = JSON.parse(b64uToText(parts[1]));
  setOut("jwt-header", JSON.stringify(header, null, 2));
  setOut("jwt-payload", JSON.stringify(payload, null, 2));

  const now = Date.now() / 1000;
  const bits = [];
  if (payload.iat) bits.push(`签发 ${fmtTime(payload.iat)}`);
  if (payload.exp) bits.push(`${payload.exp < now ? "已过期" : "有效期至"} ${fmtTime(payload.exp)}`);
  if (payload.nbf) bits.push(`生效 ${fmtTime(payload.nbf)}`);
  if (!payload.exp && !payload.iat) bits.push("payload 里没有 iat / exp");
  $("#jwt-time").textContent = bits.join(" · ");
  return { header, payload, parts };
}

$("#jwt-in").addEventListener("input", () => {
  const el = $("#jwt-in");
  if (!el.value.trim()) {
    setOut("jwt-header", "");
    setOut("jwt-payload", "");
    $("#jwt-time").textContent = "解析后可查看签发与过期时间";
    return;
  }
  try {
    jwtParse();
  } catch (_) {
    /* 输入中途不弹错，交给验签按钮 */
  }
});

$("#jwt-verify").addEventListener("click", (e) =>
  runAsync(e.currentTarget, async () => {
    const { header, parts } = jwtParse();
    const alg = String(header.alg || "");
    const keyText = $("#jwt-key").value.trim();
    if (!alg) throw new Error("header 里没有 alg");
    if (alg === "none") {
      const box = $("#jwt-result");
      box.className = "result bad";
      box.textContent = "✗ alg=none：这是未签名的 JWT，任何服务端都应当拒绝";
      return;
    }
    if (!keyText) throw new Error(`验签需要密钥：${alg.startsWith("HS") ? "填入密钥原文" : "填入公钥 PEM"}`);

    const signingInput = `${parts[0]}.${parts[1]}`;
    const expect = parts[2];
    let ok = false;

    if (alg.startsWith("HS")) {
      const map = { HS256: () => CJ.HmacSHA256, HS384: () => CJ.HmacSHA384, HS512: () => CJ.HmacSHA512 };
      const get = map[alg];
      if (!get) throw new Error(`不支持的算法 ${alg}`);
      const hex = get()(signingInput, keyText).toString(CJ.enc.Hex);
      const got = hexToBase64(hex).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      ok = got === expect;
    } else if (alg === "RS256" || alg === "RS384" || alg === "RS512" || alg === "PS256" || alg === "PS384" || alg === "PS512") {
      const hashMap = { 256: "SHA-256", 384: "SHA-384", 512: "SHA-512" };
      const hash = hashMap[alg.slice(2)];
      const isPss = alg.startsWith("PS");
      const parsed = parseKey(keyText);
      if (parsed.isPriv) throw new Error("验签请填公钥，你填入的是私钥");
      const key = await crypto.subtle.importKey("spki", spkiOf(parsed), isPss ? { name: "RSA-PSS", hash } : { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
      const param = isPss ? { name: "RSA-PSS", saltLength: { 256: 32, 384: 48, 512: 64 }[alg.slice(2)] } : { name: "RSASSA-PKCS1-v1_5" };
      try {
        ok = await crypto.subtle.verify(param, key, b64uToBytes(expect), utf8Bytes(signingInput));
      } catch (_) {
        throw new Error("验签过程出错：公钥与算法不匹配");
      }
    } else {
      throw new Error(`暂不支持 ${alg}（支持 HS256/384/512、RS*、PS*）`);
    }

    const box = $("#jwt-result");
    box.className = "result " + (ok ? "ok" : "bad");
    box.textContent = ok ? `✓ 验签通过 · ${alg}` : `✗ 验签失败 · ${alg}：密钥不对，或内容被改过`;
  })
);

$("#jwtClear").addEventListener("click", () => {
  $("#jwt-in").value = "";
  $("#jwt-key").value = "";
  setOut("jwt-header", "");
  setOut("jwt-payload", "");
  $("#jwt-time").textContent = "解析后可查看签发与过期时间";
  const box = $("#jwt-result");
  box.className = "result";
  box.textContent = "等待验证";
  toast("已清空 JWT");
});

/* ============================================================ 清空时同步重置结果框 */

$("#clearAll").addEventListener("click", () => {
  /* 密钥属于"页面设备态"而不是用户输入：清空后补一组新的，避免把面板清成砖 */
  try {
    if (!$("#sm2-pub").value.trim()) {
      const kp = sm2lib.generateKeyPairHex();
      $("#sm2-pub").value = kp.publicKey;
      $("#sm2-priv").value = kp.privateKey;
    }
    if (!$("#sm4-key").value.trim()) {
      $("#sm4-key").value = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
      $("#sm4-iv").value = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    }
    if (!$("#aes-key").value.trim()) {
      $("#aes-key").value = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
      $("#aes-iv").value = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    }
    if (!$("#des-key").value.trim()) {
      $("#des-key").value = bytesToHex(crypto.getRandomValues(new Uint8Array(24)));
      $("#des-iv").value = bytesToHex(crypto.getRandomValues(new Uint8Array(8)));
    }
  } catch (_) {
    /* 密钥库缺失时不阻断清空 */
  }
  toast("已清空；密钥已补一组新的");

  const r = $("#rsa-verify-result");
  if (r) {
    r.className = "result";
    r.textContent = "等待验证";
  }
  const j = $("#jwt-result");
  if (j) {
    j.className = "result";
    j.textContent = "等待验证";
  }
  $("#jwt-time").textContent = "解析后可查看签发与过期时间";

  const fpEl = $("#keygen-fp");
  if (fpEl) fpEl.textContent = "公钥指纹会显示在这里";
  const metaEl = $("#keygen-meta");
  if (metaEl) metaEl.textContent = "选好参数后点「生成」";
});

/* ============================================================ 启动 */

try {
  syncAesIv();
  syncDesIv();
  syncKeygenFmt();
  $("#codec-hint").textContent = CODEC_HINT[$("#codec-mode").value] || "";

  $("#aes-key").value = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  $("#aes-iv").value = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  $("#des-key").value = bytesToHex(crypto.getRandomValues(new Uint8Array(24)));
  $("#des-iv").value = bytesToHex(crypto.getRandomValues(new Uint8Array(8)));

  if (!CJ) toast("crypto-js 未加载，AES / DES / RSA 之外的部分仍可用", true);
} catch (e) {
  console.error(e);
}

/* Ed25519 支持性探测：不支持的浏览器直接把选项置灰，避免点了才报错 */
(async () => {
  try {
    await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  } catch (_) {
    const opt = [...$("#keygen-alg").options].find((o) => o.value === "ed25519");
    if (opt) {
      opt.disabled = true;
      opt.text = "Ed25519（当前浏览器不支持）";
      if ($("#keygen-alg").value === "ed25519") $("#keygen-alg").value = "rsa2048";
    }
  }
})();
