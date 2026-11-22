# gm-tools

纯前端的加解密与证书工具箱。所有计算在浏览器里完成，不上传任何数据、不连任何后端。

- **加解密站**：<https://gm.xianglong.vip/> — AES / DES·3DES / SM4 / SM2 / RSA、摘要与 HMAC、编码转换、数字信封、JWT 解析、密钥对生成（RSA / SM2 / Ed25519）。
- **证书站**：<https://gm.xianglong.vip/cert/> — PEM / DER / JKS 证书解析、证书链完整性诊断、扩展字段（SAN / KeyUsage / 基本约束）、SHA-256 指纹。

## 目录

```
web/
├── index.html          加解密站主页面（多面板单页）
├── app.js              国密与基础算法面板
├── extra.js            AES/DES/RSA/摘要/编码/JWT/密钥生成
├── style.css
├── vendor/             sm2 sm3 sm4 crypto-js（本地引入，无 CDN 依赖）
└── cert/               证书解析页
    ├── index.html
    ├── cert.js         ASN.1 / X.509 / JKS 解析（无第三方依赖）
    ├── ui.js
    └── cert.css
```

## 部署

静态文件，任意 web server 直接指向 `web/` 即可。注意让 `/cert/` 落到 `web/cert/index.html`。

仓库里的版本与线上一致；`vendor/` 中的库均为固定版本本地化，不依赖外部 CDN。
