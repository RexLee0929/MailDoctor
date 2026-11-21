## **{NAME}** **{VERSION}**

{TAGLINE}

给自建邮件服务器做一次完整体检：DNS 记录、发信认证、自动配置端点、端口与证书、账号登录，逐项给出结论和可以照着改的建议。

**主要功能**

- 收信与投递：MX、A、PTR、空 MX 声明，并校验发现域名
- 发信认证：SPF、DKIM（含密钥长度）、DMARC、MTA-STS、TLS-RPT、CAA
- 服务发现：SRV（IMAP / Submission / Autodiscover）与 autoconfig、autodiscover 记录
- 自动配置端点：实际抓取并解析 autoconfig XML、Autodiscover、mobileconfig、MTA-STS 的内容
- 端口与证书：25 / 465 / 587 / 993 等端口连通性，证书 SAN 覆盖
- 账号实测：用真实账号走一次 IMAP / SMTP 登录，只握手，不发送任何邮件

**快捷键**

Enter 开始检查　Esc 关闭关于

免费软件，依据 MIT License 分发。
© 2026 {AUTHOR}　保留所有权利。
