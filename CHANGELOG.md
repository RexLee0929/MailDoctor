# 更新日志

本项目的所有显著变更都记录在这个文件里。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-11-21

### 新增

- 六个分组的体检项：收信与投递、发信认证、服务发现、自动配置端点、端口与证书、账号实测
- DNS 双通道解析：DoH（Cloudflare / Google）优先，原生 UDP 53 兜底，结果可交叉验证
- SPF / DKIM / DMARC / MTA-STS / TLS-RPT / CAA / SRV 校验，DKIM 额外检查密钥长度是否达到 2048 位
- 实际抓取并解析 Mozilla autoconfig、Autodiscover（GET 与 POST）、Apple mobileconfig、MTA-STS 策略文件，校验内容而不只是看记录是否存在
- 按每个客户端的真实回退顺序判定自动配置能力（Thunderbird / BlueMail / Spark / Apple Mail / Outlook / K-9 / FairEmail），并对无法判定者提供「凭 `mail.<域名>` 惯例可配置」的结论
- 端口连通性探测与证书 SAN 覆盖检查，探测使用自解析 IP 直连并显式指定 SNI
- IMAP / SMTP 真实登录实测（仅握手，不发送邮件）
- Web 界面以 SSE 流式返回进度，命令行模式输出纯文本报告
- `--public` 公网模式：限流 + 拒绝内网扫描目标
- Dockerfile 与 GitHub Actions 自动构建（GHCR）

### 修复

- 识别 `0 .` 空 MX，判定为「该域声明不收信」而不是「缺少 MX」
- DNS 查询无结果时不再回退到系统解析，避免被本机代理的 fake-ip 劫持得出错误结论
- TLS 探测结果转为纯字典再序列化，修复不可 JSON 序列化的报错

[1.0.0]: releases/v1.0.0.md
