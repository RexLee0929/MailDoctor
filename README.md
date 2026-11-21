# MailDoctor

自建邮箱的配置体检工具。给定一个域名，逐项验证它「能不能收到信」「发出去的信会不会进垃圾箱」「主流客户端能不能自动配置」，最后给出一个可以照着补的清单。

出发点是 Poste.io 免费版不带官方诊断：DNS 记录少一条、Autodiscover 返回的 XML 命名空间写错一个字母、证书没覆盖 `autodiscover.` 子域——这些都表现为「客户端提示密码错误」或「发给 Gmail 直接进垃圾箱」，很难从服务器日志反推。这个工具把这类问题一次性摊开。

零依赖，只用 Python 标准库。

## 检查什么

| 分组 | 内容 | 回答的问题 |
| --- | --- | --- |
| 收信与投递 | MX、A、PTR、空 MX 识别、发现域名 | 别人能不能把信送到你的服务器 |
| 发信认证 | SPF、DKIM（含密钥长度）、DMARC、MTA-STS、TLS-RPT、CAA | 你的信会不会被判垃圾、会不会被冒用 |
| 服务发现 | SRV（IMAP / Submission / Sieve）、autoconfig / autodiscover 记录 | 客户端能不能自己找到服务器 |
| 自动配置端点 | 实际抓取 Mozilla autoconfig、Autodiscover（GET + POST）、Apple mobileconfig、MTA-STS 策略并校验内容 | 配置文件的**内容**对不对，不只是记录在不在 |
| 端口与证书 | 25 / 465 / 587 / 993 / 995 / 143 / 4190 连通性，证书 SAN 覆盖 | 客户端连得上吗、证书会不会报警 |
| 账号实测 | 真实账号走一次 IMAP / SMTP 登录（**不发送任何邮件**） | 凭据和认证方式对不对 |

DNS 查询走双通道：优先 DoH（Cloudflare / Google），失败回落到原生 UDP 53 直连。TTL 短、结果异常时会交叉验证。

## 快速开始

```bash
python run.py
```

打开 `http://127.0.0.1:8787`，填域名即可。不需要 `pip install`。

命令行模式（适合脚本或远程排障）：

```bash
python run.py --cli example.com
python run.py --cli example.com --dkim s20240419303
python run.py --cli example.com --email me@example.com --password '***'   # 加做登录实测
```

DKIM 的 selector 通常不是 `default`。Poste.io 按建域日期生成，形如 `s20240419303`，在后台「DKIM key」一栏可以看到。

## 客户端兼容性判定

工具按每个客户端真实的回退顺序判断，而不是看某一条记录在不在：

| 客户端 | 判定依据 |
| --- | --- |
| Thunderbird | Mozilla autoconfig XML（`/mail/config-v1.1.xml` 或 `/.well-known/autoconfig/`） |
| BlueMail | Autodiscover → autoconfig → SRV，逐级回退 |
| Apple Mail / iOS | mobileconfig 描述文件或 autoconfig |
| Outlook（桌面） | Autodiscover（含 POST 与正确的 XML 命名空间） |
| 其他 | 若 `mail.<域名>` 可解析、端口开放、证书有效，判为「可凭惯例配置」 |

最后一行是刻意保留的：现实中很多客户端就靠 `mail.<域名>` 这个惯例猜，判定过严会得出「不可用」的错误结论。

## 部署

### Docker

```bash
docker build -t maildoctor .
docker run -d --name maildoctor -p 127.0.0.1:8787:8787 maildoctor
```

或直接用镜像（GitHub Actions 构建，推到 GHCR）：

```bash
docker compose up -d
```

`docker-compose.yml` 默认只绑回环、只读根文件系统、丢掉全部 capability。要对外访问就加一层 Caddy 反代**并设密码**。

### 公网模式

```bash
python run.py --host 0.0.0.0 --port 8787 --public
```

`--public` 会启用限流（默认每 IP 4 次/分钟）并拒绝把内网地址作为扫描目标，避免实例被当成端口扫描代理。**它不是认证机制**——公网部署必须自己加一层访问控制。

## 注意

- 工具会主动连接目标的 25 / 465 / 587 / 993 等端口做探测。只应扫描自己拥有或获授权检查的域名。
- 账号实测只做登录握手，不会发送、删除或修改任何邮件。
- 结果不落盘，刷新即重扫。

## 许可

MIT，见 [LICENSE](LICENSE)。
