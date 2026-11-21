# MailDoctor

自建邮箱的配置体检工具。给定一个域名，逐项验证它「能不能收到信」「发出去的信会不会进垃圾箱」「主流客户端能不能自动配置」，最后给出一份可以照着补的清单。

出发点是 Poste.io 免费版不带官方诊断：DNS 记录少一条、Autodiscover 返回的 XML 命名空间写错一个字母、证书没覆盖 `autodiscover.` 子域——这些都表现为「客户端提示密码错误」或「发给 Gmail 直接进垃圾箱」，很难从服务器日志反推。这个工具把这类问题一次性摊开。

![平台](https://img.shields.io/badge/platform-Windows%20%2F%20Linux-0078D4)
![运行时](https://img.shields.io/badge/python-3.9%2B-3776AB)
![依赖](https://img.shields.io/badge/dependencies-none-4C1)
![许可](https://img.shields.io/badge/license-MIT-4C1)

## 获取与运行

两种方式二选一，功能完全相同：拉镜像用 Docker 跑，或者拉源码本地跑。

### 镜像运行

```bash
docker pull ghcr.io/rexlee0929/maildoctor:1.0.1
docker run -d --name maildoctor -p 127.0.0.1:8787:8787 ghcr.io/rexlee0929/maildoctor:1.0.1
```

打开 `http://127.0.0.1:8787`，填入域名即可。`:latest` 跟踪主分支，`:1.0.1` 这类版本号对应正式发版，也可以用短提交哈希锁定某次构建。镜像只构建 `linux/amd64`；若仓库与镜像设为私有，先执行 `docker login ghcr.io`。要只读根文件系统等更严的运行参数，见下文「部署 → Docker」，或直接用仓库里的 `docker-compose.yml`。

### 源码运行

需要改代码、做离线部署或读实现时用这种方式。零第三方依赖，只用 Python 标准库，不需要 `pip install`，也不需要虚拟环境。

```bash
git clone https://github.com/RexLee0929/MailDoctor.git
cd MailDoctor
python run.py
```

Windows 上也可以双击 `start.cmd`。两者都会在 `http://127.0.0.1:8787` 起服务。

命令行模式适合脚本或远程排障：

```bash
python run.py --cli example.com
python run.py --cli example.com --dkim s20240419303
python run.py --cli example.com --email me@example.com --password '***'   # 加做登录实测
```

总分低于 70% 时，命令行以非零状态退出，便于接到监控或巡检脚本里。

## 30 秒上手

1. 起服务：镜像方式用上面的 `docker run`，或 `docker compose up -d`；源码方式 `python run.py`（Windows 可双击 `start.cmd`）。打开 `http://127.0.0.1:8787`（用仓库里的 compose 起的是 `http://127.0.0.1:8006`）。
2. 填入自己的域名，按 Enter 或点「开始检查」。
3. 需要检查 DKIM 时展开「更多选项」，填入 selector。Poste.io 按建域日期生成，形如 `s20240419303`，在后台「DKIM key」一栏可以查到。
4. 想确认账号密码和认证方式可用，再填测试账号与密码；工具只做登录握手，不发送任何邮件。
5. 按「需要补充的 DNS 记录」和 zone 片段逐条补齐，改完再扫一次。

## 它解决什么

| 现象 | 只看表面会怎样 | MailDoctor 的做法 |
|---|---|---|
| 客户端提示「密码错误」 | 反复改密码、翻服务器日志，实际是 autodiscover 记录或证书问题 | 抓取并解析自动配置端点，指出卡在哪一步 |
| 发给 Gmail 进垃圾箱 | 只知道「被判垃圾」，不知道缺哪条认证 | 检查 SPF、DKIM、DMARC、MTA-STS、TLS-RPT、CAA，并给出记录 |
| 换个客户端就要手填服务器 | 不知道 SRV、autoconfig 该配什么 | 按各客户端真实的回退顺序判定，可直接照着补 |
| 换证书或加子域后自动配置失效 | 只看到「证书不受信任」 | 检查证书 SAN 是否覆盖 `mail.`、`autoconfig.`、`autodiscover.` |
| 本机能连，外网连不上 | 以为服务正常，实际被防火墙或运营商拦住 | 从运行扫描的机器发起真实连接，逐端口探测 |

## 检查什么

| 分组 | 检查项 | 回答的问题 |
|---|---|---|
| 收信与投递 | MX、空 MX（RFC 7505）、邮件主机 A/AAAA、PTR 反向解析 | 别人能不能把信送到你的服务器 |
| 发信认证 | SPF、DKIM（含密钥长度）、DMARC、MTA-STS、TLS-RPT、CAA | 你的信会不会被判垃圾、域名会不会被冒用 |
| 服务发现 | IMAP / Submission / Autodiscover 的 SRV、autoconfig / autodiscover 记录、mailconf 冲突 | 客户端能不能自己找到服务器 |
| 自动配置端点 | Mozilla autoconfig（含 `.well-known`）、Autodiscover GET 与 POST、XML 命名空间、路径覆盖矩阵、Exchange ActiveSync、Apple mobileconfig、MTA-STS 策略文件 | 配置文件的**内容**对不对，不只是记录在不在 |
| 端口与证书 | 25 / 143 / 465 / 587 / 993 / 995 连通性，证书 SAN 覆盖 | 客户端连得上吗、证书会不会报警 |
| 账号实测 | IMAP 登录（只读收件箱）与 SMTP 认证，**不发送任何邮件** | 凭据和认证方式对不对 |

DNS 查询走双通道：优先 DoH（Cloudflare、Google），失败回落到原生 UDP 53 直连；TTL 短或结果异常时会交叉验证。

## 客户端兼容性

工具按每个客户端真实的回退顺序判断，而不是看某一条记录在不在：

| 客户端 | 判定依据 |
|---|---|
| Thunderbird | Mozilla autoconfig XML（`/mail/config-v1.1.xml` 或 `/.well-known/autoconfig/`），任一可用即可 |
| BlueMail / Spark | Autodiscover → autoconfig → SRV，逐级回退 |
| Apple Mail / iOS | RFC 6186 SRV（IMAP + Submission）或 mobileconfig |
| Outlook | Microsoft Autodiscover（GET / POST，含 XML 命名空间校验）或 Autodiscover SRV |
| K-9 Mail / FairEmail | RFC 6186 SRV（IMAP + Submission） |
| 其他 | `mail.<域名>` 可解析、端口开放、证书有效时，判为「可凭惯例配置」 |

最后一行是刻意保留的：现实中不少客户端就靠 `mail.<域名>` 这个惯例猜，判定过严会得出「不可用」的错误结论。不过完全依赖惯例也有代价——只认标准发现链路的客户端（部分 Outlook、受企业策略管控的设备）仍会失败，所以能补齐的记录还是应该补。

## 界面

主页面从上到下：

- 顶部是域名输入框、「开始检查」和「关于」按钮；页面标题会带上当前版本号。
- 「更多选项」里可以填邮件主机、DKIM selector、测试账号和密码；邮件主机留空时自动用 `mail.<域名>`。
- 结果区先显示总分与结论，再按分组流式渲染检查项；每组到达即显示，不必等全部完成。
- 分组之后是「需要补充的 DNS 记录」、客户端自动配置矩阵，以及可直接复制的完整 zone 片段。
- 「关于」里的文案来自根目录的 `ABOUT.md`，版本号由后端注入。

快捷键：域名输入框内按 `Enter` 开始检查；关于窗口打开时按 `Esc` 关闭。

## 选项与参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--host` | `127.0.0.1` | 监听地址；公网部署用 `0.0.0.0` |
| `--port` | `8787` | 监听端口 |
| `--public` | 关闭 | 启用限流（每 IP 4 次/分钟）并拒绝把内网地址作为扫描目标 |
| `--max-concurrent` | 6 | 同时进行的扫描数；超出时返回 503，不排队 |
| `--open` | 关闭 | 启动后自动打开浏览器 |
| `--cli DOMAIN` | — | 不开服务，直接对域名输出文本报告 |
| `--mail-host` | `mail.<域名>` | 邮件服务器主机名；解析不到时自动回退到 MX 指向的主机 |
| `--dkim` | 空 | DKIM selector；不填时只按常见名称尝试 |
| `--email` | `postmaster@<域名>` | 登录实测使用的邮箱地址 |
| `--password` | 空 | 配合 `--email`；只有填了密码才会执行账号实测 |
| `--log-file` | 空 | 输出同时写入该文件，超过 10 MB 轮转一份；容器部署用 |

界面上的「更多选项」与 `--mail-host`、`--dkim`、`--email`、`--password` 一一对应。密码只用于本次登录，不写入配置或日志。

## 部署

### 本地

```bash
python run.py
python run.py --open          # 启动后自动打开浏览器
```

端口被占用时不会自动换端口，直接报错退出。Windows 上可以先查占用：`netstat -ano | findstr :8787`。

### Docker

直接用镜像（与上面的 `pull` + `run` 相同，参数更严）：

```bash
docker run -d --name maildoctor \
  -p 127.0.0.1:8787:8787 \
  --read-only --tmpfs /tmp:size=32m \
  --security-opt no-new-privileges --cap-drop ALL \
  ghcr.io/rexlee0929/maildoctor:1.0.1
```

或者用仓库里的 `docker-compose.yml`，它已经填好镜像名，并配了只绑回环、只读根文件系统、丢掉全部 capability、`/tmp` 挂 tmpfs 和日志轮转。宿主机端口是 **8006**（容器内仍是 8787），日志由程序自己写到挂载出来的 `./logs`：

```bash
mkdir -p logs && chown -R 10001:10001 logs    # 必须：容器以 uid 10001 运行，属主不对就没有日志
docker compose up -d
docker compose logs -f      # 启动阶段的容器日志
tail -f logs/maildoctor.log # 程序日志，超过 10 MB 轮转一份
```

日志文件不可写时程序不会退出，只打印警告并退化为只写控制台——但那样宿主机上就看不到日志了，所以 `chown` 这步别省。

镜像基于 `python:3.13-alpine`，只构建 `linux/amd64`，运行时不带 pip 和 setuptools。确实需要改代码时再本地构建：

```bash
docker build -t maildoctor .
docker run -d --name maildoctor -p 127.0.0.1:8787:8787 maildoctor
```

根文件系统只读时 **必须保留 `tmpfs: /tmp`**：TLS 探测会写临时 PEM 文件，没有可写目录会直接失败。

### 公网

```bash
python run.py --host 0.0.0.0 --port 8787 --public
```

`--public` 会启用限流并拒绝解析到内网的扫描目标，避免实例被当成 DNS 或端口扫描代理。**它不是认证机制**——对外暴露必须自己加一层访问控制，例如 Caddy 反向代理加 basic auth，并只允许可信来源访问。

## 判定与评分

- 评分按权重计算：通过得 1 分、警告得 0.5 分、失败得 0 分；提示和跳过不计入分母。核心项权重更高（MX、SPF 为 10，DKIM 为 9，A 记录为 8）。
- 客户端矩阵的通道语义是「外层任一、内层全部」：Thunderbird 的 `autoconfig` 子域和 `.well-known` 是两条独立路径，任一可用即可；而 SRV 通道要求 IMAP 与 Submission 同时存在。
- 端口探测不使用系统解析：先用工具自己的 DNS 查到 IP，再直连并显式传 SNI。这样既避开本机代理的 fake-ip 假阳性，也能验证真实证书。
- DNS 无结果时不会回退到系统解析。系统解析可能被代理劫持到一个「什么端口都开着」的假地址，回退只会得到错误结论。

## 常见问题

**扫描说端口不通，但我在服务器上能连？**

工具是从运行它的机器发起连接，不是从邮件服务器本机。检查云安全组、主机防火墙，以及运营商是否封了 25 端口；不少云厂商默认封锁 25 出站。

**DKIM 显示「未找到公钥」，但后台明明有记录？**

selector 通常不是 `default`。Poste.io 按建域日期生成，形如 `s20240419303`；把后台「DKIM key」里的完整 selector 填进「更多选项」再扫。

**「可凭惯例配置」是什么意思？**

标准发现链路（autoconfig、autodiscover、SRV）都不通，但 `mail.<域名>` 能解析、端口和证书正常，多数客户端会按惯例直接猜中并配置成功。它仍然不是完整状态：只认标准发现的客户端会失败，建议按清单补齐。

**填真实账号密码安全吗？**

密码只在本次扫描的内存里使用，不落盘、不写日志；IMAP 只读收件箱，SMTP 只做认证，不发送、删除或修改邮件。公网实例不要填真实密码，除非实例完全由你控制。

**可以扫描别人的域名吗？**

不可以。工具会主动连接目标的邮件端口，只应扫描自己拥有或已获授权检查的域名。

**结果会保存吗？**

不会。结果只在当前页面显示，刷新即重扫；命令行输出到终端。

## 开发说明

环境、目录结构、Docker 构建、同步脚本和踩过的坑见 [DEVELOPMENT.md](DEVELOPMENT.md)。

## 已知限制

- 不能验证 DKIM 是否真的在签名，只能验证公钥记录存在且长度达标；验证签名要发一封真信看头部。
- 客户端矩阵覆盖 Thunderbird、BlueMail、Spark、Apple Mail、Outlook、K-9/FairEmail，未覆盖 Samsung Mail、eM Client 等专有实现。
- 不做投递实测（不发信到 Gmail / Outlook 观察落点），这一步仍然需要人工完成。
- 公网模式 `--public` 只提供限流与内网拦截，不是认证；对外暴露必须自行加访问控制。
- 扫描结果受运行环境影响：本机代理、防火墙、DNS 出口都可能改变结论，换一个网络复扫有助于区分。

## 反馈

问题反馈：rexlee@rexleepro.com。请附上域名（可脱敏）、扫描结果或命令行输出；不要发送邮箱密码。

## 第三方组件

没有第三方 Python 依赖，运行时只用标准库。Docker 镜像基于 `python:3.13-alpine`（Python Software Foundation，PSF License）。

## License

MIT，见 [LICENSE](LICENSE)。Copyright © 2026 Rex Lee。
