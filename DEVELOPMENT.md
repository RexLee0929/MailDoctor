# 开发说明

这份文档写结构、运行方式和几个踩过的坑。只想用程序的话看 [README.md](README.md) 就够了。

## 环境

- Python 3.9 以上
- **没有任何第三方依赖**，不需要 `pip install`，也不需要 venv

这条不是凑巧，是刻意约束：工具要在排障现场随时能跑起来，装依赖的环节本身就是故障源。加依赖前先想清楚是否值得。

## 目录结构

```
run.py                 启动入口：参数解析、CLI 模式、启动 HTTP 服务
maildoctor/
  __init__.py          版本号与对外导出
  model.py             Target / Check / Collector / CLIENTS 客户端矩阵
  dnsq.py              DNS 查询：DoH + 原生 UDP 53，报文手工编解
  netutil.py           端口探测、证书读取、HTTP 抓取（含 SNI 处理）
  checks_dns.py        MX / A / PTR / SPF / DKIM / DMARC / MTA-STS / TLS-RPT / CAA / SRV
  checks_autoconf.py   autoconfig / Autodiscover / mobileconfig / 路径矩阵 / 命名空间校验
  checks_tls.py        端口连通 + 证书 SAN 覆盖
  checks_auth.py       IMAP / SMTP 登录实测（不发信）
  scan.py              编排：分组、并发、进度事件
  report.py            汇总评分、客户端矩阵、待补记录
  server.py            ThreadingHTTPServer + SSE 推送 + /api/* 路由
web/                   前端（index.html / app.js / style.css），无构建步骤
```

`server.py` 里 `WEB_DIR = Path(__file__).parent.parent / "web"`，所以 `maildoctor/` 和 `web/` 必须保持在同一层，容器内也要维持这个相对位置。

## 运行

```bash
python run.py                                    # 127.0.0.1:8787
python run.py --host 0.0.0.0 --public            # 公网模式
python run.py --cli example.com --dkim s2024...  # 命令行
```

端口被占用时不会自动换端口，直接报错退出。Windows 上先查明占用：

```bash
netstat -ano | findstr :8787
```

## Docker

```bash
docker build -t maildoctor .
docker run --rm -p 127.0.0.1:8787:8787 maildoctor
```

镜像基于 `python:3.13-alpine`，构建时会删掉 pip / setuptools（运行时用不到）。因为零依赖，没有 `pip install` 层，改代码重建基本是秒级。

GitHub Actions 在 push 到 `main` 时自动构建并推到 GHCR，见 `.github/workflows/build-image.yml`。缓存走 `type=gha`。

`docker-compose.yml` 里 `read_only: true` 必须配 `tmpfs: /tmp`：`netutil.py` 用 `tempfile.mkstemp()` 写 PEM 临时文件，根文件系统只读会直接崩。

## 同步到发布区

按《分区规范》，编辑区（本目录）是唯一出生地，发布区是 `D:\Code\MailDoctor`，只由脚本搬运。

```bash
python tools/sync_to_code.py            # 预演，只打印计划
python tools/sync_to_code.py --apply    # 真正写入
python tools/sync_to_code.py --apply --prune   # 顺带删掉已移除的文件
```

`tools/sync_to_code.py` 的白名单是硬编码的。**新增目录必须手动加进 `SOURCE_DIRS`**，否则它永远同步不过去，而且不报错。本项目的白名单比规范模板多了几项，理由都在文件注释里：

- `maildoctor/`、`web/` 替代规范里的 `src/`：Python 项目没有构建分层，代码就在根下
- `.github/`：GitHub Actions 的 workflow 必须进仓库才能构建
- `Dockerfile`、`.dockerignore`、`docker-compose.yml`：别人 clone 下来能构建、能部署的前提
- 跳过规则额外排除 `__pycache__` 与 `*.pyc`

## 踩过的坑

**本机代理的 fake-ip 会让所有端口显示「开放」。** 代理软件把任意域名解析成 `198.18.x.x` 这类假地址，而假地址上所有端口都能连上，于是体检结果全是绿的。对策：探测时不用系统解析，用工具自己查到的真实 IP 直连，并显式传 SNI——注意 SNI 必须是域名，不能用 IP。

**DNS 查不到时绝不能回退系统解析。** 同样是被代理劫持：DoH 查不到，系统解析却返回一个假地址，后面的结论全错。查不到就报查不到。

**空 MX（`0 .`）不是「缺少 MX」。** 这是 RFC 7505 的「本域不收信」声明，要单独判定，否则会给出「补一条 MX」的错误建议。

**DKIM selector 不是标准名。** Poste.io 按建域日期生成 `s20240419303` 这种。只扫 `default` / `selector1` 会误报「未找到公钥」，必须让用户填 selector，或从后台读。

**Autodiscover 的 XML 命名空间错一个字母，Outlook 就整段忽略。** 必须是 `http://schemas.microsoft.com/exchange/autodiscover/outlook/response/v1.0/`，根元素还要带 `a:` 前缀。只检查 HTTP 200 和「有 XML」是不够的，必须解析命名空间。

**判定过严会得出「客户端能配但工具说不可用」。** 一开始找不到任何自动配置端点就报失败，但实际 BlueMail 之类靠 `mail.<域名>` 惯例就能配上。后来加了「惯例通道」：主机可解析 + 端口开放 + 证书有效，就判可凭惯例配置。

**TLS 对象不能直接进 JSON。** 探测结果里如果混了 `ssl.SSLSocket` 或证书对象，SSE 推送会抛 `TypeError`。统一转成纯 dict 再序列化。

## 加一个检查项

1. 在 `checks_*.py` 里构造 `Check(...)`，用 `collector.add()` 挂到对应分组；
2. `status` 只用 `pass` / `warn` / `fail` / `info` / `skip`，`skip` 不参与评分；
3. `fix` 字段写「可执行的动作」，不要写「请联系管理员」这类废话——用户在排障，他需要下一步做什么；
4. 返回前确认没有把不可序列化的对象塞进 `data`。
