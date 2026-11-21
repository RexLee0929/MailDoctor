# 开发说明

这份文档写结构、运行方式和几个踩过的坑。只想用程序的话看 [README.md](README.md) 就够了。

## 环境

- Python 3.9 以上（Docker 镜像用 3.13）。代码要保持 3.9 兼容，不要用 3.10 以后才有的语法。
- **没有任何第三方依赖**，不需要 `pip install`，也不需要 venv

这条不是凑巧，是刻意约束：工具要在排障现场随时能跑起来，装依赖的环节本身就是故障源。加依赖前先想清楚是否值得。

## 版本号

`maildoctor/__init__.py` 的 `__version__` 是唯一来源：`server.py` 用它生成 `/api/health`、`/api/about` 和响应头，前端标题栏也从 `/api/about` 读取。改版本时只改这一处，并让发布区的 `vX.Y.Z` 标签与之一致；README 和 `ABOUT.md` 不写死版本号。

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

`ABOUT.md` 是「关于」文案的唯一来源，`server.py` 读取后替换占位符；`releases/` 放每个版本的发布说明；`tools/sync_to_code.py` 负责编辑区到发布区的同步。

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

## 改动范围

| 需求 | 修改位置 |
|---|---|
| 增加检查项 | 在对应的 `checks_*.py` 里构造 `Check`，分组 id 用 `model.GROUPS` 中已有的值，详见文末 |
| 调整评分 | `model.SCORE` 或各检查项的 `weight`；`INFO`、`SKIP` 不计入分母 |
| 增加客户端 | `model.CLIENTS` 增加通道组合；缺少的通道要在 `checks_*.py` 里补上同 id 的检查 |
| 增加 API | `server.py` 的 `do_GET` / `do_POST` 路由，前端在 `web/app.js` 里对接 |
| 改界面 | `web/index.html`、`web/app.js`、`web/style.css`；没有构建步骤，刷新即可 |
| 改关于文案 | 根目录 `ABOUT.md`，保留 `{NAME}`、`{VERSION}`、`{TAGLINE}`、`{AUTHOR}` 占位符 |
| 改公网限制 | `server.py` 的 `RateLimiter` 与 `_blocked_target`，并同步 README 的部署说明 |

## Docker

```bash
docker build -t maildoctor .
docker run --rm -p 127.0.0.1:8787:8787 maildoctor
```

镜像基于 `python:3.13-alpine`，构建时会删掉 pip / setuptools（运行时用不到）。因为零依赖，没有 `pip install` 层，改代码重建基本是秒级。

GitHub Actions 在 push 到 `main`、打 `v*` tag 或手动触发时构建并推送到 GHCR，见 `.github/workflows/build-image.yml`，缓存走 `type=gha`。工作流里镜像名是 `ghcr.io/${{ github.repository }}`，由仓库地址推导，不需要另写常量；tag 规则是 `main` 分支产出 `latest`、`v*` tag 产出语义化版本号，每次构建另带一个短提交哈希。按当前仓库，实际地址是 `ghcr.io/rexlee0929/maildoctor`（GHCR 路径一律小写），`docker-compose.yml` 里已经按这个填好；仓库改名或换所有者后，只需要改 compose 那一行。

工作流只构建 `linux/amd64`。在 arm64 机器上要原生运行，得自己 `docker build` 一份，否则走模拟层。

`Dockerfile` 复制 `run.py`、`maildoctor/`、`web/`，另外单独 `COPY ABOUT.md ./`，容器内 `/api/about` 与本地一样读完整的关于文案。注意 `.dockerignore` 里有 `*.md`，会把这个文件挡在构建上下文外，所以末尾保留了 `!ABOUT.md` 例外——删掉它构建会直接报找不到文件。

`docker-compose.yml` 里 `read_only: true` 必须配 `tmpfs: /tmp`：`netutil.py` 用 `tempfile.mkstemp()` 写 PEM 临时文件，根文件系统只读会直接崩。

## 验证

项目没有自动化测试目录。改动后至少手工过一遍：

```bash
python run.py --cli example.com          # 六组都有输出，总分与结论合理
python run.py --open                     # 浏览器里跑一次真实域名
curl -s http://127.0.0.1:8787/api/health # 返回 ok 与当前版本
```

界面重点看四件事：分组是否随 SSE 逐个出现、客户端矩阵是否与检查结果一致、「需要补充的 DNS 记录」是否去重、zone 片段能否直接复制。改过公网逻辑时，用 `--public` 启动并扫描 `localtest.me` 这类解析到内网的域名，确认被 403 拒绝。命令行退出码也值得看一眼：总分低于 70% 返回 1，其余返回 0。

## 同步到发布区

按《分区规范》，编辑区（本目录）是唯一出生地，发布区由脚本的 `--dest` 或环境变量 `MD_DEST` 指定，只由脚本搬运。

```bash
python tools/sync_to_code.py            # 预演，只打印计划
python tools/sync_to_code.py --apply    # 真正写入
python tools/sync_to_code.py --apply --prune   # 顺带删掉已移除的文件
python tools/sync_to_code.py --apply --force   # 目标被外部改过时强制覆盖
```

`tools/sync_to_code.py` 的白名单是硬编码的。**新增目录必须手动加进 `SOURCE_DIRS`**，否则它永远同步不过去，而且不报错。本项目的白名单比规范模板多了几项，理由都在文件注释里：

- `maildoctor/`、`web/` 替代规范里的 `src/`：Python 项目没有构建分层，代码就在根下
- `.github/`：GitHub Actions 的 workflow 必须进仓库才能构建
- `Dockerfile`、`.dockerignore`、`docker-compose.yml`：别人 clone 下来能构建、能部署的前提
- 跳过规则额外排除 `__pycache__` 与 `*.pyc`

脚本用 `tools/.sync-state.json` 记录上次同步的哈希。发布区文件在上次同步后被外部改过时，默认报冲突并跳过，不覆盖；确认要丢弃那些改动才加 `--force`。脚本不创建备份，也不执行任何 git 操作。

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
2. `status` 只用 `pass` / `warn` / `fail` / `info` / `skip`，`skip` 不参与评分；`weight` 按重要性给，核心项 8–10，可选增强 2–4；
3. `fix` 字段写「可执行的动作」，不要写「请联系管理员」这类废话——用户在排障，他需要下一步做什么；
4. 返回前确认没有把不可序列化的对象塞进 `data`。
