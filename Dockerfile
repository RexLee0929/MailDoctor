# MailDoctor —— 纯标准库，无第三方依赖，因此不需要 pip install 阶段
FROM python:3.13-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

WORKDIR /app

# 只复制运行必需的文件，保持 web/ 与 maildoctor/ 相对 run.py 的位置
COPY run.py ./
COPY maildoctor/ ./maildoctor/
COPY web/ ./web/

# /api/about 的文案源，缺了会退回 server.py 里的内置简短版本
COPY ABOUT.md ./

# 运行时用不到 pip / setuptools，删掉可省约 12MB
RUN rm -rf /usr/local/lib/python3.*/ensurepip \
           /usr/local/lib/python3.*/site-packages/pip \
           /usr/local/lib/python3.*/site-packages/pip-* \
           /usr/local/lib/python3.*/site-packages/setuptools \
           /usr/local/lib/python3.*/site-packages/setuptools-* \
           /usr/local/lib/python3.*/site-packages/pkg_resources

# 非 root 运行（8787 > 1024，无需特权端口）
RUN adduser -D -H -u 10001 app
USER 10001:10001

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8787/api/health >/dev/null || exit 1

CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "8787", "--public"]
