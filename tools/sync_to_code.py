#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MailDoctor 同步工具：当前工作区（编辑区） -> D:\\Code\\MailDoctor（发布区）

用法:
  python tools/sync_to_code.py            # 预演（默认，不写任何文件）
  python tools/sync_to_code.py --apply    # 真正写入发布区
  python tools/sync_to_code.py --dest <路径>   # 覆盖目标目录（默认取环境变量 MD_DEST 或 D:/Code/MailDoctor）
  python tools/sync_to_code.py --force    # 目标被外部改过时仍然覆盖
  python tools/sync_to_code.py --prune    # 发布区里已从源码删除的文件，一并删除（需配合 --apply）

安全策略:
  1. 不做 --apply 时只打印计划，绝不落盘。
  2. 只写白名单里的源码/文档，__pycache__、.pyc 和 `_` 开头的临时文件一律不同步。
  3. 若目标文件在上次同步之后被外部改动过（哈希对不上），默认报冲突并跳过，不覆盖。
  4. 默认不删除任何目标文件，除非显式 --prune。
  5. 本工具不创建发布区目录、不执行 git init —— 发布区由人一次性建好。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parent                      # 编辑区根目录
STATE_FILE = HERE / ".sync-state.json"

DEFAULT_DEST = r"D:/Code/MailDoctor"

# ── 源码同步白名单（相对编辑区根）────────────────────────────────────────
# 与《分区规范》模板的差异，逐条都是刻意加的：
#   · maildoctor/ + web/ 替代 src/ —— Python 项目没有构建分层，代码就在根下
#   · .github/            —— Actions 的 workflow 必须进仓库才能构建镜像
#   · Dockerfile / .dockerignore / docker-compose.yml —— 别人 clone 后能构建、能部署
SOURCE_FILES = [
    "README.md",
    "CHANGELOG.md",
    "DEVELOPMENT.md",
    "ABOUT.md",
    "LICENSE",
    ".gitignore",
    ".gitattributes",
    "Dockerfile",
    ".dockerignore",
    "docker-compose.yml",
]
SOURCE_DIRS = ["maildoctor", "web", ".github", "tools", "releases"]

# 判断「是不是同一批代码」时忽略的路径片段
SKIP_PARTS = {".git", ".vs", ".sync-state.json", "__pycache__", ".mypy_cache",
              ".pytest_cache", "_shots"}

# 后缀级排除：任何位置出现都不同步（编译缓存 / 临时物）
SKIP_SUFFIXES = {".pyc", ".pyo"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rel_files() -> list[Path]:
    """收集需要同步的源码文件（相对编辑区根的 POSIX 路径）。"""
    out: list[Path] = []
    for name in SOURCE_FILES:
        p = SRC_ROOT / name
        if p.is_file():
            out.append(Path(name))
    for d in SOURCE_DIRS:
        base = SRC_ROOT / d
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            r = p.relative_to(SRC_ROOT)
            if SKIP_PARTS & set(r.parts):
                continue
            if p.suffix.lower() in SKIP_SUFFIXES:
                continue
            # `_` 开头视为截图/临时物（_shots/ 等），但 __init__.py 是包入口必须放行
            if any(part.startswith("_") for part in r.parts) and r.name != "__init__.py":
                continue
            out.append(r)
    return sorted(out, key=lambda x: x.as_posix().lower())


def load_state() -> dict:
    if STATE_FILE.is_file():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            print("! .sync-state.json 解析失败，按「无历史」处理")
    return {"files": {}}


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--apply", action="store_true", help="真正写入（默认只预演）")
    ap.add_argument("--force", action="store_true", help="目标被外部改动时强制覆盖")
    ap.add_argument("--prune", action="store_true", help="删除发布区中已不存在的源码文件")
    ap.add_argument("--dest", default=os.environ.get("MD_DEST", DEFAULT_DEST))
    args = ap.parse_args()

    dest = Path(args.dest).resolve()
    print(f"编辑区: {SRC_ROOT}")
    print(f"发布区: {dest}")
    print(f"模式  : {'写入' if args.apply else '预演(不落盘)'}")
    print("-" * 64)

    if not dest.is_dir():
        print(f"× 发布区不存在: {dest}")
        print(f"  先建目录并初始化仓库：")
        print(f"    mkdir -p \"{dest.as_posix()}\"")
        print(f"    git -C \"{dest.as_posix()}\" init -b main")
        return 2
    if dest == SRC_ROOT:
        print("× 编辑区与发布区是同一个目录，无需同步")
        return 2

    state = load_state()
    known = state.get("files", {})

    tasks = [(SRC_ROOT / r, r) for r in rel_files()]

    add, same, conflict = [], [], []
    stamp = time.strftime("%Y%m%d-%H%M%S")
    new_state = {}

    for src, rel in tasks:
        dst = dest / rel
        if not src.is_file():
            continue
        key = rel.as_posix()
        src_hash = sha256(src)
        if not dst.is_file():
            new_state[key] = src_hash
            add.append((src, rel, "新增"))
            continue
        dst_hash = sha256(dst)
        if dst_hash == src_hash:
            new_state[key] = src_hash
            same.append(rel)
            continue
        was = known.get(key)
        if was is None or was == dst_hash or args.force:
            new_state[key] = src_hash
            add.append((src, rel, "更新"))
        else:
            # 冲突：目标在上次同步后被外部改过。这里绝不更新 new_state ——
            # 一旦把「新源哈希」记成基准，下次比较时它依然不等于目标哈希，
            # 冲突就会永久化。
            conflict.append((src, rel, "目标被外部改过"))

    removed: list[Path] = []
    if args.prune:
        conflict_keys = {rel.as_posix() for _, rel, _ in conflict}
        for k in known:
            if k in new_state or k in conflict_keys:
                continue
            target = dest / k
            if not target.is_file():
                continue
            # 源里已经没有这个文件了，只能拿状态里上次同步的哈希当基准。
            # 目标哈希对不上，说明它在同步后被外部改过，不能因为源删了就顺手抹掉。
            if not args.force and sha256(target) != known[k]:
                conflict.append((None, Path(k), "源已删 / 目标被外部改过"))
                continue
            removed.append(Path(k))

    print(f"无变化 {len(same):>4} 个")
    for src, rel, tag in add:
        print(f"  [{tag}] {rel.as_posix()}")
    if conflict:
        print(f"冲突   {len(conflict):>4} 个（目标在上次同步后被改动，未覆盖）")
        for src, rel, tag in conflict:
            print(f"  [!] {rel.as_posix()}  {tag}")
        print("      → 确认要覆盖请加 --force")
    for r in removed:
        print(f"  [删除] {r.as_posix()}")

    if not args.apply:
        print("-" * 64)
        print(f"预演结束：待写 {len(add)}，冲突 {len(conflict)}，待删 {len(removed)}。加 --apply 执行。")
        return 1 if conflict else 0

    if not add and not removed:
        print("-" * 64)
        if conflict:
            print(f"× 有 {len(conflict)} 个冲突未处理，什么都没写。确认覆盖请加 --force")
            return 1
        print("无需写入。")
        return 0

    written = 0
    for src, rel, tag in add:
        dst = dest / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        written += 1

    for r in removed:
        (dest / r).unlink()

    # 写完再落状态，避免中途失败把状态写脏
    merged = dict(known)
    merged.update(new_state)
    for r in removed:
        merged.pop(r.as_posix(), None)
    STATE_FILE.write_text(
        json.dumps({"synced_at": stamp, "dest": str(dest), "files": merged},
                   ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("-" * 64)
    print(f"完成：写入 {written}，删除 {len(removed)}。")
    if conflict:
        print(f"× 仍有 {len(conflict)} 个冲突未覆盖（状态已保留原基准），确认覆盖请加 --force")
    # 有冲突就不能返回 0：否则外层脚本会当成一切正常，把旧文件当新版本推上去。
    return 1 if conflict else 0


if __name__ == "__main__":
    sys.exit(main())
