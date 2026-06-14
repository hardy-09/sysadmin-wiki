#!/bin/bash
# 首次运行自动建虚拟环境并安装依赖
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

if [ ! -d "venv" ]; then
  echo "→ 创建虚拟环境…"
  python3 -m venv venv
  venv/bin/pip install -q --upgrade pip
  venv/bin/pip install -q -r requirements.txt
  echo "✓ 依赖安装完成"
fi

echo "→ 启动 SysAdmin Wiki …"
echo "  访问地址: http://0.0.0.0:${PORT:-5001}"
exec venv/bin/python app.py
