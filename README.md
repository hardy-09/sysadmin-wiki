# Wiki

一个面向系统管理员的私有知识库，基于 Flask 构建。支持 Markdown 笔记、多工作区、全文搜索、数据导入导出，内置登录限速与安全加固。

---

## 功能概览

### 笔记

- 树状层级结构，支持无限嵌套
- **拖拽换父级**：直接拖动笔记节点到目标位置，实时更新树结构
- Markdown 实时预览（基于 marked.js + DOMPurify XSS 过滤）
- 代码块语法高亮（highlight.js）
- 打开导航栏笔记页自动展示第一条笔记
- 支持 JSON（还原层级）、Markdown（多文件批量）、TXT 格式导入导出

### 多工作区

- 每个用户可创建多个独立工作区，笔记与密码库按工作区隔离
- 顶栏随时切换，支持重命名、删除、设置固定数量上限

### 搜索

- 全文搜索笔记标题与正文
- 结果高亮显示匹配片段

### 管理后台

- 用户管理：创建账户、重置密码、启用/禁用、设置管理员权限
- 数据导入导出：密码库（JSON / Excel）、笔记（JSON / MD / TXT）
- 自定义选项配置

### 安全

| 特性 | 说明 |
|------|------|
| 登录限速（按用户名） | 第 4 次失败出现数学验证码，第 5 次起指数递增封锁时间 |
| 登录限速（按 IP） | 同一 IP 累计 20 次失败后封锁，防止换账号爆破 |
| 数学验证码 | 两种题型：`(a + b) × c` 和 `a × b - c` |
| 会话安全 | `HttpOnly` + `SameSite=Lax` Cookie，`SECRET_KEY` 持久化到文件 |
| CSP 响应头 | 限制脚本与样式来源，封堵 XSS 数据外泄 |
| 其他安全头 | `X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy` |
| 开放重定向防护 | `next` 参数严格校验，只允许站内路径 |

---

## 快速开始

### 环境要求

- Python 3.9+
- pip

### 安装

```bash
git clone https://github.com/hardy-09/sysadmin-wiki.git
cd sysadmin-wiki

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 运行（开发）

```bash
python app.py
# 访问 http://localhost:5001
```

首次启动自动创建 admin 账户，默认密码 `admin123`，**请立即修改**。

### 生产部署（推荐）

```bash
# 安装 gunicorn
pip install gunicorn

# 启动（配合 nginx 反代）
gunicorn -w 2 -b 127.0.0.1:5001 app:app
```

nginx 示例配置：

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;
    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;
    }
}
```

开启 HTTPS 后在 `app.py` 追加：

```python
app.config['SESSION_COOKIE_SECURE'] = True
```

### 文件权限保护

```bash
chmod 600 .secret_key .fernet_key instance/sysadmin.db
```

---

## 技术栈

| 组件 | 说明 |
|------|------|
| Flask | Web 框架 |
| SQLAlchemy | ORM，SQLite 存储 |
| Flask-Login | 会话管理 |
| cryptography (Fernet) | 对称加密 |
| openpyxl | Excel 导入导出 |
| marked.js | Markdown 渲染 |
| DOMPurify | XSS 过滤 |
| Bootstrap 5 | UI 组件 |

---

## 目录结构

```
sysadmin-wiki/
├── app.py              # 主程序，全部路由与业务逻辑
├── requirements.txt
├── start.sh
└── templates/
    ├── base.html       # 基础布局与导航
    ├── login.html
    ├── index.html
    ├── search.html
    ├── data.html       # 导入导出管理页
    ├── notes/
    │   └── main.html   # 笔记主界面
    ├── users/          # 用户管理
    ├── workspaces/     # 工作区管理
    └── options/        # 自定义选项
```

---

## License

MIT
