# iptables-web - 防火墙规则管理系统

基于 Flask + SQLite + Paramiko + iptables 的 Web 管理系统，用于集中管理多台 Linux 主机的防火墙规则。

## 功能概览

- 主机管理：维护被管控主机（IP、SSH 端口、认证方式等）
- 规则管理：查看/新增/编辑/删除主机的入方向、出方向规则
- 模板管理：创建规则模板并批量下发到多台主机
- 规则查看：在侧边栏可直接进入规则查看并切换主机
- 模板删除联动清理：删除模板时会尝试同步清理对应主机上的模板规则
- 操作日志：记录关键操作，支持查询与审计
- 权限控制：基于角色的访问控制（RBAC）

## 技术栈

- 前端：Tailwind CSS + Font Awesome + 原生 JavaScript
- 后端：Python + Flask + Flask-Login + Flask-APScheduler
- 数据库：SQLite（`firewall_management.db`）
- 远程执行：Paramiko（SSH）

## 环境要求

- Python 3.9+
- Linux 环境（推荐部署在 CentOS / Debian / Ubuntu）
- 目标主机可通过 SSH 访问，并安装 `iptables`

## 本地启动（推荐）

```bash
# 1) 进入项目目录
cd iptables-web

# 2) 创建虚拟环境
python3 -m venv .venv
source .venv/bin/activate

# 3) 安装依赖
pip install -r requirements.txt

# 4) 启动
python3 app.py
```

默认监听：`0.0.0.0:2025`  
访问地址：`http://127.0.0.1:2025`

## Docker 启动

```bash
docker build -t iptables_web:latest .
docker run --net=host -d --name iptables-web iptables_web:latest
```

## 登录说明

- 默认账号：`admin`
- 默认密码：`admin123`
- 首次登录后请立即修改密码

> 若历史数据中的密码哈希为 `scrypt` 且运行环境不支持 `hashlib.scrypt`，会导致登录失败。  
> 当前代码已将新密码哈希切换为 `pbkdf2:sha256`，建议重置该账号密码后再登录。

## 使用流程

1. 在“主机管理”中添加被管理主机（SSH 参数必须正确）
2. 在“模板管理”中创建模板并配置规则
3. 批量应用模板到目标主机
4. 通过“规则查看”切换主机核验规则效果
5. 通过“操作日志”审计关键操作

## 常见问题排查

### 1) 登录时提示“网络错误”

通常不是前端网络问题，而是后端 `/login` 返回了 500。  
可查看服务日志是否有类似报错：

- `hashlib has no attribute scrypt`
- 数据库表不存在或连接异常

建议：

- 确认使用 `python3 app.py` 正常启动
- 检查 `firewall_management.db` 是否存在且可读写
- 将异常账号密码重置为新哈希（pbkdf2）

### 2) 规则页面 500，日志提示 `SSH 操作失败: timed out`

说明 Web 服务无法通过 SSH 连到目标主机，而非页面逻辑错误。  
请重点检查：

- 主机 IP / SSH 端口是否正确
- 账号密码或私钥是否正确
- 目标机是否允许该来源 IP 访问 SSH
- 安全组、防火墙、路由是否放通

### 3) Debian/Ubuntu 规则不持久

需要安装并启用持久化组件：

```bash
apt install -y iptables-persistent
```

## 安全建议

- 仅在受信任网络中部署管理端
- 生产环境启用 HTTPS 与反向代理鉴权
- 定期备份 `firewall_management.db`
- 对关键账号启用强密码策略

## 参考文档

- [iptables 扩展模块文档](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [Flask 官方文档](https://flask.palletsprojects.com/)
- [Tailwind CSS 文档](https://tailwindcss.com/docs)

## 贡献

欢迎提交 Issue 和 Pull Request 改进系统功能。