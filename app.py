#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/7/23 16:55
# @Author  : lsy
# @FileName: app.py
# @Software: PyCharm
# @Function:
from functools import wraps
import sqlite3
import re
import paramiko
from paramiko.client import AutoAddPolicy
from datetime import datetime
import math
from io import StringIO
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session, abort, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import time

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # 生产环境中应使用更安全的密钥

# 配置登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # 指定登录页面的路由
login_manager.login_message = '请先登录以访问该页面'

ssh = paramiko.SSHClient()
DATABASE = 'firewall_management.db'
# 确保静态文件目录正确配置
app.static_folder = 'static'


def permission_required(permission_code):
    """权限检查装饰器"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))

            # 检查用户是否有指定权限
            if not current_user.has_permission(permission_code):
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify(success=False, message='没有操作权限')
                abort(403)  # 拒绝访问

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# 初始化数据库（创建表）
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def pwd_shell_cmd(hostname, port, user, pwd, cmd):
    try:
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname=hostname, port=port, username=user, password=pwd, timeout=5)
        # stdin, stdout, stderr = ssh.exec_command('iptables -nL IN_public_allow --line-number -t filter -v')
        stdin, stdout, stderr = ssh.exec_command(cmd)
        # stdin, stdout, stderr = ssh.exec_command('iptables -nL INPUT --line-number -t filter -v')
        # 读取输出（确保数据被完全读取）
        output = stdout.read().decode()
        error = stderr.read().decode()
        return output
    except Exception as e:
        print(f"SSH 操作失败: {e}")
    finally:
        # 先关闭流对象（关键步骤）
        if stdin:
            stdin.close()
        if stdout:
            stdout.close()
        if stderr:
            stderr.close()
        # 再关闭 SSH 连接
        if ssh:
            ssh.close()


def sshkey_shell_cmd(hostname, port, user, private_key_str, cmd):
    try:
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        key_file = StringIO(private_key_str)  # 模拟文件对象
        pkey = paramiko.RSAKey.from_private_key(key_file)  # 转换为RSA密钥对象
        ssh.connect(hostname=hostname, port=port, username=user, pkey=pkey, timeout=5,
                    look_for_keys=False,
                    allow_agent=False)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode()
        return output
    except Exception as e:
        print(f"SSH 操作失败: {e}")
    finally:
        # 再关闭 SSH 连接
        if ssh:
            ssh.close()


def get_rule(iptables_output):
    # 提取规则行（过滤掉非规则行）
    lines = [line.strip() for line in iptables_output.split('\n') if
             line.strip() and not line.startswith(('Chain', 'num'))]
    # 正确匹配完整字段顺序的正则表达式（包含in和out接口）
    pattern = re.compile(
        r'^(\d+)\s+'  # num（规则序号）
        r'(\w+)\s+'  # target
        r'(\w+)\s+'  # prot
        r'(--)\s+'  # opt
        r'([\d./*]+)\s+'  # source
        r'([\d./*]+)\s*'  # destination
        # 扩展端口匹配：支持单端口、端口范围和多端口
        r'(?:\s+(?:(?:tcp|udp)\s+(?:dpt|spt):(\d+)|'  # 单端口 (如 tcp dpt:80)
        r'(?:tcp|udp)\s+(?:dpts|spts):(\d+:\d+)|'  # 端口范围 (如 tcp dpts:90:100)
        r'multiport\s+(?:dports|sports)\s+([\d,]+)))?'  # 多端口 (如 multiport dports 90,91,92)
        r'(?:\s+(?!/\*).*?)?'  # 排除注释的所有内容
        r'(?:\s+/\*\s*(.*?)\s*\*/)?$'  # 注释
    )
    data_list = []
    for line in lines:
        match = pattern.match(line)
        if match:
            num = match.group(1)
            target = match.group(2)
            prot = match.group(3)
            source = match.group(5)
            destination = match.group(6)
            port = match.group(7) or '-1/-1'
            port_range = match.group(8) or ''
            port_mul = match.group(9) or ''
            comment = match.group(10) or ''
            # 提取other内容（排除注释部分）
            # 先去掉注释，再取destination之后的内容
            line_without_comment = re.sub(r'/\*.*?\*/', '', line).strip()
            # 分割出前面的固定字段
            parts = re.split(r'\s+', line_without_comment, 9)  # 分割为10个部分
            other = ' '.join(parts[9:]) if len(parts) > 9 else ''
            if port_range != '':
                data = {'num': num,
                        "target": target,
                        "prot": prot,
                        "source": source,
                        "destination": destination,
                        "port": port_range,
                        "comment": comment
                        }
            elif port_mul != '':
                data = {'num': num,
                        "target": target,
                        "prot": prot,
                        "source": source,
                        "destination": destination,
                        "port": port_mul,
                        "comment": comment
                        }
            else:
                data = {'num': num,
                        "target": target,
                        "prot": prot,
                        "source": source,
                        "destination": destination,
                        "port": port,
                        "comment": comment
                        }
            data_list.append(data)
        else:
            print(f"无法匹配的规则: {line}")
    return data_list


# 根路径路由：重定向到 /hosts?page=1
@app.route('/')
def index():
    # 使用 url_for 生成 hosts 路由的 URL，指定 page=1
    return redirect(url_for('hosts', page=1))


# 查看规则
@app.route("/rules_in", methods=['GET'])
@login_required
def rules_in():
    all_params = dict(request.args)
    host_id = all_params['host_id']
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key,operating_system
        FROM hosts where id = {}
        '''.format(host_id))
        # 获取所有记录
        # 1. 获取所有列名（从 cursor.description 中提取）
        columns = [column[0] for column in cursor.description]
        # 2. 将每行数据与列名配对，转换为字典
        hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        hostname = hosts[0]['ip_address']
        port = hosts[0]['ssh_port']
        user = hosts[0]['username']
        pwd = hosts[0]['password']
        auth_method = hosts[0]['auth_method']
        private_key = hosts[0]['private_key']
        if auth_method == 'password':
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -nL INPUT --line-number -t filter')
        else:
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -nL INPUT --line-number -t filter')
            print(iptables_output)
        data_list = get_rule(iptables_output)
        return render_template('rule.html', data_list=data_list, id=host_id)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


@app.route("/rules_out", methods=['GET'])
@login_required
def rules_out():
    all_params = dict(request.args)
    host_id = all_params['host_id']
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key,operating_system
        FROM hosts where id = {}
        '''.format(host_id))
        # 获取所有记录
        # 1. 获取所有列名（从 cursor.description 中提取）
        columns = [column[0] for column in cursor.description]
        # 2. 将每行数据与列名配对，转换为字典
        hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        hostname = hosts[0]['ip_address']
        port = hosts[0]['ssh_port']
        user = hosts[0]['username']
        pwd = hosts[0]['password']
        auth_method = hosts[0]['auth_method']
        private_key = hosts[0]['private_key']
        if auth_method == 'password':
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -nL OUTPUT --line-number -t filter')
        else:
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -nL OUTPUT --line-number -t filter')
        data_list = get_rule(iptables_output)
        return render_template('rule.html', data_list=data_list, id=host_id)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 修改规则
@app.route("/rules_update", methods=['POST'])
@login_required
@permission_required('iptab_edit')  # 添加规则编辑权限
def rules_update():
    all_params = request.get_json()
    host_id = all_params['host_id']
    rule_id = all_params['rule_id']
    direction = all_params['direction']
    # 获取规则的具体数据
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key,operating_system
        FROM hosts where id = {}
        '''.format(host_id))
        # 获取所有记录
        # 1. 获取所有列名（从 cursor.description 中提取）
        columns = [column[0] for column in cursor.description]
        # 2. 将每行数据与列名配对，转换为字典
        hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        hostname = hosts[0]['ip_address']
        port = hosts[0]['ssh_port']
        user = hosts[0]['username']
        pwd = hosts[0]['password']
        auth_method = hosts[0]['auth_method']
        private_key = hosts[0]['private_key']
        operating_system = hosts[0]['operating_system']
        if auth_method == 'password':
            # 删除
            pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                          cmd='iptables -D {} {}'.format(direction, rule_id))
            # 正常的tcp或udp规则
            if 'tcp' in all_params['protocol'] or 'udp' in all_params['protocol']:
                # 正常的端口
                if '-1/-1' not in all_params['port']:
                    # 添加规则中的：正常端口中的范围端口
                    if '-' in all_params['port']:
                        new_port = all_params['port'].replace("-", ":")
                        # print(new_port)
                        cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                            all_params['auth_policy'], all_params['description'])
                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}" '.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                            all_params['auth_policy'], all_params['description'])
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                            all_params['auth_policy'], all_params['description'])
                else:
                    # tcp 或udp的所有端口
                    cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                    direction, rule_id, all_params['auth_object'], all_params['protocol'],
                    all_params['auth_policy'], all_params['description'])

            # 添加
            pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                          cmd=cmd)
            if operating_system == 'centos' or operating_system == 'redhat':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
            # 查看
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -nL {} --line-number -t filter'.format(direction))

        else:
            sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                             cmd='iptables -D {} {}'.format(direction, rule_id))
            if operating_system == 'centos' or operating_system == 'redhat':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            # 正常的tcp或udp规则
            if 'tcp' in all_params['protocol'] or 'udp' in all_params['protocol']:
                # 正常的端口
                if '-1/-1' not in all_params['port']:
                    # 添加规则中的：正常端口中的范围端口
                    if '-' in all_params['port']:
                        new_port = all_params['port'].replace("-", ":")
                        print(new_port)
                        cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                            all_params['auth_policy'], all_params['description'])
                        print(cmd)
                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}" '
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                            all_params['auth_policy'], all_params['description'])
                else:
                    # tcp 或udp的所有端口
                    cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                    direction, rule_id, all_params['auth_object'], all_params['protocol'],
                    all_params['auth_policy'], all_params['description'])

            # 添加
            sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                             cmd=cmd)
            if operating_system == 'centos' or operating_system == 'redhat':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            # 查看
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -nL {} --line-number -t filter'.format(direction))
        data_list = get_rule(iptables_output)
        return render_template('rule.html', data_list=data_list, id=host_id)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 添加规则
@app.route("/rules_add", methods=['POST'])
@login_required
@permission_required('iptab_add')  # 添加规则添加权限
def rules_add():
    all_params = request.get_json()
    host_id = all_params['host_id']
    rule_id = all_params['rule_id']
    direction = all_params['direction']
    # 获取规则的具体数据
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key, operating_system
        FROM hosts where id = {}
        '''.format(host_id))
        # 获取所有记录
        # 1. 获取所有列名（从 cursor.description 中提取）
        columns = [column[0] for column in cursor.description]
        # 2. 将每行数据与列名配对，转换为字典
        hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        hostname = hosts[0]['ip_address']
        port = hosts[0]['ssh_port']
        user = hosts[0]['username']
        pwd = hosts[0]['password']
        auth_method = hosts[0]['auth_method']
        private_key = hosts[0]['private_key']
        operating_system = hosts[0]['operating_system']
        if auth_method == 'password':
            # 正常的tcp或udp规则
            if 'tcp' in all_params['protocol'] or 'udp' in all_params['protocol']:
                # 正常的端口
                if '-1/-1' not in all_params['port']:
                    # 添加规则中的：正常端口中的范围端口
                    if '-' in all_params['port']:
                        new_port = all_params['port'].replace("-", ":")
                        print(new_port)
                        cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                            all_params['auth_policy'], all_params['description'])
                        print(cmd)
                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                            all_params['auth_policy'], all_params['description'])
                        print(cmd)
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                            all_params['auth_policy'], all_params['description'])
                else:
                    # tcp 或udp的所有端口
                    cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                    direction, rule_id, all_params['auth_object'], all_params['protocol'],
                    all_params['auth_policy'], all_params['description'])

            # 添加
            pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                          cmd=cmd)
            if operating_system == 'centos' or operating_system == 'redhat':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')

            # 查看
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -nL {} --line-number -t filter'.format(direction))

        else:
            # 正常的tcp或udp规则
            if 'tcp' in all_params['protocol'] or 'udp' in all_params['protocol']:
                # 正常的端口
                if '-1/-1' not in all_params['port']:
                    # 添加规则中的：正常端口中的范围端口
                    if '-' in all_params['port']:
                        new_port = all_params['port'].replace("-", ":")
                        print(new_port)
                        cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                            all_params['auth_policy'], all_params['description'])
                        print(cmd)
                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}" '
                        print(cmd)
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                            all_params['auth_policy'], all_params['description'])
                else:
                    # tcp 或udp的所有端口
                    cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                    direction, rule_id, all_params['auth_object'], all_params['protocol'],
                    all_params['auth_policy'], all_params['description'])

            # 添加
            sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                             cmd=cmd)
            if operating_system == 'centos' or operating_system == 'redhat':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')

            # 查看
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -nL {} --line-number -t filter'.format(direction))
        data_list = get_rule(iptables_output)
        return render_template('rule.html', data_list=data_list, id=host_id)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 删除规则
@app.route("/rule_del", methods=['DELETE'])
@login_required
@permission_required('iptab_del')  # 添加规则删除权限
def del_rule():
    all_params = dict(request.args)
    host_id = all_params['host_id']
    rule_id = all_params['rule_id']
    direction = all_params['direction']
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key,operating_system
        FROM hosts where id = {}
        '''.format(host_id))
        # 获取所有记录
        # 1. 获取所有列名（从 cursor.description 中提取）
        columns = [column[0] for column in cursor.description]
        # 2. 将每行数据与列名配对，转换为字典
        hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        hostname = hosts[0]['ip_address']
        port = hosts[0]['ssh_port']
        user = hosts[0]['username']
        pwd = hosts[0]['password']
        auth_method = hosts[0]['auth_method']
        private_key = hosts[0]['private_key']
        operating_system = hosts[0]['operating_system']
        if auth_method == 'password':
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -D {} {}'.format(direction, rule_id))
            if operating_system == 'centos' or operating_system == 'redhat':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
        else:
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -D {} {}'.format(direction, rule_id))
            if operating_system == 'centos' or operating_system == 'redhat':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
        data_list = get_rule(iptables_output)
        return render_template('rule.html', data_list=data_list, id=host_id)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 查看主机
# 主机管理页面路由 - 读取数据库并返回数据到前端
@app.route("/hosts", methods=['GET'])
@login_required
@permission_required('hosts_view')  # 添加主机查看权限
def hosts():
    all_params = dict(request.args)
    page = all_params['page']
    page_size = 10
    start = (int(page) - 1) * page_size
    end = int(page) * page_size
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT id, username, auth_method, host_name, host_identifier, ip_address, 
               operating_system, created_at, ssh_port
        FROM hosts 
        ORDER BY created_at DESC
        ''')

        # 获取所有记录
        hosts = cursor.fetchall()

        # 转换为字典列表，方便前端处理
        host_list = []
        for host in hosts:
            host_list.append({
                'id': host['id'],
                'ssh_port': host['ssh_port'],
                'username': host['username'],
                'auth_method': host['auth_method'],
                'host_name': host['host_name'],
                'host_identifier': host['host_identifier'],
                'ip_address': host['ip_address'],
                'operating_system': host['operating_system'],
                'created_at': host['created_at']
            })
        # 将主机数据传递到模板
        return render_template('host.html', host_list=host_list[start:end], sum=len(host_list), start=(start + 1),
                               end=end, current_page=page, total_pages=(math.ceil(len(host_list) / 10)))
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 添加主机
@app.route('/host_add', methods=['POST'])
@login_required
@permission_required('hosts_add')  # 添加主机添加权限
def add_host():
    try:
        data = request.get_json()
        # 验证必填字段
        required_fields = ['host_name', 'host_identifier', 'ip_address', 'operating_system']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'success': False, 'message': f'缺少必填字段: {field}'}), 400

        db = get_db()
        cursor = db.cursor()

        # 插入主机数据
        cursor.execute('''
        INSERT INTO hosts 
        (host_name, host_identifier, ip_address, operating_system, ssh_port, 
         username, auth_method, password, private_key, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['host_name'],
            data['host_identifier'],
            data['ip_address'],
            data['operating_system'],
            data.get('ssh_port', 22),
            data.get('username', ''),
            data.get('auth_method', 'password'),
            data.get('password', ''),
            data.get('private_key', ''),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))

        db.commit()
        return jsonify({'success': True, 'message': '主机添加成功'})

    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': '主机标识已存在'}), 409
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# 删除主机
@app.route('/host_del', methods=['DELETE'])
@login_required
@permission_required('hosts_del')  # 添加主机删除权限
def del_host():
    host_id = request.args.get('id')
    try:
        db = get_db()
        cursor = db.cursor()
        # 删除主机
        cursor.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
        db.commit()
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'message': '主机不存在'}), 404
        return jsonify({'success': True, 'message': '主机删除成功'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# 修改主机
@app.route('/host_update', methods=['POST'])
@permission_required('hosts_edit')  # 添加主机编辑权限
@login_required
def update_host():
    data = request.get_json()
    host_id = data['id']
    try:
        db = get_db()
        cursor = db.cursor()
        # 不修改密码
        if data['password'] is None and data['private_key'] == '':
            cursor.execute(
                'UPDATE hosts SET host_name = ?, host_identifier = ?, ip_address = ?, operating_system = ?, ssh_port = ?, username = ?, updated_at = ? WHERE id = ?;',
                (data['host_name'], data['host_identifier'], data['ip_address'], data['operating_system'],
                 data['ssh_port'], data['username'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), host_id))
            db.commit()
            if cursor.rowcount == 0:
                return jsonify({'success': False, 'message': '主机不存在'}), 404
            return jsonify({'success': True, 'message': '主机编辑成功'})
        # 修改密码
        else:
            cursor.execute(
                'UPDATE hosts SET host_name = ?, host_identifier = ?, ip_address = ?, operating_system = ?, ssh_port = ?, username = ?, auth_method = ?, password = ?, private_key = ? ,updated_at = ? WHERE id = ?;',
                (data['host_name'], data['host_identifier'], data['ip_address'], data['operating_system'],
                 data['ssh_port'], data['username'], data['auth_method'], data['password'], data['private_key'],
                 datetime.now().strftime('%Y-%m-%d %H:%M:%S'), host_id))
            db.commit()
            if cursor.rowcount == 0:
                return jsonify({'success': False, 'message': '主机不存在'}), 404
            return jsonify({'success': True, 'message': '主机编辑成功'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# 查看模板
@app.route("/templates", methods=['GET'])
@login_required
def templates():
    try:
        db = get_db()
        cursor = db.cursor()
        # 查看所有的数据
        cursor.execute('SELECT * FROM templates ;')
        result = cursor.fetchall()
        temp_info = []
        for res in result:
            template_id = res['id']

            cursor.execute('SELECT * FROM rules where template_id="{}" ;'.format(template_id))
            rules_data = cursor.fetchall()

            # 这个循环是rule的规则内容了
            data_list = []
            for rule in rules_data:
                data_list.append({
                    # rules表中的数据信息
                    'rule_id': rule['id'],
                    'policy': rule['policy'],
                    'protocol': rule['protocol'],
                    'port': rule['port'],
                    'auth_object': rule['auth_object'],
                    'description': rule['description'],
                    'created_at': rule['created_at'],
                    'updated_at': rule['updated_at']
                })

            temp_info.append({'template_id': template_id,
                              'template_name': res['template_name'],
                              'direction': res['direction'],
                              'template_identifier': res['template_identifier'],
                              'updated_at': res['updated_at'],
                              'rules': data_list,
                              })
            # print(temp_info)
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': '模板名称已存在'}), 409
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    return render_template('templates.html', data_list=temp_info)


# 添加模板
@app.route("/temp_add", methods=['POST'])
@login_required
def templates_add():
    try:
        data = request.get_json()
        # print(data)
        db = get_db()
        cursor = db.cursor()
        # 插入主机数据
        cursor.execute('''
        INSERT INTO templates 
        (template_name, template_identifier, direction,created_at, updated_at)
        VALUES (?, ?, ?, ?,?)
        ''', (
            data['name'],
            data['description'],
            data['direction'],
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))
        # 查询templat_id
        cursor.execute('SELECT id FROM templates ORDER BY id DESC LIMIT 1;')
        result = cursor.fetchone()
        if result:
            # 结果是元组，取第一个元素（即 ID）
            template_id = result[0]
        else:
            # 表中没有数据时返回 None 或提示
            template_id = 1

        for rule in data['rules']:
            if rule['policy'] == '允许':
                policy = 'ACCEPT'
            else:
                policy = 'DROP'
            cursor.execute('''
            INSERT INTO rules 
            (template_id, policy, protocol, port,auth_object,description,created_at,updated_at)
            VALUES (?, ?, ?, ?,?, ?, ?,?)
            ''', (
                template_id,
                policy,
                rule['protocol'],
                rule['port'],
                rule['auth_object'],
                rule['description'],
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ))

            db.commit()
        return jsonify({'success': True, 'message': '模板添加成功'})

    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': '模板名称已存在'}), 409
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# 删除模板
@app.route("/temp_del", methods=['DELETE'])
@login_required
def templates_del():
    template_id = request.args.get('temp_id')
    try:
        db = get_db()
        cursor = db.cursor()
        # 删除主机
        cursor.execute('DELETE FROM templates WHERE id = ?', (template_id,))
        cursor.execute('DELETE FROM rules WHERE template_id = ?', (template_id,))

        db.commit()
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'message': '模板不存在'}), 404
        return jsonify({'success': True, 'message': '模板删除成功'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# 修改模板
@app.route("/temp_edit", methods=['POST'])
@login_required
def templates_edit():
    try:
        data = request.get_json()
        db = get_db()
        cursor = db.cursor()
        # 修改模板信息
        cursor.execute('''
        UPDATE  templates set template_name = ?, template_identifier = ?, direction = ?, updated_at =? WHERE id = ?;
        ''', (
            data['name'],
            data['description'],
            data['direction'],
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            data['temp_id']
        ))
        # 先删除旧规则
        cursor.execute('DELETE FROM rules WHERE template_id = ?', (data['temp_id'],))
        for rule in data['rules']:
            if rule['policy'] == '允许':
                policy = 'ACCEPT'
            else:
                policy = 'DROP'
            # 添加新规则
            cursor.execute('''
            INSERT INTO rules 
            (template_id, policy, protocol, port,auth_object,description,created_at,updated_at)
            VALUES (?, ?, ?, ?,?, ?, ?,?)
            ''', (
                data['temp_id'],
                policy,
                rule['protocol'],
                rule['port'],
                rule['auth_object'],
                rule['description'],
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ))

            db.commit()
        return jsonify({'success': True, 'message': '模板修改成功'})

    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': '模板名称不存在'}), 409
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# 应用模板获取主机列表
@app.route("/temp_host_api", methods=['GET'])
@login_required
def temp_host_api():
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT id, host_identifier
        FROM hosts 
        ORDER BY created_at DESC
        ''')
        # 获取所有记录
        hosts = cursor.fetchall()

        # 转换为字典列表，方便前端处理
        host_list = []
        for host in hosts:
            host_list.append({
                'id': host['id'],
                'host_name': host['host_identifier']
            })
        # 返回JSON格式数据
        return jsonify({
            'success': True,
            'data': host_list
        })
    except Exception as e:
        # 错误处理，同样返回JSON格式
        return jsonify({
            'success': False,
            'message': f"获取主机数据失败: {str(e)}"
        }), 500


# 应用模板
@app.route("/temp_to_hosts", methods=['POST'])
@login_required
@permission_required('iptab_add')
def temp_to_hosts():
    all_params = request.get_json()
    print(all_params)
    template_id = all_params['template_id']
    host_ids_list = all_params['host_ids']
    # 获取模板的规则
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 获取模板的方向
        cursor.execute(''' select direction from templates  where id = {} ;'''.format(template_id))
        direction_data = cursor.fetchone()
        direction = direction_data[0]
        # 查询所有主机数据
        cursor.execute('''SELECT * FROM  rules
        where template_id = {}
        '''.format(template_id))
        # 获取所有记录
        temp_data = cursor.fetchall()
        cmd_list = []
        for rule in temp_data:
            print(rule['port'])
            # 正常的tcp或udp规则
            if 'tcp' in rule['protocol'].lower() or 'udp' in rule['protocol'].lower():
                # 正常的端口
                if '-1/-1' not in rule['port']:
                    # 添加规则中的：正常端口中的范围端口
                    if '-' in rule['port']:
                        new_port = rule['port'].replace("-", ":")
                        # print(new_port)
                        cmd = 'iptables -A {}  -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule['auth_object'], rule['protocol'], new_port,
                            rule['policy'], rule['description'])
                        cmd_list.append(cmd)
                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in rule['port']:
                        cmd = 'iptables -A {}  -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}" '.format(
                            direction, rule['auth_object'], rule['protocol'],
                            rule['port'],
                            rule['policy'], rule['description'])
                        cmd_list.append(cmd)
                    else:
                        cmd = 'iptables -A {}  -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule['auth_object'], rule['protocol'],
                            rule['port'],
                            rule['policy'], rule['description'])
                        cmd_list.append(cmd)
                else:
                    # tcp 或udp的所有端口
                    cmd = 'iptables -A {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                        direction, rule['auth_object'], rule['protocol'],
                        rule['policy'], rule['description'])
                    cmd_list.append(cmd)
            # ICMP 或 all 协议的规则
            else:
                cmd = 'iptables -A {}  -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                    direction, rule['auth_object'], rule['protocol'],
                    rule['policy'], rule['description'])
                cmd_list.append(cmd)
        # 获取主机的信息
        for host_id in host_ids_list:
            # 查询所有主机数据
            cursor.execute('''
            SELECT ssh_port, username, ip_address, auth_method, password, private_key, operating_system
            FROM hosts where id = {}
            '''.format(host_id))
            # 获取所有记录
            # 1. 获取所有列名（从 cursor.description 中提取）
            columns = [column[0] for column in cursor.description]
            # 2. 将每行数据与列名配对，转换为字典
            hosts = [dict(zip(columns, row)) for row in cursor.fetchall()]
            hostname = hosts[0]['ip_address']
            port = hosts[0]['ssh_port']
            user = hosts[0]['username']
            pwd = hosts[0]['password']
            auth_method = hosts[0]['auth_method']
            private_key = hosts[0]['private_key']
            operating_system = hosts[0]['operating_system']
            if auth_method == 'password':
                for cmd in cmd_list:
                    pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                  cmd=cmd)
                    if operating_system == 'centos' or operating_system == 'redhat':
                        pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                      cmd='iptables-save > /etc/sysconfig/iptables')
                    elif operating_system == 'debian':
                        pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                      cmd='iptables-save > /etc/iptables/rules.v4')
                    elif operating_system == 'ubuntu':
                        pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                      cmd='iptables-save > /etc/iptables/rules.v4')
            else:
                for cmd in cmd_list:
                    sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                     cmd=cmd)
                    if operating_system == 'centos' or operating_system == 'redhat':
                        sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                         cmd='iptables-save > /etc/sysconfig/iptables')
                    elif operating_system == 'debian':
                        sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                         cmd='iptables-save > /etc/iptables/rules.v4')
                    elif operating_system == 'ubuntu':
                        sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                         cmd='iptables-save > /etc/iptables/rules.v4')
        # 将规则添加到主机上

        return jsonify({
            'success': True,
            'message': "成功"
        })

    except Exception as e:
        # 错误处理，同样返回JSON格式
        return jsonify({
            'success': False,
            'message': f"获取主机数据失败: {str(e)}"
        }), 500


# 系统设置
@app.route("/systemseting", methods=['GET'])
@login_required
@permission_required('sys_view')  # 添加系统设置查看权限
def systemseting():
    return render_template('systemseting.html')


# 系统配置接口
@app.route('/api/system-config', methods=['GET', 'POST'])
def get_system_config():
    if request.method == "GET":
        @permission_required('sys_view')
        def get_config():
            try:

                db = get_db()
                config = db.execute('SELECT * FROM system_config ORDER BY id DESC LIMIT 1').fetchone()
                print(dict(config))
                return jsonify(dict(config)) if config else jsonify({})
            except Exception as e:
                app.logger.error(f"获取系统配置失败: {str(e)}")
                return jsonify({'error': '获取系统配置失败'}), 500
    else:
        @permission_required('sys_edit')
        def update_config():
            try:
                data = request.get_json()
                db = get_db()
                cursor = db.cursor()
                system_name = data['system_name']
                default_session_timeout = data['default_session_timeout']
                log_retention_time = data['log_retention_days']
                color_mode = data['color_mode']
                password_strategy = data['password_strategy']
                updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                # 更新system_config 表
                cursor.execute(
                    ''' update system_config  set system_name = ?, session_timeout = ?, log_retention_time = ?, color_mode = ?,password_strategy = ?, updated_at = ?  where id=1; ''',
                    (
                        system_name, default_session_timeout, log_retention_time, color_mode, password_strategy, updated_at
                    ))
                db.commit()
                return jsonify({'success': True, 'message': '保存系统配置成功'})
            except Exception as e:
                app.logger.error(f"保存系统配置失败: {str(e)}")
                return jsonify({'error': '保存系统配置失败'}), 500


# 获取会话超时时间（从数据库）
def get_session_timeout():
    """从数据库获取会话超时时间（分钟），默认30分钟"""
    try:
        db = get_db()
        config = db.execute('SELECT session_timeout FROM system_config ORDER BY id DESC LIMIT 1').fetchone()
        if config and config['session_timeout'] is not None:
            return int(config['session_timeout'])
        return 30  # 默认值
    except Exception as e:
        app.logger.error(f"获取会话超时时间失败: {str(e)}")
        return 30  # 异常时使用默认值


# 添加请求前钩子，检查会话超时
@app.before_request
def check_session_timeout():
    """在每个请求前检查会话是否超时"""
    # 排除登录页面，避免循环重定向
    if request.path == '/login':
        return

    # 仅对已登录用户检查超时
    if current_user.is_authenticated:
        # 获取会话创建时间（首次访问时初始化）
        if 'created_at' not in session:
            session['created_at'] = time.time()  # <-- 添加默认值
        created_at = session['created_at']
        timeout_seconds = get_session_timeout() * 60
        current_time = time.time()

        # 检查是否超时
        if current_time - created_at > timeout_seconds:
            logout_user()
            session.clear()  # 清除会话数据
            flash('会话已超时，请重新登录', 'info')
            return redirect(url_for('login'))

        # 更新会话活动时间（实现"空闲超时"机制）
        session['created_at'] = current_time


# 用户类
class User(UserMixin):
    def __init__(self, user_id, username, roles=None):
        self.id = user_id
        self.username = username
        self.roles = roles or []  # 存储用户拥有的角色列表

    def has_permission(self, permission_code):
        """检查用户是否拥有指定权限"""
        db = get_db()
        try:
            cursor = db.cursor()
            # 通过三表关联查询用户是否拥有权限
            cursor.execute('''
            SELECT 1 FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            JOIN user_roles ur ON rp.role_id = ur.role_id
            WHERE ur.user_id = ? AND p.code = ?
            LIMIT 1
            ''', (self.id, permission_code))
            return cursor.fetchone() is not None
        except Exception as e:
            app.logger.error(f"权限检查失败: {str(e)}")
            return False


# 加载用户回调函数
@login_manager.user_loader
def load_user(user_id):
    """从数据库加载用户信息，包括用户角色"""
    db = get_db()
    try:
        # 查询用户基本信息
        user = db.execute('SELECT id, username, status FROM user WHERE id = ?',
                          (user_id,)).fetchone()
        if not user or user['status'] != 'active':
            return None

        # 查询用户角色
        roles = db.execute('''
        SELECT r.id, r.role_name FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
        ''', (user_id,)).fetchall()

        return User(
            user_id=user['id'],
            username=user['username'],
            roles=[{'id': r['id'], 'name': r['role_name']} for r in roles]
        )
    except Exception as e:
        app.logger.error(f"加载用户失败: {str(e)}")
        return None


# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=True, redirect_url=url_for('hosts', page=1))
        return redirect(url_for('hosts', page=1))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        # 从数据库查询用户
        db = get_db()
        user_data = db.execute('SELECT id, username, password, status FROM user WHERE username = ?',
                               (username,)).fetchone()

        if not user_data:
            return jsonify(success=False, message='用户名不存在') if request.headers.get(
                'X-Requested-With') == 'XMLHttpRequest' else \
                render_template('login.html', error='用户名不存在')

        if user_data['status'] != 'active':
            return jsonify(success=False, message='用户已被禁用') if request.headers.get(
                'X-Requested-With') == 'XMLHttpRequest' else \
                render_template('login.html', error='用户已被禁用')

        if not check_password_hash(user_data['password'], password):
            return jsonify(success=False, message='密码不正确') if request.headers.get(
                'X-Requested-With') == 'XMLHttpRequest' else \
                render_template('login.html', error='密码不正确')

        # 加载用户角色信息
        user = load_user(user_data['id'])
        session['created_at'] = time.time()
        login_user(user, remember=remember)

        return jsonify(success=True, redirect_url=url_for('hosts', page=1)) if request.headers.get(
            'X-Requested-With') == 'XMLHttpRequest' else \
            redirect(url_for('hosts', page=1))

    return render_template('login.html')


@app.route('/users', methods=['GET', 'POST'])
@login_required
@permission_required('user_view')
def users():
    # 如果是查看用户管理页面
    if request.method == "GET":
        @permission_required('user_view')
        def get_users():
            try:
                db = get_db()
                cursor = db.cursor()
                # 查询用户基本信息及关联的角色
                cursor.execute(''' 
                SELECT u.id, u.username, u.email, u.status, u.created_at,
                       GROUP_CONCAT(r.role_name, ', ') as roles
                FROM user u
                LEFT JOIN user_roles ur ON u.id = ur.user_id
                LEFT JOIN roles r ON ur.role_id = r.id
                GROUP BY u.id
                ''')
                data = cursor.fetchall()
                user_list = []
                for i in data:
                    user_dict = {
                        'id': i['id'],
                        'roles': i['roles'] if i['roles'] else 'None',
                        'username': i['username'],
                        'email': i['email'],
                        'status': i['status'],
                        'created_at': i['created_at']
                    }
                    user_list.append(user_dict)
                print(user_list)
                return render_template('systemseting.html', user_list=user_list)
            except Exception as e:
                print(e)
                # 添加异常情况下的响应
                return jsonify({
                    "success": False,
                    "message": f"获取用户列表失败: {str(e)}"
                }), 500
    # 如果是添加用户
    elif request.method == 'POST':
        db = get_db()
        @permission_required('user_add')
        def add_user():
            try:
                # 获取JSON数据而非表单数据
                user_data = request.get_json()
                print(user_data)
                if not user_data:
                    return jsonify({
                        "success": False,
                        "message": "未收到数据，请检查请求格式"
                    }), 400

                cursor = db.cursor()
                # 从JSON数据中获取字段并验证
                username = user_data.get('username')
                password = user_data.get('password')
                email = user_data.get('email')
                status = user_data.get('status', 'active')  # 默认状态为active
                # 【新增】获取角色ID并验证
                role_id = user_data.get('role')
                if not role_id:
                    return jsonify({
                        "success": False,
                        "message": "角色为必填项"
                    }), 400
                try:
                    role_id = int(role_id)  # 转换为整数
                except ValueError:
                    return jsonify({
                        "success": False,
                        "message": "无效的角色ID格式"
                    }), 400

                # 验证必填字段
                if not username or not password or not email:
                    return jsonify({
                        "success": False,
                        "message": "用户名、密码和邮箱为必填项"
                    }), 400

                # 密码哈希处理
                hashed_password = generate_password_hash(password)
                cursor.execute(''' 
                INSERT INTO user
                (username, password, email, status, created_at)
                VALUES (?, ?, ?, ?, ?)
                 ''', (
                    username,
                    hashed_password,  # 使用哈希后的密码
                    email,
                    status,
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))

                # 【新增】获取新创建用户的ID
                user_id = cursor.lastrowid

                # 【新增】插入用户-角色关联记录
                cursor.execute('''
                INSERT INTO user_roles (user_id, role_id)
                VALUES (?, ?)
                ''', (user_id, role_id))

                # 【修改】统一提交事务（用户表和关联表一起提交）
                db.commit()

                return jsonify({
                    "success": True,
                    "message": "用户添加成功！"
                }), 200

            except sqlite3.IntegrityError as e:
                print(e)
                db.rollback()
                return jsonify({
                    "success": False,
                    "message": "用户名或邮箱已存在，请更换！"
                }), 409
            except Exception as e:
                print(e)
                if 'db' in locals():
                    db.rollback()
                return jsonify({
                    "success": False,
                    "message": f"添加失败：{str(e)}"
                }), 500


@app.route('/user_edit', methods=['GET', 'POST'])
@login_required
@permission_required('user_edit')
def user_edit():
    if request.method == 'GET':
        user_id = request.args.get('id')
        try:
            db = get_db()
            cursor = db.cursor()
            # 获取用户信息
            cursor.execute('SELECT id, username, email, status FROM user WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({'success': False, 'message': '用户不存在'}), 404
            # 获取所有角色
            cursor.execute('SELECT id, role_name FROM roles')
            roles = cursor.fetchall()
            # 获取用户已分配的角色
            cursor.execute('SELECT role_id FROM user_roles WHERE user_id = ?', (user_id,))
            user_roles = [row['role_id'] for row in cursor.fetchall()]
            return jsonify({
                'success': True,
                'user': dict(user),
                'roles': [dict(role) for role in roles],
                'user_roles': user_roles
            })
        except Exception as e:
            return jsonify({'success': False, 'message': f"获取用户信息失败: {str(e)}"}), 500
    elif request.method == 'POST':
        # 打印请求数据
        data = request.get_json()
        print("0"*100)
        print(data)
        user_id = data['id']
        db = get_db()
        try:
            cursor = db.cursor()
            # 获取用户当前信息，用于处理部分更新情况（添加status字段）
            cursor.execute('SELECT username, email, status FROM user WHERE id = ?', (user_id,))
            current_user = cursor.fetchone()
            if not current_user:
                return jsonify({'success': False, 'message': '用户不存在'}), 404
            # 提取数据，如未提供则使用当前信息
            username = data.get('username', current_user['username'])
            email = data.get('email', current_user['email'])
            status = data.get('status', current_user['status'])  # 默认为当前状态
            # 更新用户基本信息
            if 'password' in data and data['password']:
                # 如果提供了新密码，则更新密码
                hashed_password = generate_password_hash(data['password'])
                cursor.execute('''
                        UPDATE user SET username = ?, email = ?, status = ?, password = ? 
                        WHERE id = ?
                        ''', (username, email, status, hashed_password, user_id))
            else:
                # 不更新密码
                cursor.execute('''
                        UPDATE user SET username = ?, email = ?, status = ? 
                        WHERE id = ?
                        ''', (username, email, status, user_id))
            # 处理角色分配（如果提供了角色数据）
            if 'role' in data:
                # 删除用户现有角色
                cursor.execute('DELETE FROM user_roles WHERE user_id = ?', (user_id,))
                # 分配新角色
                roles = data.get('role', [])
                if roles:
                    cursor.executemany('''
                            INSERT INTO user_roles (user_id, role_id)
                            VALUES (?, ?)
                            ''', [(user_id, role_id) for role_id in roles])
            db.commit()
            return jsonify({'success': True, 'message': '用户更新成功'})
        except sqlite3.IntegrityError:
            db.rollback()
            return jsonify({'success': False, 'message': '用户名或邮箱已存在'}), 409
        except Exception as e:
            db.rollback()
            return jsonify({'success': False, 'message': f"更新用户失败: {str(e)}"}), 500


@app.route('/user_del', methods=['DELETE'])
@login_required
@permission_required('user_del')
def user_del():
    user_id = request.args.get('id')
    # 防止删除自己
    if int(user_id) == current_user.id:
        return jsonify({'success': False, 'message': '不能删除当前登录用户'}), 400
    db = get_db()
    try:
        cursor = db.cursor()
        # 删除用户角色关联
        cursor.execute('DELETE FROM user_roles WHERE user_id = ?', (user_id,))
        # 删除用户
        cursor.execute('DELETE FROM user WHERE id = ?', (user_id,))
        if cursor.rowcount == 0:
            db.rollback()
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        db.commit()
        return jsonify({'success': True, 'message': '用户删除成功'})
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': f"删除用户失败: {str(e)}"}), 500


@app.route('/user/<int:user_id>/roles', methods=['POST'])
@login_required
@permission_required('user_assign')
def assign_user_roles(user_id):
    data = request.get_json()
    roles = data['roles']
    db = get_db()
    try:
        cursor = db.cursor()
        # 先删除现有角色
        cursor.execute('DELETE FROM user_roles WHERE user_id = ?', (user_id,))
        # 分配新角色
        if roles:
            cursor.executemany('''
            INSERT INTO user_roles (user_id, role_id)
            VALUES (?, ?)
            ''', [(user_id, role_id) for role_id in roles])
        db.commit()
        return jsonify({'success': True, 'message': '角色分配成功'})
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': f"角色分配失败: {str(e)}"}), 500


@app.route('/roles', methods=['GET', 'POST'])
@login_required
@permission_required('role_view')  # 角色管理需要role_view权限
def roles():
    if request.method == 'GET':
        db = get_db()
        try:
            # 获取所有角色
            cursor = db.cursor()
            cursor.execute(''' SELECT id, role_name, role_description, created_at, updated_at FROM roles''')
            roles = cursor.fetchall()

            role_list = []
            for role in roles:
                # 获取角色拥有的权限
                cursor.execute('''
                SELECT p.code FROM permissions p
                JOIN role_permissions rp ON p.id = rp.permission_id
                WHERE rp.role_id = ?
                ''', (role['id'],))
                permissions = [row['code'] for row in cursor.fetchall()]

                # 新增：查询角色关联的用户数量
                cursor.execute('''
                SELECT COUNT(DISTINCT ur.user_id) as user_count
                FROM user_roles ur
                LEFT JOIN user u ON ur.user_id = u.id
                WHERE ur.role_id = ?
                ''', (role['id'],))
                user_count = cursor.fetchone()['user_count'] or 0

                role_list.append({
                    'id': role['id'],
                    'role_name': role['role_name'],
                    'role_description': role['role_description'],
                    'permissions': permissions,  # 返回角色拥有的权限列表
                    'user_count': user_count,  # 新增：角色关联用户数量
                    'created_at': role['created_at'],
                    'updated_at': role['updated_at']
                })
            # 【新增】根据请求头判断返回 JSON 还是渲染页面
            if request.headers.get('Accept') == 'application/json':
                return jsonify({
                    'success': True,
                    'roles': role_list  # 返回角色列表 JSON 数据
                })
            else:
                # 原逻辑：渲染角色管理页面
                return render_template('systemseting.html', role_list=role_list)
        except Exception as e:
            return jsonify({"success": False, "message": f"获取角色失败：{str(e)}"}), 500

    elif request.method == 'POST':
        # 添加新角色 (需要role_add权限)
        if not current_user.has_permission('role_add'):
            return jsonify(success=False, message='没有添加角色权限'), 403
        db = get_db()
        try:
            # 获取JSON数据（而非表单数据）
            role_data = request.get_json()
            if not role_data:
                return jsonify({"success": False, "message": "请求数据格式错误，应为JSON"}), 400
            cursor = db.cursor()

            # 创建角色 - 使用role_data而非request.form

            cursor.execute(''' 
                INSERT INTO roles (role_name, role_description, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                 ''', (
                role_data.get('role_name'),  # <-- 修复：从JSON数据获取
                role_data.get('role_description', ''),  # <-- 修复：从JSON数据获取，提供默认值
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ))
            role_id = cursor.lastrowid
            # 分配权限 - 同样从JSON数据获取
            permissions = role_data.get('permissions', [])  # <-- 修复：从JSON数据获取

            if permissions:
                cursor.executemany('''
                    INSERT INTO role_permissions (role_id, permission_id)
                    VALUES (?, ?)
                    ''', [(role_id, p) for p in permissions])
            db.commit()
            return jsonify({"success": True, "message": "角色添加成功！"}), 200
        except Exception as e:
            db.rollback()
            return jsonify({"success": False, "message": f"错误：{str(e)}"}), 500


@app.route('/role_edit', methods=['GET', 'POST'])
@login_required
@permission_required('role_edit')
def role_edit():
    if request.method == 'GET':
        role_id = request.args.get('id')
        try:
            db = get_db()
            cursor = db.cursor()

            # 获取角色信息
            cursor.execute('SELECT id, role_name, role_description FROM roles WHERE id = ?', (role_id,))
            role = cursor.fetchone()

            if not role:
                return jsonify({'success': False, 'message': '角色不存在'}), 404

            # 获取角色权限
            cursor.execute('''
            SELECT p.id FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = ?
            ''', (role_id,))
            permissions = [row['id'] for row in cursor.fetchall()]

            return jsonify({
                'success': True,
                'role': dict(role),
                'permissions': permissions
            })
        except Exception as e:
            return jsonify({'success': False, 'message': f"获取角色信息失败: {str(e)}"}), 500

    elif request.method == 'POST':
        data = request.get_json()
        role_id = data['id']
        db = get_db()
        try:
            cursor = db.cursor()

            # 更新角色信息
            cursor.execute('''
            UPDATE roles SET role_name = ?, role_description = ?, updated_at = ?
            WHERE id = ?
            ''', (
                data['role_name'],
                data['role_description'],
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                role_id
            ))

            # 如果有提交权限，则更新权限
            if 'permissions' in data:
                # 先删除现有权限
                cursor.execute('DELETE FROM role_permissions WHERE role_id = ?', (role_id,))

                # 添加新权限
                permissions = data['permissions']
                if permissions:
                    cursor.executemany('''
                    INSERT INTO role_permissions (role_id, permission_id)
                    VALUES (?, ?)
                    ''', [(role_id, p) for p in permissions])

            db.commit()
            return jsonify({'success': True, 'message': '角色更新成功'})

        except sqlite3.IntegrityError:
            db.rollback()
            return jsonify({'success': False, 'message': '角色名称已存在'}), 409
        except Exception as e:
            db.rollback()
            return jsonify({'success': False, 'message': f"更新角色失败: {str(e)}"}), 500


@app.route('/role_del', methods=['DELETE'])
@login_required
@permission_required('role_del')
def role_del():
    role_id = request.args.get('id')
    print(role_id)
    # 防止删除管理员角色
    if int(role_id) == 1:
        return jsonify({'success': False, 'message': '不能删除默认管理员角色'}), 400
    db = get_db()
    try:
        cursor = db.cursor()
        # 检查是否有关联用户
        cursor.execute('SELECT COUNT(*) as count FROM user_roles WHERE role_id = ?', (role_id,))
        count = cursor.fetchone()['count']
        if count > 0:
            db.rollback()
            return jsonify({'success': False, 'message': f'该角色已分配给{count}个用户，请先移除用户关联'}), 400

        # 删除角色权限关联
        cursor.execute('DELETE FROM role_permissions WHERE role_id = ?', (role_id,))

        # 删除角色
        cursor.execute('DELETE FROM roles WHERE id = ?', (role_id,))

        if cursor.rowcount == 0:
            db.rollback()
            return jsonify({'success': False, 'message': '角色不存在'}), 404

        db.commit()
        return jsonify({'success': True, 'message': '角色删除成功'})

    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': f"删除角色失败: {str(e)}"}), 500


@app.route('/roles/<int:role_id>/permissions', methods=['GET', 'POST'])
@login_required
@permission_required('role_assign')  # 分配权限需要role_assign权限
def role_permissions(role_id):
    db = get_db()
    if request.method == 'GET':
        # 获取角色当前拥有的权限
        cursor = db.cursor()
        cursor.execute('''
        SELECT p.id, p.code, p.name, 
               (SELECT 1 FROM role_permissions rp WHERE rp.role_id = ? AND rp.permission_id = p.id) as has_perm
        FROM permissions p
        ''', (role_id,))
        permissions = cursor.fetchall()
        return jsonify({
            "success": True,
            "permissions": [dict(perm) for perm in permissions]
        })

    elif request.method == 'POST':
        # 更新角色权限
        permissions = request.json.get('permissions', [])
        print(permissions)
        cursor = db.cursor()

        try:
            # 先删除现有权限
            cursor.execute('DELETE FROM role_permissions WHERE role_id = ?', (role_id,))

            # 添加新权限
            if permissions:
                cursor.executemany('''
                INSERT INTO role_permissions (role_id, permission_id)
                VALUES (?, ?)
                ''', [(role_id, p) for p in permissions])

            db.commit()
            return jsonify({"success": True, "message": "权限分配成功！"})
        except Exception as e:
            db.rollback()
            return jsonify({"success": False, "message": f"权限分配失败：{str(e)}"}), 500


# 操作日志
@app.route("/logs", methods=['GET'])
@login_required
@permission_required('log_view')
def logs():
    return render_template('logs.html')


# 注销路由
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功注销', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2025)
