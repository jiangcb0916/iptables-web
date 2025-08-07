#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/7/23 16:55
# @Author  : lsy
# @FileName: app.py
# @Software: PyCharm
# @Function:
from flask import Flask, render_template, g, jsonify, request
import sqlite3
import re
import paramiko
from paramiko.client import AutoAddPolicy
from datetime import datetime
import math
from io import StringIO

app = Flask(__name__)
ssh = paramiko.SSHClient()
DATABASE = 'firewall_management.db'
# 确保静态文件目录正确配置
app.static_folder = 'static'


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
        r'(?:\s+(?:tcp|udp)\s+(?:dpt|spt):(\d+))?'  # port
        # 匹配所有非注释的后续内容（统一作为other）
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
            comment = match.group(8) or ''
            # 提取other内容（排除注释部分）
            # 先去掉注释，再取destination之后的内容
            line_without_comment = re.sub(r'/\*.*?\*/', '', line).strip()
            # 分割出前面的固定字段
            parts = re.split(r'\s+', line_without_comment, 9)  # 分割为10个部分
            other = ' '.join(parts[9:]) if len(parts) > 9 else ''
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


# 查看规则
@app.route("/rules_in", methods=['GET'])
def rules_in():
    all_params = dict(request.args)
    host_id = all_params['id']
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key
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
        return render_template('rule.html', data_list=data_list,id=host_id)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


@app.route("/rules_out", methods=['GET'])
def rules_out():
    all_params = dict(request.args)
    host_id = all_params['id']
    try:
        # 获取数据库连接
        db = get_db()
        cursor = db.cursor()
        # 查询所有主机数据
        cursor.execute('''
        SELECT ssh_port, username, ip_address, auth_method, password, private_key
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
        return render_template('rule.html', data_list=data_list,id=host_id)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 修改规则

# 添加规则

# 删除规则

# 查看主机
# 主机管理页面路由 - 读取数据库并返回数据到前端
@app.route("/hosts", methods=['GET'])
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
def templates():
    return render_template('templates.html')


# 添加模板
# 删除模板
# 修改模板

# 系统设置
@app.route("/systemseting", methods=['GET'])
def systemseting():
    return render_template('systemseting.html')


# 操作日志
@app.route("/logs", methods=['GET'])
def logs():
    return render_template('logs.html')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80)
