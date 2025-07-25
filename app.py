#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/7/23 16:55
# @Author  : lsy
# @FileName: app.py
# @Software: PyCharm
# @Function:
from flask import Flask, render_template
import sqlite3
import re
import paramiko
from paramiko.client import AutoAddPolicy

app = Flask(__name__)
ssh = paramiko.SSHClient()

user = 'root'
port = 22
pwd = 'pwd'


def shell_cmd(cmd):
    try:
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(hostname='10.0.0.11', port=port, username=user, password=pwd, timeout=10)
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
@app.route("/rules", methods=['GET'])
def index():
    iptables_output = shell_cmd(cmd='iptables -nL INPUT --line-number -t filter')
    data_list = get_rule(iptables_output)
    return render_template('rule.html', data_list=data_list)


# 修改规则
# 添加规则
# 删除规则

# 查看主机
@app.route("/hosts", methods=['GET'])
def hosts():
    return render_template('host.html')


# 添加主机
# 删除主机
# 修改主机

# 查看模板
@app.route("/templates", methods=['GET'])
def hosts():
    return render_template('templates.html')


# 添加模板
# 删除模板
# 修改模板

# 系统设置
@app.route("/systemseting", methods=['GET'])
def hosts():
    return render_template('systemseting.html')


# 操作日志
@app.route("/logs", methods=['GET'])
def hosts():
    return render_template('logs.html')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=80)
