#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/7/25 17:23
# @Author  : lsy
# @FileName: test.py
# @Software: PyCharm
# @Function:
from flask import Flask, request, jsonify, g
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
DATABASE = 'firewall_management.db'


# 数据库连接函数
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


# 主机API路由
@app.route('/api/hosts', methods=['POST'])
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


@app.route('/api/hosts/<int:host_id>', methods=['DELETE'])
def delete_host(host_id):
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


if __name__ == '__main__':
    # 确保数据库文件存在
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)