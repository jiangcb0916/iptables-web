#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/7/23 16:55
# @Author  : lsy
# @FileName: app.py
# @Software: PyCharm
# @Function:
import random
from functools import wraps
import sqlite3
import re
import ipaddress
import uuid
import socket
import platform
import subprocess
import os
import shlex
import base64
import hashlib
import secrets
import hmac
import csv
import threading
import tempfile
import fcntl
from contextlib import contextmanager
import paramiko
from paramiko.client import AutoAddPolicy
from paramiko.ssh_exception import PasswordRequiredException, SSHException, AuthenticationException
import math
from io import StringIO
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session, g, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
import time
import json
from flask_apscheduler import APScheduler
from datetime import datetime, timedelta
import pytz

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
USE_LOCAL_FILE_STORE = os.getenv('USE_LOCAL_FILE_STORE', '1').strip().lower() not in ('0', 'false', 'no')
LOCAL_STORE_DIR = os.path.join(app.root_path, 'data', 'store')
HOSTS_STORE_FILE = os.path.join(LOCAL_STORE_DIR, 'hosts.json')
OPERATION_LOG_STORE_FILE = os.path.join(LOCAL_STORE_DIR, 'operation_logs.json')
USERS_STORE_FILE = os.path.join(LOCAL_STORE_DIR, 'users.json')
ROLES_STORE_FILE = os.path.join(LOCAL_STORE_DIR, 'roles.json')
SYSTEM_CONFIG_STORE_FILE = os.path.join(LOCAL_STORE_DIR, 'system_config.json')
TEMPLATES_STORE_FILE = os.path.join(LOCAL_STORE_DIR, 'templates.json')
SSH_KEY_RECORDS_STORE_FILE = os.path.join(LOCAL_STORE_DIR, 'ssh_key_setup_records.json')
PORT_SCAN_STORE_FILE = os.path.join(LOCAL_STORE_DIR, 'port_scan_records.json')
FIREWALL_RULE_STORE_FILE = os.path.join(LOCAL_STORE_DIR, 'firewall_rules.json')
PORT_RULES_STORE_FILE = os.path.join(app.root_path, 'data', 'rules.json')
_STORE_THREAD_LOCK = threading.RLock()

DEFAULT_PERMISSION_CODES = [
    'sys_view', 'sys_edit',
    'user_view', 'user_add', 'user_edit', 'user_del', 'user_assign',
    'role_view', 'role_add', 'role_edit', 'role_assign', 'role_del',
    'temp_view', 'temp_add', 'temp_edit', 'temp_del',
    'hosts_view', 'hosts_add', 'hosts_edit', 'hosts_del',
    'iptab_view', 'iptab_add', 'iptab_edit', 'iptab_del',
    'log_view',
    'ssh_key_manage'
]
PERMISSION_DEFINITIONS = [
    {"id": 1, "code": "sys_view", "name": "查看系统设置"},
    {"id": 2, "code": "sys_edit", "name": "编辑系统设置"},
    {"id": 3, "code": "user_view", "name": "查看用户列表"},
    {"id": 4, "code": "user_add", "name": "添加用户"},
    {"id": 5, "code": "user_edit", "name": "编辑用户"},
    {"id": 6, "code": "user_del", "name": "删除用户"},
    {"id": 7, "code": "user_assign", "name": "分配用户角色"},
    {"id": 8, "code": "role_view", "name": "查看角色"},
    {"id": 9, "code": "role_add", "name": "添加角色"},
    {"id": 10, "code": "role_edit", "name": "编辑角色"},
    {"id": 11, "code": "role_assign", "name": "分配角色权限"},
    {"id": 12, "code": "role_del", "name": "删除角色"},
    {"id": 13, "code": "temp_view", "name": "查看模板"},
    {"id": 14, "code": "temp_add", "name": "添加模板"},
    {"id": 15, "code": "temp_edit", "name": "编辑模板"},
    {"id": 16, "code": "temp_del", "name": "删除模板"},
    {"id": 17, "code": "hosts_view", "name": "查看主机"},
    {"id": 18, "code": "hosts_add", "name": "添加主机"},
    {"id": 19, "code": "hosts_edit", "name": "编辑主机"},
    {"id": 20, "code": "hosts_del", "name": "删除主机"},
    {"id": 21, "code": "iptab_view", "name": "查看规则"},
    {"id": 22, "code": "iptab_add", "name": "添加规则"},
    {"id": 23, "code": "iptab_edit", "name": "编辑规则"},
    {"id": 24, "code": "iptab_del", "name": "删除规则"},
    {"id": 25, "code": "log_view", "name": "查看日志"},
    {"id": 26, "code": "ssh_key_manage", "name": "管理SSH密钥"}
]

# 配置登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '请先登录以访问该页面'

ssh = paramiko.SSHClient()
DATABASE = 'firewall_management.db'
# 确保静态文件目录正确配置
app.static_folder = 'static'

# 新增：初始化调度器
scheduler = APScheduler()


def _clone_default(value):
    if isinstance(value, (dict, list)):
        return json.loads(json.dumps(value))
    return value


@contextmanager
def _store_lock(path):
    lock_path = f"{path}.lock"
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with open(lock_path, 'a+', encoding='utf-8') as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _ensure_local_store_files():
    if not USE_LOCAL_FILE_STORE:
        return
    os.makedirs(LOCAL_STORE_DIR, exist_ok=True)
    if not os.path.exists(HOSTS_STORE_FILE):
        _write_store_json(HOSTS_STORE_FILE, {"items": []})
    if not os.path.exists(OPERATION_LOG_STORE_FILE):
        _write_store_json(OPERATION_LOG_STORE_FILE, {"items": []})
    if not os.path.exists(ROLES_STORE_FILE):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        _write_store_json(ROLES_STORE_FILE, {
            "items": [{
                "id": 1,
                "role_name": "admin",
                "role_description": "系统管理员，拥有所有权限",
                "permission_codes": DEFAULT_PERMISSION_CODES,
                "created_at": now,
                "updated_at": now
            }]
        })
    if not os.path.exists(USERS_STORE_FILE):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        _write_store_json(USERS_STORE_FILE, {
            "items": [{
                "id": 1,
                "username": "admin",
                "password": generate_password_hash('admin123', method='pbkdf2:sha256'),
                "email": "admin@example.com",
                "status": "active",
                "role_ids": [1],
                "created_at": now,
                "updated_at": now
            }]
        })
    if not os.path.exists(SYSTEM_CONFIG_STORE_FILE):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        _write_store_json(SYSTEM_CONFIG_STORE_FILE, {
            "id": 1,
            "system_name": "防火墙管理系统",
            "session_timeout": 30,
            "log_retention_time": "30",
            "color_mode": "light",
            "password_strategy": "medium",
            "created_at": now,
            "updated_at": now
        })
    if not os.path.exists(TEMPLATES_STORE_FILE):
        _write_store_json(TEMPLATES_STORE_FILE, {"items": []})
    if not os.path.exists(SSH_KEY_RECORDS_STORE_FILE):
        _write_store_json(SSH_KEY_RECORDS_STORE_FILE, {"items": []})
    if not os.path.exists(PORT_SCAN_STORE_FILE):
        _write_store_json(PORT_SCAN_STORE_FILE, {"items": []})
    if not os.path.exists(FIREWALL_RULE_STORE_FILE):
        _write_store_json(FIREWALL_RULE_STORE_FILE, {"items": []})
    if not os.path.exists(PORT_RULES_STORE_FILE):
        _write_store_json(PORT_RULES_STORE_FILE, {"items": []})


def _read_store_json(path, default):
    with _STORE_THREAD_LOCK, _store_lock(path):
        if not os.path.exists(path):
            return _clone_default(default)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = json.load(f)
            return content
        except Exception:
            return _clone_default(default)


def _write_store_json(path, payload):
    with _STORE_THREAD_LOCK, _store_lock(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix='tmp_', dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


def _read_hosts_from_store():
    data = _read_store_json(HOSTS_STORE_FILE, {"items": []})
    items = data.get('items', []) if isinstance(data, dict) else []
    normalized = []
    for item in items:
        if not isinstance(item, dict):
            continue
        normalized.append(item)
    return normalized


def _write_hosts_to_store(items):
    _write_store_json(HOSTS_STORE_FILE, {"items": items})


def _next_host_id(items):
    max_id = 0
    for item in items:
        try:
            max_id = max(max_id, int(item.get('id', 0)))
        except Exception:
            continue
    return max_id + 1


def _find_host_in_store(host_id):
    target = str(host_id)
    for item in _read_hosts_from_store():
        if str(item.get('id')) == target:
            return item
    return None


def _upsert_host_status_store(host_id, status, last_checked_at, last_check_error):
    items = _read_hosts_from_store()
    target = str(host_id)
    updated = None
    for item in items:
        if str(item.get('id')) == target:
            item['status'] = status
            item['last_checked_at'] = last_checked_at
            item['last_check_error'] = last_check_error
            item['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            updated = item
            break
    if updated:
        _write_hosts_to_store(items)
    return updated


def _read_operation_logs_from_store():
    data = _read_store_json(OPERATION_LOG_STORE_FILE, {"items": []})
    items = data.get('items', []) if isinstance(data, dict) else []
    return [item for item in items if isinstance(item, dict)]


def _read_users_from_store():
    data = _read_store_json(USERS_STORE_FILE, {"items": []})
    items = data.get('items', []) if isinstance(data, dict) else []
    return [item for item in items if isinstance(item, dict)]


def _write_users_to_store(items):
    _write_store_json(USERS_STORE_FILE, {"items": items})


def _read_roles_from_store():
    data = _read_store_json(ROLES_STORE_FILE, {"items": []})
    items = data.get('items', []) if isinstance(data, dict) else []
    return [item for item in items if isinstance(item, dict)]


def _write_roles_to_store(items):
    _write_store_json(ROLES_STORE_FILE, {"items": items})


def _read_templates_from_store():
    data = _read_store_json(TEMPLATES_STORE_FILE, {"items": []})
    items = data.get('items', []) if isinstance(data, dict) else []
    return [item for item in items if isinstance(item, dict)]


def _write_templates_to_store(items):
    _write_store_json(TEMPLATES_STORE_FILE, {"items": items})


def _read_ssh_key_records_store():
    data = _read_store_json(SSH_KEY_RECORDS_STORE_FILE, {"items": []})
    items = data.get('items', []) if isinstance(data, dict) else []
    return [item for item in items if isinstance(item, dict)]


def _write_ssh_key_records_store(items):
    _write_store_json(SSH_KEY_RECORDS_STORE_FILE, {"items": items})


def _read_port_scan_records_store():
    data = _read_store_json(PORT_SCAN_STORE_FILE, {"items": []})
    items = data.get('items', []) if isinstance(data, dict) else []
    return [item for item in items if isinstance(item, dict)]


def _write_port_scan_records_store(items):
    _write_store_json(PORT_SCAN_STORE_FILE, {"items": items})


def _read_firewall_rules_store():
    data = _read_store_json(FIREWALL_RULE_STORE_FILE, {"items": []})
    items = data.get('items', []) if isinstance(data, dict) else []
    return [item for item in items if isinstance(item, dict)]


def _write_firewall_rules_store(items):
    _write_store_json(FIREWALL_RULE_STORE_FILE, {"items": items})


def _read_port_rules_store():
    data = _read_store_json(PORT_RULES_STORE_FILE, {"items": []})
    items = data.get('items', []) if isinstance(data, dict) else []
    return [item for item in items if isinstance(item, dict)]


def _write_port_rules_store(items):
    _write_store_json(PORT_RULES_STORE_FILE, {"items": items})


def _read_system_config_store():
    data = _read_store_json(SYSTEM_CONFIG_STORE_FILE, {})
    if not isinstance(data, dict):
        return {}
    return data


def _write_system_config_store(data):
    _write_store_json(SYSTEM_CONFIG_STORE_FILE, data)


def _next_id(items):
    max_id = 0
    for item in items:
        try:
            max_id = max(max_id, int(item.get('id', 0)))
        except Exception:
            continue
    return max_id + 1


def _permission_maps():
    id_to_code = {int(item['id']): item['code'] for item in PERMISSION_DEFINITIONS}
    code_to_item = {item['code']: item for item in PERMISSION_DEFINITIONS}
    return id_to_code, code_to_item


def _permission_codes_from_payload(permissions):
    id_to_code, code_to_item = _permission_maps()
    result = []
    if not isinstance(permissions, list):
        return result
    for permission in permissions:
        code = None
        if isinstance(permission, int):
            code = id_to_code.get(permission)
        elif isinstance(permission, str):
            permission = permission.strip()
            if not permission:
                continue
            if permission.isdigit():
                code = id_to_code.get(int(permission))
            elif permission in code_to_item:
                code = permission
        if code and code not in result:
            result.append(code)
    return result


def _build_permission_response(role_permission_codes):
    current = set(role_permission_codes or [])
    response = []
    for item in PERMISSION_DEFINITIONS:
        response.append({
            "id": item["id"],
            "code": item["code"],
            "name": item["name"],
            "has_perm": item["code"] in current
        })
    return response


def _normalize_local_store_data():
    """
    启动时规范化本地存储结构，避免历史数据字段缺失导致运行期异常。
    """
    if not USE_LOCAL_FILE_STORE:
        return

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # hosts
    hosts = _read_hosts_from_store()
    norm_hosts = []
    for item in hosts:
        host = dict(item)
        host['id'] = int(host.get('id', 0) or 0)
        host['host_name'] = str(host.get('host_name', '') or '')
        host['host_identifier'] = str(host.get('host_identifier', '') or '')
        host['ip_address'] = str(host.get('ip_address', '') or '')
        host['operating_system'] = str(host.get('operating_system', '') or '')
        try:
            host['ssh_port'] = int(host.get('ssh_port', 22) or 22)
        except (TypeError, ValueError):
            host['ssh_port'] = 22
        host['username'] = str(host.get('username', '') or '')
        host['auth_method'] = str(host.get('auth_method', 'password') or 'password')
        host['password'] = str(host.get('password', '') or '')
        host['private_key'] = str(host.get('private_key', '') or '')
        host['status'] = str(host.get('status', 'unknown') or 'unknown')
        host['last_checked_at'] = str(host.get('last_checked_at', '') or '')
        host['last_check_error'] = str(host.get('last_check_error', '') or '')
        host['created_at'] = str(host.get('created_at', now) or now)
        host['updated_at'] = str(host.get('updated_at', now) or now)
        norm_hosts.append(host)
    if norm_hosts != hosts:
        _write_hosts_to_store(norm_hosts)

    # operation logs
    logs = _read_operation_logs_from_store()
    norm_logs = []
    for item in logs:
        log = dict(item)
        try:
            log['id'] = int(log.get('id', 0) or 0)
        except (TypeError, ValueError):
            log['id'] = 0
        log['user_id'] = log.get('user_id')
        log['username'] = str(log.get('username', '') or '')
        log['operation_type'] = str(log.get('operation_type', '') or '')
        log['operation_object'] = str(log.get('operation_object', '') or '')
        log['operation_summary'] = str(log.get('operation_summary', '') or '')
        details = log.get('operation_details', '')
        if isinstance(details, (dict, list)):
            log['operation_details'] = json.dumps(details, ensure_ascii=False)
        else:
            log['operation_details'] = str(details or '')
        log['success'] = 1 if int(log.get('success', 0) or 0) else 0
        log['operation_time'] = str(log.get('operation_time', now) or now)
        norm_logs.append(log)
    if norm_logs != logs:
        _write_store_json(OPERATION_LOG_STORE_FILE, {"items": norm_logs})

    # users
    users = _read_users_from_store()
    norm_users = []
    for item in users:
        user = dict(item)
        user['id'] = int(user.get('id', 0) or 0)
        user['username'] = str(user.get('username', '') or '')
        user['password'] = str(user.get('password', '') or '')
        user['email'] = str(user.get('email', '') or '')
        user['status'] = str(user.get('status', 'active') or 'active')
        role_ids = user.get('role_ids', [])
        if not isinstance(role_ids, list):
            role_ids = [role_ids]
        user['role_ids'] = [int(role_id) for role_id in role_ids if str(role_id).isdigit()]
        user['created_at'] = str(user.get('created_at', now) or now)
        user['updated_at'] = str(user.get('updated_at', now) or now)
        norm_users.append(user)
    if norm_users != users:
        _write_users_to_store(norm_users)

    # roles
    roles = _read_roles_from_store()
    norm_roles = []
    for item in roles:
        role = dict(item)
        role['id'] = int(role.get('id', 0) or 0)
        role['role_name'] = str(role.get('role_name', '') or '')
        role['role_description'] = str(role.get('role_description', '') or '')
        permission_codes = role.get('permission_codes', [])
        if not isinstance(permission_codes, list):
            permission_codes = [permission_codes]
        role['permission_codes'] = sorted(set(_permission_codes_from_payload(permission_codes)))
        role['created_at'] = str(role.get('created_at', now) or now)
        role['updated_at'] = str(role.get('updated_at', now) or now)
        norm_roles.append(role)
    if norm_roles != roles:
        _write_roles_to_store(norm_roles)

    # system config
    cfg = _read_system_config_store()
    norm_cfg = dict(cfg) if isinstance(cfg, dict) else {}
    norm_cfg['id'] = int(norm_cfg.get('id', 1) or 1)
    current_system_name = str(norm_cfg.get('system_name', '') or '').strip()
    if not current_system_name or current_system_name.lower() in ('iptables-web', 'iptables_web', 'iptables web'):
        norm_cfg['system_name'] = '防火墙管理系统'
    else:
        norm_cfg['system_name'] = current_system_name
    try:
        norm_cfg['session_timeout'] = int(norm_cfg.get('session_timeout', 30) or 30)
    except (TypeError, ValueError):
        norm_cfg['session_timeout'] = 30
    norm_cfg['log_retention_time'] = str(norm_cfg.get('log_retention_time', '30') or '30')
    norm_cfg['color_mode'] = str(norm_cfg.get('color_mode', 'light') or 'light')
    norm_cfg['password_strategy'] = str(norm_cfg.get('password_strategy', 'medium') or 'medium')
    norm_cfg['created_at'] = str(norm_cfg.get('created_at', now) or now)
    norm_cfg['updated_at'] = str(norm_cfg.get('updated_at', now) or now)
    if norm_cfg != cfg:
        _write_system_config_store(norm_cfg)

    # templates
    templates = _read_templates_from_store()
    norm_templates = []
    for item in templates:
        temp = dict(item)
        temp['id'] = int(temp.get('id', 0) or 0)
        temp['template_name'] = str(temp.get('template_name', '') or '')
        temp['template_identifier'] = str(temp.get('template_identifier', '') or '')
        temp['direction'] = str(temp.get('direction', 'INPUT') or 'INPUT')
        temp['created_at'] = str(temp.get('created_at', now) or now)
        temp['updated_at'] = str(temp.get('updated_at', now) or now)
        rules = temp.get('rules', [])
        if not isinstance(rules, list):
            rules = []
        norm_rules = []
        for idx, rule in enumerate(rules, start=1):
            item_rule = dict(rule) if isinstance(rule, dict) else {}
            item_rule['rule_id'] = int(item_rule.get('rule_id', idx) or idx)
            item_rule['policy'] = str(item_rule.get('policy', '') or '')
            item_rule['protocol'] = str(item_rule.get('protocol', '') or '')
            item_rule['port'] = str(item_rule.get('port', '') or '')
            item_rule['auth_object'] = str(item_rule.get('auth_object', '') or '')
            item_rule['description'] = str(item_rule.get('description', '') or '')
            item_rule['limit'] = str(item_rule.get('limit', '') or '')
            item_rule['created_at'] = str(item_rule.get('created_at', temp['created_at']) or temp['created_at'])
            item_rule['updated_at'] = str(item_rule.get('updated_at', temp['updated_at']) or temp['updated_at'])
            norm_rules.append(item_rule)
        temp['rules'] = norm_rules
        norm_templates.append(temp)
    if norm_templates != templates:
        _write_templates_to_store(norm_templates)

    # ssh key setup records
    ssh_records = _read_ssh_key_records_store()
    norm_ssh_records = []
    for item in ssh_records:
        rec = dict(item)
        rec['id'] = int(rec.get('id', 0) or 0)
        rec['host_ip'] = str(rec.get('host_ip', '') or '')
        try:
            rec['ssh_port'] = int(rec.get('ssh_port', 22) or 22)
        except (TypeError, ValueError):
            rec['ssh_port'] = 22
        rec['target_username'] = str(rec.get('target_username', '') or '')
        rec['key_type'] = str(rec.get('key_type', 'ed25519') or 'ed25519')
        rec['private_key'] = str(rec.get('private_key', '') or '')
        rec['public_key'] = str(rec.get('public_key', '') or '')
        rec['private_key_path'] = str(rec.get('private_key_path', '') or '')
        rec['public_key_path'] = str(rec.get('public_key_path', '') or '')
        rec['setup_status'] = str(rec.get('setup_status', 'success') or 'success')
        rec['error_message'] = str(rec.get('error_message', '') or '')
        rec['operator_user_id'] = rec.get('operator_user_id')
        rec['operator_username'] = str(rec.get('operator_username', '') or '')
        rec['created_at'] = str(rec.get('created_at', now) or now)
        rec['revoke_status'] = str(rec.get('revoke_status', 'active') or 'active')
        rec['revoke_message'] = str(rec.get('revoke_message', '') or '')
        rec['revoked_at'] = str(rec.get('revoked_at', '') or '')
        norm_ssh_records.append(rec)
    if norm_ssh_records != ssh_records:
        _write_ssh_key_records_store(norm_ssh_records)

    # port rules (for port detection module)
    port_rules = _read_port_rules_store()
    norm_port_rules = []
    for item in port_rules:
        rule = dict(item)
        rule['id'] = str(rule.get('id', '') or '')
        rule['host_id'] = int(rule.get('host_id', 0) or 0)
        rule['host_ip'] = str(rule.get('host_ip', '') or '')
        rule['direction'] = str(rule.get('direction', 'INPUT') or 'INPUT').upper()
        if rule['direction'] not in ('INPUT', 'OUTPUT'):
            rule['direction'] = 'INPUT'
        rule['action'] = str(rule.get('action', 'DROP') or 'DROP').upper()
        if rule['action'] not in ('ACCEPT', 'DROP'):
            rule['action'] = 'DROP'
        rule['protocol'] = str(rule.get('protocol', 'tcp') or 'tcp').lower()
        if rule['protocol'] not in ('tcp', 'udp'):
            rule['protocol'] = 'tcp'
        try:
            rule['port'] = int(rule.get('port', 0) or 0)
        except (TypeError, ValueError):
            rule['port'] = 0
        rule['source_ip'] = str(rule.get('source_ip', '') or '')
        rule['dest_ip'] = str(rule.get('dest_ip', '') or '')
        rule['interface'] = str(rule.get('interface', '') or '')
        rule['comment'] = str(rule.get('comment', '') or '')
        rule['enabled'] = 1 if int(rule.get('enabled', 1) or 0) else 0
        rule['created_at'] = str(rule.get('created_at', now) or now)
        rule['created_by'] = str(rule.get('created_by', '') or '')
        norm_port_rules.append(rule)
    if norm_port_rules != port_rules:
        _write_port_rules_store(norm_port_rules)




def _append_operation_log_store(log_item):
    logs = _read_operation_logs_from_store()
    logs.append(log_item)
    if len(logs) > 50000:
        logs = logs[-50000:]
    _write_store_json(OPERATION_LOG_STORE_FILE, {"items": logs})


def _load_host_connection_info(host_id):
    """
    按 host_id 加载主机连接信息，优先使用本地文件存储。
    """
    if USE_LOCAL_FILE_STORE:
        host = _find_host_in_store(host_id)
        if not host:
            return None
        return {
            'id': host.get('id'),
            'ssh_port': int(host.get('ssh_port', 22)),
            'username': host.get('username', ''),
            'ip_address': host.get('ip_address', ''),
            'auth_method': host.get('auth_method', 'password'),
            'password': host.get('password', ''),
            'private_key': host.get('private_key', ''),
            'operating_system': host.get('operating_system', '')
        }

    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
    SELECT id, ssh_port, username, ip_address, auth_method, password, private_key, operating_system
    FROM hosts WHERE id = ?
    ''', (host_id,))
    row = cursor.fetchone()
    if not row:
        return None
    return dict(row)


COMMON_PORTS = [
    {"port": 22, "service": "SSH"},
    {"port": 80, "service": "HTTP"},
    {"port": 443, "service": "HTTPS"},
    {"port": 3389, "service": "RDP"},
    {"port": 23, "service": "Telnet"},
    {"port": 21, "service": "FTP"},
    {"port": 25, "service": "SMTP"},
    {"port": 3306, "service": "MySQL"},
    {"port": 8080, "service": "HTTP-Alt"},
]
COMMON_SERVICE_MAP_TCP = {int(item["port"]): item["service"] for item in COMMON_PORTS}
COMMON_SERVICE_MAP_UDP = {
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    161: "SNMP",
    162: "SNMP-Trap",
    500: "ISAKMP",
    514: "Syslog",
    520: "RIP",
    1900: "SSDP",
}


def _service_name_for_port(protocol, port):
    protocol = str(protocol or 'tcp').lower()
    if protocol == 'udp':
        return COMMON_SERVICE_MAP_UDP.get(int(port), f'UDP {port}')
    return COMMON_SERVICE_MAP_TCP.get(int(port), f'Port {port}')


def _parse_port_tokens(port_expr, max_ports=256):
    if isinstance(port_expr, list):
        raw_tokens = [str(item).strip() for item in port_expr]
    else:
        raw_tokens = [text.strip() for text in str(port_expr or '').split(',')]
    ports = set()
    for token in raw_tokens:
        if not token:
            continue
        if '-' in token:
            left, right = token.split('-', 1)
            if not left.strip().isdigit() or not right.strip().isdigit():
                raise ValueError(f'无效端口范围: {token}')
            start = int(left.strip())
            end = int(right.strip())
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f'端口范围超出限制: {token}')
            for port in range(start, end + 1):
                ports.add(port)
                if len(ports) > max_ports:
                    raise ValueError(f'端口数量过多，请控制在 {max_ports} 个以内')
        else:
            if not token.isdigit():
                raise ValueError(f'无效端口: {token}')
            port = int(token)
            if port < 1 or port > 65535:
                raise ValueError(f'端口超出范围: {token}')
            ports.add(port)
            if len(ports) > max_ports:
                raise ValueError(f'端口数量过多，请控制在 {max_ports} 个以内')
    if not ports:
        raise ValueError('请至少输入一个有效端口')
    return sorted(ports)


def _ping_host(host_ip, timeout_sec=2):
    if not host_ip:
        return False, '目标主机为空'
    if platform.system().lower() == 'windows':
        cmd = ['ping', '-n', '1', '-w', str(int(timeout_sec * 1000)), host_ip]
    else:
        cmd = ['ping', '-c', '1', '-W', str(timeout_sec), host_ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec + 1)
        if result.returncode == 0:
            return True, '主机可达'
        return False, (result.stderr or result.stdout or '').strip() or '主机不可达'
    except FileNotFoundError:
        return True, '当前环境未安装 ping，跳过前置检测'
    except subprocess.TimeoutExpired:
        return False, 'Ping检测超时'
    except Exception as e:
        return False, f'Ping检测异常: {str(e)}'


def _check_tcp_port(host_ip, port, timeout_sec=2):
    start = time.time()
    try:
        with socket.create_connection((host_ip, int(port)), timeout=timeout_sec):
            return True, int((time.time() - start) * 1000)
    except Exception:
        return False, int((time.time() - start) * 1000)


def _check_udp_port(host_ip, port, timeout_sec=2):
    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_sec)
    try:
        sock.connect((host_ip, int(port)))
        sock.send(b'\x00')
        try:
            sock.recv(1)
            return True, int((time.time() - start) * 1000)
        except socket.timeout:
            # UDP无响应场景较常见，视为“可能开放（open|filtered）”
            return True, int((time.time() - start) * 1000)
        except (ConnectionRefusedError, OSError):
            return False, int((time.time() - start) * 1000)
    except Exception:
        return False, int((time.time() - start) * 1000)
    finally:
        sock.close()


def _scan_target_ports(host_id, host_ip, port_items, protocol='tcp'):
    ping_ok, ping_message = _ping_host(host_ip, timeout_sec=2)
    rows = []
    protocol = str(protocol or 'tcp').lower()
    for item in port_items:
        port = int(item.get('port'))
        service = str(item.get('service', '') or f'Port {port}')
        if not ping_ok and '跳过前置' not in ping_message:
            is_open, elapsed = False, -1
        else:
            if protocol == 'udp':
                is_open, elapsed = _check_udp_port(host_ip, port, timeout_sec=2)
            else:
                is_open, elapsed = _check_tcp_port(host_ip, port, timeout_sec=2)
        rows.append({
            "port": port,
            "protocol": protocol,
            "service": service,
            "status": "open" if is_open else "closed",
            "response_ms": elapsed
        })
    if USE_LOCAL_FILE_STORE:
        records = _read_port_scan_records_store()
        records.append({
            "id": _next_id(records),
            "host_id": int(host_id or 0),
            "host_ip": host_ip,
            "protocol": protocol,
            "ping_ok": ping_ok,
            "ping_message": ping_message,
            "checked_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "results": rows
        })
        if len(records) > 5000:
            records = records[-5000:]
        _write_port_scan_records_store(records)
    return ping_ok, ping_message, _decorate_scan_rows_with_rule_status(host_ip, protocol, rows)


def _run_remote_shell(host, cmd):
    if host.get('auth_method', 'password') == 'password':
        return pwd_shell_cmd(
            hostname=host['ip_address'],
            user=host['username'],
            port=host['ssh_port'],
            pwd=host['password'],
            cmd=cmd
        )
    return sshkey_shell_cmd(
        hostname=host['ip_address'],
        user=host['username'],
        port=host['ssh_port'],
        private_key_str=host['private_key'],
        cmd=cmd
    )


def _persist_host_firewall_rules(host):
    operating_system = str(host.get('operating_system', '') or '').lower()
    cmd = ''
    if operating_system in ('centos', 'redhat'):
        cmd = 'iptables-save > /etc/sysconfig/iptables'
    elif operating_system in ('ubuntu', 'debian'):
        cmd = 'iptables-save > /etc/iptables/rules.v4'
    if cmd:
        _run_remote_shell(host, cmd)
    return cmd


def _save_firewall_rule_records(host, ports, protocol, action, chain, source, persist_cmd):
    if not USE_LOCAL_FILE_STORE:
        return
    rules = _read_firewall_rules_store()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for port in ports:
        rules.append({
            "id": _next_id(rules),
            "host_id": int(host.get('id', 0) or 0),
            "target_ip": host.get('ip_address', ''),
            "protocol": protocol,
            "port": int(port),
            "action": action,
            "chain": chain,
            "source": source,
            "persist_command": persist_cmd,
            "created_at": now
        })
    _write_firewall_rules_store(rules)


def _normalize_ip_scope(raw_value):
    value = str(raw_value or '').strip()
    if not value or value.lower() in ('all', 'any', '全部', '所有'):
        value = '0.0.0.0/0'
    scope_error = _validate_auth_object(value)
    if scope_error:
        raise ValueError(scope_error)
    return value


def _build_iptables_rule_cmd(direction, action, protocol, port, source_ip=None, dest_ip=None, interface=''):
    direction = str(direction or 'INPUT').strip().upper()
    action = str(action or 'DROP').strip().upper()
    protocol = str(protocol or 'tcp').strip().lower()
    if direction not in ('INPUT', 'OUTPUT'):
        raise ValueError('方向仅支持 INPUT/OUTPUT')
    if action not in ('ACCEPT', 'DROP'):
        raise ValueError('动作仅支持 ACCEPT/DROP')
    if protocol not in ('tcp', 'udp'):
        raise ValueError('协议仅支持 tcp/udp')
    try:
        port = int(port)
    except Exception:
        raise ValueError('端口必须是数字')
    if port <= 0 or port > 65535:
        raise ValueError('端口范围必须在 1-65535 之间')

    cmd_parts = [f'iptables -A {direction}', f'-p {protocol}']
    if direction == 'INPUT':
        cmd_parts.append(f'-s {source_ip or "0.0.0.0/0"}')
        cmd_parts.append(f'--dport {port}')
        if interface:
            cmd_parts.append(f'-i {interface}')
    else:
        cmd_parts.append(f'-d {dest_ip or "0.0.0.0/0"}')
        cmd_parts.append(f'--dport {port}')
        if interface:
            cmd_parts.append(f'-o {interface}')
    cmd_parts.append(f'-j {action}')
    return ' '.join(cmd_parts)


def _build_iptables_dedupe_cmd(direction, action, protocol, port, source_ip=None, dest_ip=None, interface=''):
    rule_cmd = _build_iptables_rule_cmd(direction, action, protocol, port, source_ip, dest_ip, interface)
    return rule_cmd.replace('iptables -A', 'iptables -C', 1) + f' || {rule_cmd}'


def _port_rule_identity(rule):
    return (
        str(rule.get('host_ip', '') or ''),
        str(rule.get('direction', '') or '').upper(),
        str(rule.get('action', '') or '').upper(),
        str(rule.get('protocol', '') or '').lower(),
        str(rule.get('port', '') or ''),
        str(rule.get('source_ip', '') or ''),
        str(rule.get('dest_ip', '') or ''),
        str(rule.get('interface', '') or ''),
    )


def _decorate_scan_rows_with_rule_status(host_ip, protocol, rows):
    if not USE_LOCAL_FILE_STORE:
        return rows
    protocol = str(protocol or 'tcp').lower()
    rules = _read_port_rules_store()
    indexed = {
        (int(item.get('port', 0) or 0), str(item.get('protocol', '') or '').lower())
        for item in rules
        if str(item.get('host_ip', '') or '') == str(host_ip or '')
           and str(item.get('direction', 'INPUT') or 'INPUT').upper() == 'INPUT'
           and str(item.get('action', 'DROP') or 'DROP').upper() == 'DROP'
           and int(item.get('enabled', 1) or 0) == 1
    }
    result_rows = []
    for row in rows:
        row_copy = dict(row)
        port_value = int(row_copy.get('port', 0) or 0)
        row_copy['rule_added'] = (port_value, protocol) in indexed
        result_rows.append(row_copy)
    return result_rows


def _parse_iptables_port_value(port_text):
    text = str(port_text or '').strip()
    if not text:
        return []
    if ':' in text:
        return []
    if ',' in text:
        ports = []
        for token in text.split(','):
            token = token.strip()
            if token.isdigit():
                ports.append(int(token))
        return ports
    if text.isdigit():
        return [int(text)]
    return []


def _remove_port_rules_by_runtime_rule(host_ip, direction, runtime_rule):
    if not USE_LOCAL_FILE_STORE:
        return 0
    ports = _parse_iptables_port_value(runtime_rule.get('port', ''))
    if not ports:
        return 0
    direction = str(direction or 'INPUT').upper()
    protocol = str(runtime_rule.get('prot', '') or '').lower()
    action = str(runtime_rule.get('target', '') or '').upper()
    source = str(runtime_rule.get('source', '') or '').strip()
    destination = str(runtime_rule.get('destination', '') or '').strip()
    rules = _read_port_rules_store()
    kept = []
    removed = 0
    port_set = set(ports)
    for item in rules:
        same_host = str(item.get('host_ip', '') or '') == str(host_ip or '')
        same_direction = str(item.get('direction', '') or '').upper() == direction
        same_protocol = str(item.get('protocol', '') or '').lower() == protocol
        same_action = str(item.get('action', '') or '').upper() == action
        same_port = int(item.get('port', 0) or 0) in port_set
        if direction == 'INPUT':
            same_scope = str(item.get('source_ip', '') or '').strip() == source
        else:
            same_scope = str(item.get('dest_ip', '') or '').strip() == destination
        if same_host and same_direction and same_protocol and same_action and same_port and same_scope:
            removed += 1
            continue
        kept.append(item)
    if removed > 0:
        _write_port_rules_store(kept)
    return removed


def _normalize_runtime_scope(value):
    text = str(value or '').strip()
    if not text or text in ('*', '0.0.0.0'):
        return '0.0.0.0/0'
    return text


def _build_runtime_rule_signature_set(direction, iptables_output):
    signatures = set()
    direction = str(direction or '').upper()
    for item in get_rule(iptables_output):
        protocol = str(item.get('prot', '') or '').lower()
        action = str(item.get('target', '') or '').upper()
        source = _normalize_runtime_scope(item.get('source', ''))
        destination = _normalize_runtime_scope(item.get('destination', ''))
        ports = _parse_iptables_port_value(item.get('port', ''))
        for port in ports:
            signatures.add((
                direction,
                action,
                protocol,
                int(port),
                source if direction == 'INPUT' else '',
                destination if direction == 'OUTPUT' else '',
            ))
    return signatures


def _sync_port_rules_for_host_with_runtime(host):
    if not USE_LOCAL_FILE_STORE:
        return 0
    host_ip = str(host.get('ip_address', '') or '')
    if not host_ip:
        return 0

    try:
        input_output = _run_remote_shell(host, 'iptables -nL INPUT --line-number -t filter')
        output_output = _run_remote_shell(host, 'iptables -nL OUTPUT --line-number -t filter')
    except Exception:
        # 无法获取远端规则时，避免误删本地记录
        return 0

    runtime_signatures = set()
    runtime_signatures.update(_build_runtime_rule_signature_set('INPUT', input_output))
    runtime_signatures.update(_build_runtime_rule_signature_set('OUTPUT', output_output))

    rules = _read_port_rules_store()
    kept = []
    removed = 0
    for item in rules:
        if str(item.get('host_ip', '') or '') != host_ip:
            kept.append(item)
            continue
        if int(item.get('enabled', 1) or 0) != 1:
            kept.append(item)
            continue
        signature = (
            str(item.get('direction', 'INPUT') or 'INPUT').upper(),
            str(item.get('action', 'DROP') or 'DROP').upper(),
            str(item.get('protocol', 'tcp') or 'tcp').lower(),
            int(item.get('port', 0) or 0),
            _normalize_runtime_scope(item.get('source_ip', '')) if str(item.get('direction', 'INPUT') or 'INPUT').upper() == 'INPUT' else '',
            _normalize_runtime_scope(item.get('dest_ip', '')) if str(item.get('direction', 'INPUT') or 'INPUT').upper() == 'OUTPUT' else '',
        )
        if signature not in runtime_signatures:
            removed += 1
            continue
        kept.append(item)

    if removed > 0:
        _write_port_rules_store(kept)
    return removed


_ensure_local_store_files()
_normalize_local_store_data()


# 生成6位随机小写英文字母组成的名字
def random_name(length=6):
    # 定义小写英文字母范围（a-z对应的ASCII码是97-122）
    letters = [chr(i) for i in range(97, 123)]  # 等价于 ['a','b',...,'z']
    # 从letters中随机选6个字符，拼接成字符串
    return ''.join(random.choice(letters) for _ in range(length))

# 新增：日志清理任务
def clean_expired_logs():
    """清理过期日志"""
    if USE_LOCAL_FILE_STORE:
        try:
            retention_days = int(os.getenv('LOG_RETENTION_DAYS', '30'))
            if retention_days <= 0:
                return
            expire_dt = datetime.now() - timedelta(days=retention_days)
            logs = _read_operation_logs_from_store()
            kept_logs = []
            deleted_count = 0
            for item in logs:
                raw_time = item.get('operation_time', '')
                try:
                    item_dt = datetime.strptime(raw_time, '%Y-%m-%d %H:%M:%S')
                except Exception:
                    kept_logs.append(item)
                    continue
                if item_dt >= expire_dt:
                    kept_logs.append(item)
                else:
                    deleted_count += 1
            if deleted_count:
                _write_store_json(OPERATION_LOG_STORE_FILE, {"items": kept_logs})
            app.logger.info(f"清理过期日志成功，共删除 {deleted_count} 条记录")
        except Exception as e:
            app.logger.error(f"清理过期日志失败: {str(e)}")
        return

    # 【修复】添加应用上下文
    with app.app_context():
        db = get_db()
        try:
            cursor = db.cursor()

            # 获取日志保留时间配置
            cursor.execute('SELECT log_retention_time FROM system_config LIMIT 1')
            config = cursor.fetchone()

            # 日志保留时间为0或未配置，表示永久保留
            if not config or not config['log_retention_time'] or config['log_retention_time'] == '0':
                return

            # 计算过期日期
            retention_days = int(config['log_retention_time'])
            if retention_days <= 0:
                return

            # 计算需要保留的最早日期
            expire_date = (datetime.now() - timedelta(days=retention_days)).strftime('%Y-%m-%d %H:%M:%S')

            # 删除过期日志
            cursor.execute('DELETE FROM operation_logs WHERE operation_time < ?', (expire_date,))
            deleted_count = cursor.rowcount
            db.commit()

            app.logger.info(f"清理过期日志成功，共删除 {deleted_count} 条记录")

        except Exception as e:
            db.rollback()
            app.logger.error(f"清理过期日志失败: {str(e)}")


def clean_expired_ssh_key_records():
    """
    清理过期 SSH 密钥配置记录及本地密钥文件。
    通过环境变量 SSH_KEY_RECORD_RETENTION_DAYS 控制保留天数，默认 30 天。
    设置为 0 或负数表示不自动清理。
    """
    if USE_LOCAL_FILE_STORE:
        return

    with app.app_context():
        db = get_db()
        try:
            retention_days = int(os.getenv('SSH_KEY_RECORD_RETENTION_DAYS', '30'))
            if retention_days <= 0:
                return

            expire_date = (datetime.now() - timedelta(days=retention_days)).strftime('%Y-%m-%d %H:%M:%S')
            cursor = db.cursor()
            cursor.execute('''
            SELECT id, private_key_path, public_key_path
            FROM ssh_key_setup_records
            WHERE created_at < ?
            ''', (expire_date,))
            rows = cursor.fetchall()
            if not rows:
                return

            deleted_file_count = 0
            for row in rows:
                for file_path in [row['private_key_path'], row['public_key_path']]:
                    if not file_path:
                        continue
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                            deleted_file_count += 1
                    except Exception as file_error:
                        app.logger.warning(f"清理过期SSH密钥文件失败: {file_path}, {str(file_error)}")

            row_ids = [row['id'] for row in rows]
            placeholders = ','.join(['?'] * len(row_ids))
            cursor.execute(f'DELETE FROM ssh_key_setup_records WHERE id IN ({placeholders})', row_ids)
            deleted_records = cursor.rowcount
            db.commit()

            app.logger.info(
                f"清理过期SSH密钥记录成功，删除记录 {deleted_records} 条，删除文件 {deleted_file_count} 个"
            )
        except Exception as e:
            db.rollback()
            app.logger.error(f"清理过期SSH密钥记录失败: {str(e)}")


# 正确配置调度器（无需创建新的app实例）
scheduler.init_app(app)
scheduler.add_job(
    id='clean_expired_logs',
    func=clean_expired_logs,
    trigger='cron',
    hour=2,
    minute=0
)
scheduler.add_job(
    id='clean_expired_ssh_key_records',
    func=clean_expired_ssh_key_records,
    trigger='cron',
    hour=3,
    minute=30
)
scheduler.start()


def permission_required(permission_code):
    """权限检查装饰器"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                # 未登录用户重定向到登录页
                return redirect(url_for('login'))

            # 检查用户是否有指定权限
            if not current_user.has_permission(permission_code):
                # 统一返回JSON格式的权限错误，包含403状态码
                return jsonify({
                    'success': False,
                    'message': '没有操作权限，请联系管理员获取权限'
                }), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def permission_required_any(permission_codes):
    """权限检查：满足任一权限即可访问。"""
    code_list = permission_codes if isinstance(permission_codes, (list, tuple, set)) else [permission_codes]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if not any(current_user.has_permission(code) for code in code_list):
                return jsonify({
                    'success': False,
                    'message': '没有操作权限，请联系管理员获取权限'
                }), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def get_csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': get_csrf_token}


def validate_csrf_request():
    """
    校验 AJAX 请求的 CSRF Token。
    优先读取 X-CSRF-Token 头；兼容 JSON body 中 csrf_token 字段。
    """
    expected = session.get('csrf_token')
    supplied = request.headers.get('X-CSRF-Token')
    if not supplied and request.is_json:
        payload = request.get_json(silent=True) or {}
        supplied = payload.get('csrf_token')
    if not expected or not supplied or not hmac.compare_digest(str(expected), str(supplied)):
        raise RuntimeError('CSRF校验失败，请刷新页面后重试')


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


def _get_fernet():
    """
    获取主机凭据加密器。
    优先读取环境变量 HOST_CRED_KEY；未配置时基于 app.secret_key 派生。
    """
    raw_key = os.getenv('HOST_CRED_KEY')
    if raw_key:
        key_bytes = raw_key.encode()
    else:
        digest = hashlib.sha256(app.secret_key.encode()).digest()
        key_bytes = base64.urlsafe_b64encode(digest)
    return Fernet(key_bytes)


def encrypt_host_secret(value):
    """加密主机认证敏感字段，兼容空值和已加密值。"""
    if value is None:
        return ''
    text = str(value).strip()
    if not text:
        return ''
    if text.startswith('enc:'):
        return text
    token = _get_fernet().encrypt(text.encode()).decode()
    return f'enc:{token}'


def decrypt_host_secret(value):
    """解密主机认证敏感字段，兼容历史明文数据。"""
    if value is None:
        return ''
    text = str(value)
    if not text:
        return ''
    if not text.startswith('enc:'):
        return text
    token = text[4:].encode()
    return _get_fernet().decrypt(token).decode()


def ensure_hosts_extended_columns():
    """
    为 hosts 表补齐扩展字段（状态与检测时间），兼容已有数据库。
    """
    with app.app_context():
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute("PRAGMA table_info(hosts)")
            columns = {row[1] for row in cursor.fetchall()}
            if not columns:
                return
            if 'status' not in columns:
                cursor.execute("ALTER TABLE hosts ADD COLUMN status TEXT DEFAULT 'unknown'")
            if 'last_checked_at' not in columns:
                cursor.execute("ALTER TABLE hosts ADD COLUMN last_checked_at TEXT")
            if 'last_check_error' not in columns:
                cursor.execute("ALTER TABLE hosts ADD COLUMN last_check_error TEXT")
            cursor.execute("UPDATE hosts SET status = 'unknown' WHERE status IS NULL OR status = ''")
            db.commit()
        except Exception as e:
            db.rollback()
            app.logger.error(f"扩展hosts字段失败: {str(e)}")


def ensure_ssh_key_setup_records_table():
    """确保 SSH 密钥配置记录表存在。"""
    with app.app_context():
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh_key_setup_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_ip TEXT NOT NULL,
                ssh_port INTEGER NOT NULL,
                target_username TEXT NOT NULL,
                key_type TEXT NOT NULL,
                private_key TEXT,
                public_key TEXT,
                private_key_path TEXT,
                public_key_path TEXT,
                setup_status TEXT NOT NULL DEFAULT 'success',
                error_message TEXT,
                operator_user_id INTEGER,
                operator_username TEXT,
                created_at TEXT NOT NULL
            )
            ''')
            db.commit()
        except Exception as e:
            db.rollback()
            app.logger.error(f"初始化 ssh_key_setup_records 表失败: {str(e)}")


def ensure_ssh_key_setup_records_columns():
    """为 SSH 密钥记录表补齐扩展字段。"""
    with app.app_context():
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute("PRAGMA table_info(ssh_key_setup_records)")
            columns = {row[1] for row in cursor.fetchall()}
            if not columns:
                return
            if 'revoke_status' not in columns:
                cursor.execute("ALTER TABLE ssh_key_setup_records ADD COLUMN revoke_status TEXT DEFAULT 'active'")
            if 'revoke_message' not in columns:
                cursor.execute("ALTER TABLE ssh_key_setup_records ADD COLUMN revoke_message TEXT")
            if 'revoked_at' not in columns:
                cursor.execute("ALTER TABLE ssh_key_setup_records ADD COLUMN revoked_at TEXT")
            cursor.execute(
                "UPDATE ssh_key_setup_records SET revoke_status = 'active' "
                "WHERE revoke_status IS NULL OR revoke_status = ''"
            )
            db.commit()
        except Exception as e:
            db.rollback()
            app.logger.error(f"扩展 ssh_key_setup_records 字段失败: {str(e)}")


def ensure_ssh_key_manage_permission():
    """
    新增 ssh_key_manage 权限，并迁移给已有 hosts_add 权限的角色（兼容升级）。
    """
    with app.app_context():
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute('SELECT id FROM permissions WHERE code = ?', ('ssh_key_manage',))
            permission = cursor.fetchone()
            if permission:
                ssh_key_manage_id = permission['id']
            else:
                cursor.execute(
                    'INSERT INTO permissions (name, code, description) VALUES (?, ?, ?)',
                    ('管理SSH密钥', 'ssh_key_manage', '配置、查看和删除目标主机SSH密钥')
                )
                ssh_key_manage_id = cursor.lastrowid

            cursor.execute('SELECT id FROM permissions WHERE code = ?', ('hosts_add',))
            hosts_add_permission = cursor.fetchone()
            if hosts_add_permission:
                cursor.execute('''
                SELECT DISTINCT role_id
                FROM role_permissions
                WHERE permission_id = ?
                ''', (hosts_add_permission['id'],))
                role_rows = cursor.fetchall()
                for role_row in role_rows:
                    role_id = role_row['role_id']
                    cursor.execute('''
                    INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
                    VALUES (?, ?)
                    ''', (role_id, ssh_key_manage_id))
            db.commit()
        except Exception as e:
            db.rollback()
            app.logger.error(f"初始化 ssh_key_manage 权限失败: {str(e)}")


def save_ssh_key_setup_record(host_ip, ssh_port, target_username, key_type,
                              private_key='', public_key='',
                              private_key_path='', public_key_path='',
                              setup_status='success', error_message=''):
    """写入 SSH 密钥配置记录，便于回看和复用。"""
    if USE_LOCAL_FILE_STORE:
        records = _read_ssh_key_records_store()
        record_id = _next_id(records)
        encrypted_private_key = encrypt_host_secret(private_key) if private_key else ''
        records.append({
            'id': record_id,
            'host_ip': host_ip,
            'ssh_port': ssh_port,
            'target_username': target_username,
            'key_type': key_type,
            'private_key': encrypted_private_key,
            'public_key': public_key,
            'private_key_path': private_key_path,
            'public_key_path': public_key_path,
            'setup_status': setup_status,
            'error_message': error_message,
            'operator_user_id': current_user.id if current_user and current_user.is_authenticated else None,
            'operator_username': current_user.username if current_user and current_user.is_authenticated else '',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'revoke_status': 'active',
            'revoke_message': '',
            'revoked_at': ''
        })
        _write_ssh_key_records_store(records)
        return

    db = get_db()
    cursor = db.cursor()
    encrypted_private_key = encrypt_host_secret(private_key) if private_key else ''
    cursor.execute('''
    INSERT INTO ssh_key_setup_records
    (host_ip, ssh_port, target_username, key_type, private_key, public_key,
     private_key_path, public_key_path, setup_status, error_message,
     operator_user_id, operator_username, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        host_ip, ssh_port, target_username, key_type,
        encrypted_private_key, public_key, private_key_path, public_key_path,
        setup_status, error_message,
        current_user.id if current_user and current_user.is_authenticated else None,
        current_user.username if current_user and current_user.is_authenticated else '',
        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ))
    db.commit()


def refresh_host_statuses():
    """
    定时刷新主机连通状态（online/offline），避免列表页实时阻塞。
    """
    if USE_LOCAL_FILE_STORE:
        try:
            hosts = _read_hosts_from_store()
            for host in hosts:
                _check_and_update_host_status(None, host)
        except Exception as e:
            app.logger.error(f"刷新主机状态失败: {str(e)}")
        return

    with app.app_context():
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute('''
            SELECT id, ip_address, ssh_port, username, auth_method, password, private_key
            FROM hosts
            ''')
            hosts = cursor.fetchall()
            for host in hosts:
                _check_and_update_host_status(cursor, host)
            db.commit()
        except Exception as e:
            db.rollback()
            app.logger.error(f"刷新主机状态失败: {str(e)}")


def _check_and_update_host_status(cursor, host):
    """
    检测单台主机SSH连通性并更新状态字段，返回状态信息。
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    host_id = host['id']
    try:
        test_cmd = 'echo STATUS_OK'
        if host['auth_method'] == 'password':
            output = pwd_shell_cmd(
                hostname=host['ip_address'],
                port=host['ssh_port'],
                user=host['username'],
                pwd=host['password'],
                cmd=test_cmd
            )
        else:
            output = sshkey_shell_cmd(
                hostname=host['ip_address'],
                port=host['ssh_port'],
                user=host['username'],
                private_key_str=host['private_key'],
                cmd=test_cmd
            )
        if 'STATUS_OK' in (output or ''):
            status = 'online'
            error_msg = ''
        else:
            status = 'offline'
            error_msg = '命令返回异常'
    except Exception as host_error:
        status = 'offline'
        error_msg = str(host_error)

    if USE_LOCAL_FILE_STORE:
        _upsert_host_status_store(host_id, status, now, error_msg)
    elif cursor is not None:
        cursor.execute(
            "UPDATE hosts SET status = ?, last_checked_at = ?, last_check_error = ? WHERE id = ?",
            (status, now, error_msg, host_id)
        )
    return {
        'status': status,
        'last_checked_at': now,
        'last_check_error': error_msg
    }


if not USE_LOCAL_FILE_STORE:
    ensure_hosts_extended_columns()
    ensure_ssh_key_setup_records_table()
    ensure_ssh_key_setup_records_columns()
    ensure_ssh_key_manage_permission()
scheduler.add_job(
    id='refresh_host_statuses',
    func=refresh_host_statuses,
    trigger='interval',
    minutes=5
)


def hash_user_password(plain_password):
    """
    统一用户密码哈希算法，避免依赖环境缺失scrypt导致登录失败。
    """
    return generate_password_hash(plain_password, method='pbkdf2:sha256')


def verify_user_password(hashed_password, plain_password):
    """
    校验用户密码，兼容不同哈希算法并给出明确错误信息。
    """
    try:
        return check_password_hash(hashed_password, plain_password)
    except AttributeError as e:
        # 某些Python/OpenSSL构建不支持scrypt，Werkzeug校验会触发该异常
        if isinstance(hashed_password, str) and hashed_password.startswith('scrypt:'):
            raise ValueError('当前运行环境不支持scrypt密码校验，请重置该账号密码后重试') from e
        raise


# 【新增】操作日志记录函数
def log_operation(user_id, username, operation_type, operation_object, operation_summary, operation_details, success):
    """
    记录操作日志
    :param user_id: 操作用户ID
    :param username: 操作用户名
    :param operation_type: 操作类型(添加/编辑/删除等)
    :param operation_object: 操作对象(用户/角色/主机等)
    :param operation_summary: 操作内容摘要
    :param operation_details: 操作详情(JSON格式)
    :param success: 操作结果(1成功,0失败)
    """
    # 获取东八区当前时间
    tz = pytz.timezone('Asia/Shanghai')
    operation_time = datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
    if USE_LOCAL_FILE_STORE:
        logs = _read_operation_logs_from_store()
        log_id = 1
        if logs:
            try:
                log_id = max(int(item.get('id', 0)) for item in logs) + 1
            except Exception:
                log_id = len(logs) + 1
        _append_operation_log_store({
            "id": log_id,
            "user_id": user_id,
            "username": username,
            "operation_type": operation_type,
            "operation_object": operation_object,
            "operation_summary": operation_summary,
            "operation_details": operation_details,
            "success": 1 if success else 0,
            "operation_time": operation_time
        })
        return

    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
        INSERT INTO operation_logs 
        (user_id, username, operation_type, operation_object, operation_summary, operation_details, success, operation_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, username, operation_type, operation_object, operation_summary, operation_details, success,
              operation_time))
        db.commit()
    except Exception as e:
        app.logger.error(f"记录操作日志失败: {str(e)}")
        if 'db' in locals():
            db.rollback()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


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
    stdin = None
    stdout = None
    stderr = None
    try:
        pwd = decrypt_host_secret(pwd)
        _connect_with_password_fallback(
            ssh_client=ssh,
            hostname=hostname,
            port=port,
            username=user,
            password=pwd,
            timeout=5
        )
        # stdin, stdout, stderr = ssh.exec_command('iptables -nL IN_public_allow --line-number -t filter -v')
        stdin, stdout, stderr = ssh.exec_command(cmd)
        # stdin, stdout, stderr = ssh.exec_command('iptables -nL INPUT --line-number -t filter -v')
        # 读取输出（确保数据被完全读取）
        output = stdout.read().decode()
        error = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            raise RuntimeError(error.strip() or f"命令执行失败，exit_code={exit_code}")
        return output
    except Exception as e:
        raise RuntimeError(f"SSH 操作失败: {str(e)}")
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


def _connect_with_password_fallback(ssh_client, hostname, port, username, password, timeout=8):
    """
    先尝试标准 password 认证；若服务器仅开启 keyboard-interactive，
    自动回退到 interactive 认证，减少误报 Authentication failed。
    """
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    try:
        ssh_client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            look_for_keys=False,
            allow_agent=False
        )
        return
    except AuthenticationException as password_error:
        transport = None
        try:
            transport = paramiko.Transport((hostname, int(port)))
            transport.banner_timeout = timeout
            transport.start_client(timeout=timeout)

            def auth_handler(title, instructions, prompts):
                return [password for _ in prompts]

            transport.auth_interactive(username, auth_handler)
            if not transport.is_authenticated():
                raise password_error

            ssh_client._transport = transport
            return
        except Exception:
            if transport:
                transport.close()
            raise RuntimeError(
                f"认证失败：请检查用户名/密码是否正确，或目标主机是否禁用了密码登录（用户: {username}, 端口: {port}）"
            )


def normalize_private_key(private_key_str):
    """规范化私钥文本，兼容前端/数据库中的转义换行与Windows换行。"""
    if not isinstance(private_key_str, str):
        return ''

    key_text = private_key_str.strip().replace('\r\n', '\n')
    # 部分场景会把换行存成字面量 \n（例如 JSON 转义后再次存储）
    if '\\n' in key_text and '\n' not in key_text:
        key_text = key_text.replace('\\n', '\n')
    return key_text


def load_private_key(private_key_str):
    """
    自动识别并加载多种 SSH 私钥格式。
    支持 RSA / ED25519 / ECDSA / DSA。
    """
    key_text = normalize_private_key(private_key_str)
    if not key_text:
        raise RuntimeError('SSH私钥为空')

    # 用户误贴公钥时提前给出明确提示
    if key_text.startswith(('ssh-rsa ', 'ssh-ed25519 ', 'ecdsa-sha2-')):
        raise RuntimeError('检测到的是公钥内容，请粘贴私钥（通常以 -----BEGIN ... PRIVATE KEY----- 开头）')

    key_loaders = [
        paramiko.RSAKey,
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        paramiko.DSSKey
    ]

    for key_cls in key_loaders:
        key_file = StringIO(key_text)
        try:
            return key_cls.from_private_key(key_file)
        except PasswordRequiredException:
            raise RuntimeError('当前私钥已加密口令（passphrase），请提供未加密私钥或扩展系统支持 passphrase')
        except SSHException:
            continue
        except Exception:
            continue

    raise RuntimeError('不支持的私钥格式或私钥内容无效，请确认粘贴的是完整私钥。')


def generate_ssh_key_pair(key_type='ed25519', key_comment='iptables-web'):
    """
    生成 SSH 密钥对（无 passphrase）。
    返回: private_key_str, public_key_str
    """
    key_type = (key_type or 'ed25519').strip().lower()
    if key_type not in ('ed25519', 'rsa'):
        raise RuntimeError('仅支持 ed25519 或 rsa 密钥类型')

    if key_type == 'rsa':
        private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_str = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    else:
        private_key_obj = ed25519.Ed25519PrivateKey.generate()
        private_key_str = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    public_key_core = private_key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode()
    public_key_str = f"{public_key_core} {key_comment}".strip()
    return private_key_str, public_key_str


def save_generated_key_files(host_ip, key_type, private_key_str, public_key_str):
    """
    保存生成的密钥文件到 data/ssh_keys 目录，便于审计与备份。
    """
    safe_host = re.sub(r'[^a-zA-Z0-9_.-]', '_', host_ip or 'host')
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    key_dir = os.path.join(app.root_path, 'data', 'ssh_keys')
    os.makedirs(key_dir, exist_ok=True)

    basename = f"{safe_host}_{key_type}_{timestamp}"
    private_path = os.path.join(key_dir, f"{basename}")
    public_path = os.path.join(key_dir, f"{basename}.pub")

    with open(private_path, 'w', encoding='utf-8') as f:
        f.write(private_key_str)
    with open(public_path, 'w', encoding='utf-8') as f:
        f.write(public_key_str + '\n')

    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o644)
    return private_path, public_path


def install_public_key_with_password(hostname, port, user, password, public_key_str):
    """
    使用密码认证登录目标主机并安装公钥到 authorized_keys。
    """
    ssh_client = paramiko.SSHClient()
    stdin = None
    stdout = None
    stderr = None
    try:
        _connect_with_password_fallback(
            ssh_client=ssh_client,
            hostname=hostname,
            port=port,
            username=user,
            password=password,
            timeout=8
        )
        quoted_pubkey = shlex.quote(public_key_str.strip())
        cmd = (
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            "touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && "
            f"(grep -qxF {quoted_pubkey} ~/.ssh/authorized_keys || echo {quoted_pubkey} >> ~/.ssh/authorized_keys)"
        )
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        output = stdout.read().decode()
        error = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            raise RuntimeError(error.strip() or output.strip() or f'公钥安装失败，exit_code={exit_code}')
    except Exception as e:
        raise RuntimeError(f'安装公钥失败: {str(e)}')
    finally:
        if stdin:
            stdin.close()
        if stdout:
            stdout.close()
        if stderr:
            stderr.close()
        ssh_client.close()


def verify_key_authentication(hostname, port, user, private_key_str):
    """
    验证密钥认证是否可用。
    """
    ssh_client = paramiko.SSHClient()
    stdin = None
    stdout = None
    stderr = None
    try:
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        pkey = load_private_key(private_key_str)
        ssh_client.connect(
            hostname=hostname,
            port=port,
            username=user,
            pkey=pkey,
            timeout=8,
            look_for_keys=False,
            allow_agent=False
        )
        stdin, stdout, stderr = ssh_client.exec_command('echo SSH_KEY_OK')
        output = stdout.read().decode()
        error = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0 or 'SSH_KEY_OK' not in (output or ''):
            raise RuntimeError(error.strip() or '密钥认证验证失败')
    except Exception as e:
        raise RuntimeError(f'密钥认证验证失败: {str(e)}')
    finally:
        if stdin:
            stdin.close()
        if stdout:
            stdout.close()
        if stderr:
            stderr.close()
        ssh_client.close()


def remove_public_key_with_private_key(hostname, port, user, private_key_str, public_key_str):
    """使用当前私钥登录目标主机并移除 authorized_keys 中对应公钥。"""
    ssh_client = paramiko.SSHClient()
    stdin = None
    stdout = None
    stderr = None
    try:
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        pkey = load_private_key(private_key_str)
        ssh_client.connect(
            hostname=hostname,
            port=port,
            username=user,
            pkey=pkey,
            timeout=8,
            look_for_keys=False,
            allow_agent=False
        )
        quoted_pubkey = shlex.quote((public_key_str or '').strip())
        if not quoted_pubkey or quoted_pubkey == "''":
            raise RuntimeError('记录中缺少公钥内容，无法删除目标主机公钥')

        cmd = (
            "mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && "
            f"awk -v key={quoted_pubkey} '$0 != key' ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp && "
            "mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys"
        )
        stdin, stdout, stderr = ssh_client.exec_command(cmd)
        output = stdout.read().decode()
        error = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            raise RuntimeError(error.strip() or output.strip() or f'删除目标主机公钥失败，exit_code={exit_code}')
    except Exception as e:
        raise RuntimeError(f'删除目标主机公钥失败: {str(e)}')
    finally:
        if stdin:
            stdin.close()
        if stdout:
            stdout.close()
        if stderr:
            stderr.close()
        ssh_client.close()


def sshkey_shell_cmd(hostname, port, user, private_key_str, cmd):
    try:
        private_key_str = decrypt_host_secret(private_key_str)
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        pkey = load_private_key(private_key_str)
        ssh.connect(hostname=hostname, port=port, username=user, pkey=pkey, timeout=5,
                    look_for_keys=False,
                    allow_agent=False)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode()
        error = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            raise RuntimeError(error.strip() or f"命令执行失败，exit_code={exit_code}")
        return output
    except Exception as e:
        raise RuntimeError(f"SSH 操作失败: {str(e)}")
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
        r'(?:\s+limit: (?:up to|above) (\d+)[kmg]?b/s)?'  # 限速字段（可选：有则捕数字，无则不匹配）
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
            limit = match.group(10) or ''
            comment = match.group(11) or ''
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
                        "limit": limit,
                        "comment": comment
                        }
            elif port_mul != '':
                data = {'num': num,
                        "target": target,
                        "prot": prot,
                        "source": source,
                        "destination": destination,
                        "port": port_mul,
                        "limit": limit,
                        "comment": comment
                        }
            else:
                data = {'num': num,
                        "target": target,
                        "prot": prot,
                        "source": source,
                        "destination": destination,
                        "port": port,
                        "limit": limit,
                        "comment": comment
                        }
            data_list.append(data)
        else:
            print(f"无法匹配的规则: {line}")
    return data_list


def _normalize_rule_signature(rule):
    protocol = str(rule.get('prot', 'all') or 'all').lower()
    source = str(rule.get('source', '0.0.0.0/0') or '0.0.0.0/0').strip()
    port = str(rule.get('port', '-1/-1') or '-1/-1').strip()
    target = str(rule.get('target', '') or '').upper()
    return protocol, source, port, target


def _detect_rule_conflicts(rule_list):
    duplicates = {}
    policy_groups = {}
    issues = []
    for rule in rule_list:
        num = str(rule.get('num', '') or '')
        protocol, source, port, target = _normalize_rule_signature(rule)
        full_key = (protocol, source, port, target)
        compare_key = (protocol, source, port)
        duplicates.setdefault(full_key, []).append(num)
        policy_groups.setdefault(compare_key, []).append({"num": num, "target": target, "source": source})

    for key, nums in duplicates.items():
        if len(nums) > 1:
            protocol, source, port, target = key
            issues.append({
                "type": "duplicate",
                "severity": "medium",
                "rule_numbers": nums,
                "message": f"发现重复规则：{protocol}/{port} 来源 {source} -> {target}（规则ID: {', '.join(nums)}）"
            })

    for key, values in policy_groups.items():
        targets = {item['target'] for item in values}
        if len(targets) > 1:
            protocol, source, port = key
            issues.append({
                "type": "policy_conflict",
                "severity": "high",
                "rule_numbers": [item['num'] for item in values],
                "message": f"策略冲突：{protocol}/{port} 来源 {source} 同时存在不同动作 {', '.join(sorted(targets))}"
            })

    wildcard_first = {}
    for rule in sorted(rule_list, key=lambda item: int(item.get('num', 0) or 0)):
        protocol, source, port, target = _normalize_rule_signature(rule)
        if source == '0.0.0.0/0':
            wildcard_first.setdefault((protocol, port), {"num": str(rule.get('num', '')), "target": target})
            continue
        wildcard = wildcard_first.get((protocol, port))
        if wildcard and wildcard['target'] != target:
            issues.append({
                "type": "shadowed_rule",
                "severity": "high",
                "rule_numbers": [wildcard['num'], str(rule.get('num', ''))],
                "message": (
                    f"规则可能被覆盖：先有全来源规则 {wildcard['num']}({wildcard['target']})，"
                    f"后续规则 {rule.get('num')}({target}) 可能不生效"
                )
            })

    return issues


def _validate_auth_object(auth_object):
    """
    校验授权对象格式，支持 IPv4 和 CIDR。
    返回 None 表示通过，返回字符串表示错误信息。
    """
    value = (auth_object or '').strip()
    if not value:
        return '授权对象不能为空'
    try:
        if '/' in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        return f'授权对象格式错误: {value}（示例: 172.16.0.0/16 或 192.168.1.10）'
    return None


def _normalize_template_policy(policy_value):
    text = (policy_value or '').strip().upper()
    if text in ('允许', 'ACCEPT'):
        return 'ACCEPT'
    if text in ('拒绝', 'DROP'):
        return 'DROP'
    return None


def _normalize_template_protocol(protocol_value):
    text = (protocol_value or '').strip().lower()
    if text in ('tcp', 'udp', 'icmp', 'all'):
        return text
    return None


def _validate_template_rule(rule, index):
    policy = _normalize_template_policy(rule.get('policy'))
    if not policy:
        return None, f'第{index}条规则授权策略无效'

    protocol = _normalize_template_protocol(rule.get('protocol'))
    if not protocol:
        return None, f'第{index}条规则协议无效，仅支持 TCP/UDP/ICMP/ALL'

    port = (rule.get('port') or '').strip()
    if not port:
        return None, f'第{index}条规则端口不能为空'

    port_pattern = r'^(\d+|\d+[-:]\d+|\d+(,\d+)+|-1/-1)$'
    if protocol in ('tcp', 'udp') and not re.fullmatch(port_pattern, port):
        return None, f'第{index}条规则端口格式错误'

    auth_object = (rule.get('auth_object') or '').strip()
    auth_object_error = _validate_auth_object(auth_object)
    if auth_object_error:
        return None, f'第{index}条规则{auth_object_error}'

    limit = (rule.get('limit') or '').strip()
    if limit:
        if not re.fullmatch(r'^\d+(kb/s)?$', limit):
            return None, f'第{index}条规则限速格式错误'
        if not limit.endswith('kb/s'):
            limit = f'{limit}kb/s'

    normalized = {
        'rule_id': rule.get('rule_id'),
        'policy': policy,
        'protocol': protocol,
        'port': port,
        'auth_object': auth_object,
        'description': (rule.get('description') or '').strip(),
        'limit': limit
    }
    return normalized, None


def _validate_template_payload(data, is_edit=False):
    if not isinstance(data, dict):
        return None, '无效的JSON数据'
    if is_edit and not data.get('temp_id'):
        return None, '缺少模板ID'

    name = (data.get('name') or '').strip()
    if not name:
        return None, '模板名称不能为空'

    direction = (data.get('direction') or '').strip().upper()
    if direction not in ('INPUT', 'OUTPUT'):
        return None, '规则方向无效，仅支持 INPUT/OUTPUT'

    rules = data.get('rules')
    if not isinstance(rules, list) or not rules:
        return None, '请至少添加一条规则'

    normalized_rules = []
    for idx, rule in enumerate(rules, start=1):
        normalized_rule, error_message = _validate_template_rule(rule, idx)
        if error_message:
            return None, error_message
        normalized_rules.append(normalized_rule)

    payload = {
        'temp_id': data.get('temp_id'),
        'name': name,
        'description': (data.get('description') or '').strip(),
        'direction': direction,
        'rules': normalized_rules
    }
    return payload, None


def _validate_host_payload(data, is_update=False):
    """
    校验主机新增/编辑请求参数，返回 (错误信息, 规范化ssh_port)。
    """
    if not isinstance(data, dict):
        return '无效的JSON数据', None

    required_fields = ['host_name', 'host_identifier', 'ip_address', 'operating_system', 'username']
    for field in required_fields:
        value = (data.get(field) or '').strip() if isinstance(data.get(field), str) else data.get(field)
        if not value:
            return f'缺少必填字段: {field}', None

    ip_address_value = (data.get('ip_address') or '').strip()
    try:
        ipaddress.ip_address(ip_address_value)
    except ValueError:
        return f'IP地址格式错误: {ip_address_value}', None

    try:
        ssh_port = int(data.get('ssh_port', 22))
        if ssh_port < 1 or ssh_port > 65535:
            raise ValueError()
    except (TypeError, ValueError):
        return 'SSH端口必须是1-65535之间的整数', None

    auth_method = (data.get('auth_method') or 'password').strip().lower()
    if auth_method not in ('password', 'key'):
        return '认证方式错误，仅支持 password 或 key', None

    if not is_update:
        password = (data.get('password') or '').strip() if isinstance(data.get('password'), str) else ''
        private_key = (data.get('private_key') or '').strip() if isinstance(data.get('private_key'), str) else ''
        if auth_method == 'password' and not password:
            return '认证方式为密码时，密码不能为空', None
        if auth_method == 'key' and not private_key:
            return '认证方式为密钥时，SSH密钥不能为空', None

    return None, ssh_port


def _build_host_connection_payload(data):
    """构建并校验主机连通性测试参数。"""
    if not isinstance(data, dict):
        return None, '无效的JSON数据'

    host_id = data.get('id')
    ip_address_value = (data.get('ip_address') or '').strip()
    username = (data.get('username') or '').strip()
    auth_method = (data.get('auth_method') or 'password').strip().lower()
    password = (data.get('password') or '') if isinstance(data.get('password'), str) else ''
    private_key = (data.get('private_key') or '') if isinstance(data.get('private_key'), str) else ''
    ssh_port_raw = data.get('ssh_port', 22)

    # 编辑场景下，允许复用历史认证信息
    if host_id and (not password and not private_key):
        if USE_LOCAL_FILE_STORE:
            host = _find_host_in_store(host_id)
        else:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('''
            SELECT ip_address, ssh_port, username, auth_method, password, private_key
            FROM hosts WHERE id = ?
            ''', (host_id,))
            host = cursor.fetchone()
        if host:
            ip_address_value = ip_address_value or host.get('ip_address', '')
            ssh_port_raw = ssh_port_raw or host.get('ssh_port', 22)
            username = username or host.get('username', '')
            auth_method = auth_method or host.get('auth_method', 'password')
            password = password or (host.get('password', '') or '')
            private_key = private_key or (host.get('private_key', '') or '')

    if not ip_address_value:
        return None, 'IP地址不能为空'
    try:
        ipaddress.ip_address(ip_address_value)
    except ValueError:
        return None, f'IP地址格式错误: {ip_address_value}'

    try:
        ssh_port = int(ssh_port_raw)
        if ssh_port < 1 or ssh_port > 65535:
            raise ValueError()
    except (TypeError, ValueError):
        return None, 'SSH端口必须是1-65535之间的整数'

    if not username:
        return None, 'SSH用户名不能为空'
    if auth_method not in ('password', 'key'):
        return None, '认证方式错误，仅支持 password 或 key'
    if auth_method == 'password' and not password:
        return None, '认证方式为密码时，密码不能为空'
    if auth_method == 'key' and not private_key:
        return None, '认证方式为密钥时，SSH密钥不能为空'

    return {
        'ip_address': ip_address_value,
        'ssh_port': ssh_port,
        'username': username,
        'auth_method': auth_method,
        'password': password,
        'private_key': private_key
    }, None


def _get_rule_view_hosts(cursor=None):
    """获取规则查看页面可选主机列表。"""
    if USE_LOCAL_FILE_STORE:
        hosts = _read_hosts_from_store()
        hosts = sorted(hosts, key=lambda item: item.get('created_at', ''), reverse=True)
        return [
            {
                'id': item.get('id'),
                'host_name': item.get('host_name', ''),
                'host_identifier': item.get('host_identifier', ''),
                'ip_address': item.get('ip_address', '')
            }
            for item in hosts
        ]

    cursor.execute('''
    SELECT id, host_name, host_identifier, ip_address
    FROM hosts
    ORDER BY created_at DESC
    ''')
    return cursor.fetchall()


def _normalize_template_rule(rule):
    """将模板规则标准化，便于与iptables列表规则对比。"""
    template_port = (rule['port'] if 'port' in rule.keys() else '-1/-1') or '-1/-1'
    if template_port != '-1/-1' and '-' in template_port:
        template_port = template_port.replace('-', ':')
    return {
        'policy': ((rule['policy'] if 'policy' in rule.keys() else '') or '').upper(),
        'protocol': ((rule['protocol'] if 'protocol' in rule.keys() else '') or '').lower(),
        'source': ((rule['auth_object'] if 'auth_object' in rule.keys() else '') or '').strip(),
        'comment': ((rule['description'] if 'description' in rule.keys() else '') or '').strip(),
        'port': template_port
    }


def _is_same_rule(iptables_rule, template_rule):
    """根据关键字段匹配是否是同一条规则。"""
    return (
            (iptables_rule.get('target') or '').upper() == template_rule['policy']
            and (iptables_rule.get('prot') or '').lower() == template_rule['protocol']
            and (iptables_rule.get('source') or '').strip() == template_rule['source']
            and (iptables_rule.get('comment') or '').strip() == template_rule['comment']
            and (iptables_rule.get('port') or '-1/-1') == template_rule['port']
    )


def _collect_template_applied_host_ids(cursor, template_id):
    """
    从操作日志中提取该模板曾应用过的主机ID。
    若日志不存在或解析失败，返回空列表。
    """
    host_ids = set()
    if USE_LOCAL_FILE_STORE:
        rows = _read_operation_logs_from_store()
    else:
        cursor.execute('''
        SELECT operation_details FROM operation_logs
        WHERE operation_type = '应用' AND operation_object = '模板' AND success = 1
        ''')
        rows = cursor.fetchall()
    for row in rows:
        try:
            raw_details = row.get('operation_details') if isinstance(row, dict) else row['operation_details']
            details = json.loads(raw_details) if isinstance(raw_details, str) and raw_details else (
                raw_details if isinstance(raw_details, dict) else {}
            )
        except (TypeError, json.JSONDecodeError):
            continue
        if str(details.get('template_id')) != str(template_id):
            continue
        applied_hosts = details.get('applied_hosts') or []
        for host in applied_hosts:
            host_id = host.get('host_id')
            if host_id is not None:
                host_ids.add(str(host_id))
    return list(host_ids)


def _delete_template_rules_on_host(host, direction, template_rules):
    """
    在单台主机上删除模板规则：
    通过规则特征匹配出当前链中的行号，再按倒序删除，避免行号漂移。
    """
    hostname = host['ip_address']
    port = host['ssh_port']
    user = host['username']
    pwd = host['password']
    auth_method = host['auth_method']
    private_key = host['private_key']
    operating_system = host['operating_system']

    def run_cmd(cmd):
        if auth_method == 'password':
            return pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd, cmd=cmd)
        return sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key, cmd=cmd)

    iptables_output = run_cmd('iptables -nL {} --line-number -t filter -v'.format(direction))
    current_rules = get_rule(iptables_output)

    line_numbers_to_delete = set()
    normalized_template_rules = [_normalize_template_rule(rule) for rule in template_rules]
    for ipt_rule in current_rules:
        for temp_rule in normalized_template_rules:
            if _is_same_rule(ipt_rule, temp_rule):
                try:
                    line_numbers_to_delete.add(int(ipt_rule['num']))
                except (TypeError, ValueError):
                    pass
                break

    if not line_numbers_to_delete:
        return 0

    for line_num in sorted(line_numbers_to_delete, reverse=True):
        run_cmd('iptables -D {} {}'.format(direction, line_num))

    if operating_system == 'centos' or operating_system == 'redhat':
        run_cmd('iptables-save > /etc/sysconfig/iptables')
    elif operating_system == 'debian':
        run_cmd('iptables-save > /etc/iptables/rules.v4')
    elif operating_system == 'ubuntu':
        run_cmd('iptables-save > /etc/iptables/rules.v4')

    return len(line_numbers_to_delete)


def _get_hosts_by_ids(cursor, host_ids):
    if not host_ids:
        return []
    normalized_ids = []
    for host_id in host_ids:
        if str(host_id).isdigit():
            normalized_ids.append(int(host_id))
    if not normalized_ids:
        return []
    if USE_LOCAL_FILE_STORE:
        id_set = {str(item_id) for item_id in normalized_ids}
        matched = []
        for host in _read_hosts_from_store():
            if str(host.get('id')) in id_set:
                matched.append({
                    'id': host.get('id'),
                    'host_name': host.get('host_name', ''),
                    'host_identifier': host.get('host_identifier', ''),
                    'ssh_port': host.get('ssh_port', 22),
                    'username': host.get('username', ''),
                    'ip_address': host.get('ip_address', ''),
                    'auth_method': host.get('auth_method', 'password'),
                    'password': host.get('password', ''),
                    'private_key': host.get('private_key', ''),
                    'operating_system': host.get('operating_system', '')
                })
        return matched
    placeholders = ','.join(['?'] * len(normalized_ids))
    cursor.execute('''
    SELECT id, host_name, host_identifier, ssh_port, username, ip_address, auth_method, password, private_key, operating_system
    FROM hosts
    WHERE id IN ({})
    '''.format(placeholders), tuple(normalized_ids))
    return cursor.fetchall()


def _run_cmd_on_host(host, cmd):
    if host['auth_method'] == 'password':
        return pwd_shell_cmd(
            hostname=host['ip_address'],
            user=host['username'],
            port=host['ssh_port'],
            pwd=host['password'],
            cmd=cmd
        )
    return sshkey_shell_cmd(
        hostname=host['ip_address'],
        user=host['username'],
        port=host['ssh_port'],
        private_key_str=host['private_key'],
        cmd=cmd
    )


def _persist_iptables(host):
    if host['operating_system'] in ('centos', 'redhat'):
        _run_cmd_on_host(host, 'iptables-save > /etc/sysconfig/iptables')
    elif host['operating_system'] in ('debian', 'ubuntu'):
        _run_cmd_on_host(host, 'iptables-save > /etc/iptables/rules.v4')


def _build_template_apply_payload(cursor, template_id):
    template = None
    rules = []
    if USE_LOCAL_FILE_STORE:
        for item in _read_templates_from_store():
            if str(item.get('id')) == str(template_id):
                template = item
                rules = item.get('rules', [])
                break
    else:
        cursor.execute('SELECT template_name, direction FROM templates WHERE id = ?', (template_id,))
        template = cursor.fetchone()
        if template:
            cursor.execute('''
            SELECT policy, protocol, port, auth_object, description, "limit"
            FROM rules WHERE template_id = ?
            ''', (template_id,))
            rules = cursor.fetchall()
    if not template:
        return None, None, None, '模板不存在'
    if not rules:
        template_name = template.get('template_name') if USE_LOCAL_FILE_STORE else template['template_name']
        direction = template.get('direction') if USE_LOCAL_FILE_STORE else template['direction']
        return template_name, direction, [], None

    direction = template.get('direction') if USE_LOCAL_FILE_STORE else template['direction']
    cmd_list = []
    for rule in rules:
        protocol = (rule.get('protocol') if USE_LOCAL_FILE_STORE else rule['protocol'])
        port = (rule.get('port') if USE_LOCAL_FILE_STORE else rule['port'])
        policy = (rule.get('policy') if USE_LOCAL_FILE_STORE else rule['policy'])
        auth_object = (rule.get('auth_object') if USE_LOCAL_FILE_STORE else rule['auth_object'])
        description = (rule.get('description') if USE_LOCAL_FILE_STORE else rule['description'])
        limit = (rule.get('limit') if USE_LOCAL_FILE_STORE else rule['limit']) or ''
        if 'tcp' in protocol.lower() or 'udp' in protocol.lower():
            if '-1/-1' not in port:
                if '-' in port:
                    new_port = port.replace("-", ":")
                    if limit == '':
                        cmd = 'iptables -A {}  -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, auth_object, protocol, new_port, policy, description)
                    else:
                        cmd = 'iptables -A {}  -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                            direction, auth_object, protocol, new_port, policy, limit, random_name(), description)
                    cmd_list.append(cmd)
                elif ',' in port:
                    if limit == '':
                        cmd = 'iptables -A {}  -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}" '.format(
                            direction, auth_object, protocol, port, policy, description)
                    else:
                        cmd = 'iptables -A {}  -s {} -p {} -m multiport --dports {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment --comment "{}" '.format(
                            direction, auth_object, protocol, port, policy, limit, random_name(), description)
                    cmd_list.append(cmd)
                else:
                    if limit == '':
                        cmd = 'iptables -A {}  -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                            direction, auth_object, protocol, port, policy, description)
                    else:
                        cmd = 'iptables -A {}  -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                            direction, auth_object, protocol, port, policy, limit, random_name(), description)
                    cmd_list.append(cmd)
            else:
                if limit == '':
                    cmd = 'iptables -A {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                        direction, auth_object, protocol, policy, description)
                else:
                    cmd = 'iptables -A {} -s {} -p {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}"'.format(
                        direction, auth_object, protocol, policy, limit, random_name(), description)
                cmd_list.append(cmd)
        else:
            if limit == '':
                cmd = 'iptables -A {}  -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                    direction, auth_object, protocol, policy, description)
            else:
                cmd = 'iptables -A {}  -s {} -p {}  -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}"'.format(
                    direction, auth_object, protocol, policy, limit, random_name(), description)
            cmd_list.append(cmd)

    template_name = template.get('template_name') if USE_LOCAL_FILE_STORE else template['template_name']
    return template_name, direction, cmd_list, None


# 根路径路由：重定向到 /hosts?page=1
@app.route('/')
def index():
    # 使用 url_for 生成 hosts 路由的 URL，指定 page=1
    return redirect(url_for('hosts', page=1))


@app.route("/rules_view", methods=['GET'])
@login_required
def rules_view():
    """
    规则查看入口：
    支持主机选择和方向选择，最终跳转到已有规则详情页。
    """
    all_params = dict(request.args)
    selected_host_id = all_params.get('host_id')
    direction = (all_params.get('direction') or 'INPUT').upper()
    if direction not in ('INPUT', 'OUTPUT'):
        direction = 'INPUT'
    try:
        cursor = None
        if not USE_LOCAL_FILE_STORE:
            db = get_db()
            cursor = db.cursor()
        host_list = _get_rule_view_hosts(cursor)
        if not host_list:
            flash('暂无主机，请先添加主机后再查看规则')
            return redirect(url_for('hosts', page=1))

        host_ids = {str(host['id']) for host in host_list}
        if selected_host_id not in host_ids:
            selected_host_id = str(host_list[0]['id'])

        if direction == 'OUTPUT':
            return redirect(url_for('rules_out', host_id=selected_host_id))
        return redirect(url_for('rules_in', host_id=selected_host_id))
    except Exception as e:
        return f"获取主机数据失败: {str(e)}", 500


@app.route("/port_detection", methods=['GET'])
@login_required
@permission_required('hosts_view')
def port_detection():
    try:
        cursor = None
        if not USE_LOCAL_FILE_STORE:
            db = get_db()
            cursor = db.cursor()
        host_options = _get_rule_view_hosts(cursor)
        default_ports = ','.join(str(item['port']) for item in COMMON_PORTS)
        return render_template('port_detection.html', host_options=host_options, default_ports=default_ports)
    except Exception as e:
        return f"加载端口检测页面失败: {str(e)}", 500


@app.route('/api/port-detection/scan', methods=['POST'])
@login_required
@permission_required('hosts_view')
def port_detection_scan_api():
    payload = request.get_json(silent=True) or {}
    host_id = payload.get('host_id')
    target = str(payload.get('target') or '').strip()
    protocol = str(payload.get('protocol') or 'tcp').strip().lower()
    if protocol not in ('tcp', 'udp'):
        return jsonify({'success': False, 'message': '协议仅支持 tcp/udp'}), 400

    host = None
    host_id_value = 0
    scan_target = target
    if str(host_id).isdigit():
        host_id_value = int(host_id)
        host = _load_host_connection_info(host_id_value)
        if not host:
            return jsonify({'success': False, 'message': '主机不存在'}), 404
        scan_target = host.get('ip_address', '')
    if not scan_target:
        return jsonify({'success': False, 'message': '请先选择主机或输入目标IP/域名'}), 400

    ports_input = payload.get('ports')
    if ports_input is None or str(ports_input).strip() == '':
        ports = [item['port'] for item in COMMON_PORTS]
    else:
        try:
            ports = _parse_port_tokens(ports_input, max_ports=256)
        except ValueError as e:
            return jsonify({'success': False, 'message': str(e)}), 400

    port_items = [{"port": port, "service": _service_name_for_port(protocol, port)} for port in ports]
    try:
        if host:
            _sync_port_rules_for_host_with_runtime(host)
        ping_ok, ping_message, rows = _scan_target_ports(host_id_value, scan_target, port_items, protocol=protocol)
        return jsonify({
            'success': True,
            'host_id': host_id_value,
            'target': scan_target,
            'protocol': protocol,
            'ping_ok': ping_ok,
            'ping_message': ping_message,
            'ports': rows,
            'notice': 'UDP 探测结果为快速探测，可能存在 open|filtered 情况。' if protocol == 'udp' else ''
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'端口检测失败: {str(e)}'}), 500


def _port_to_rule_impl(payload):
    host_id = payload.get('host_id')
    if not str(host_id).isdigit():
        return jsonify({'success': False, 'message': '添加规则必须选择系统内主机'}), 400
    host_id = int(host_id)
    host = _load_host_connection_info(host_id)
    if not host:
        return jsonify({'success': False, 'message': '主机不存在'}), 404

    ports_input = payload.get('ports') or payload.get('port') or []
    try:
        ports = _parse_port_tokens(ports_input, max_ports=256)
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    direction = str(payload.get('direction') or payload.get('chain') or 'INPUT').strip().upper()
    if direction not in ('INPUT', 'OUTPUT'):
        return jsonify({'success': False, 'message': '方向仅支持 INPUT/OUTPUT'}), 400

    protocol = str(payload.get('protocol') or 'tcp').strip().lower()
    if protocol not in ('tcp', 'udp'):
        return jsonify({'success': False, 'message': '协议仅支持 tcp/udp'}), 400

    action_text = str(payload.get('action') or 'drop').strip().lower()
    if action_text in ('allow', 'accept', '允许'):
        action = 'ACCEPT'
    elif action_text in ('deny', 'drop', '拒绝'):
        action = 'DROP'
    else:
        return jsonify({'success': False, 'message': '动作仅支持 allow/deny'}), 400

    interface = str(payload.get('interface') or '').strip()
    comment = str(payload.get('comment') or '').strip()
    host_ip = str(host.get('ip_address', '') or '')
    source_ip = ''
    dest_ip = ''
    try:
        if direction == 'INPUT':
            source_ip = _normalize_ip_scope(payload.get('source_ip') or payload.get('source') or '0.0.0.0/0')
        else:
            dest_ip = _normalize_ip_scope(payload.get('dest_ip') or payload.get('destination') or '0.0.0.0/0')
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400

    existing_rules = _read_port_rules_store() if USE_LOCAL_FILE_STORE else []
    existing_keys = {_port_rule_identity(item) for item in existing_rules if int(item.get('enabled', 1) or 0) == 1}

    created_rules = []
    duplicate_rules = []
    failed_rules = []
    for port in ports:
        candidate = {
            'host_ip': host_ip,
            'direction': direction,
            'action': action,
            'protocol': protocol,
            'port': int(port),
            'source_ip': source_ip if direction == 'INPUT' else '',
            'dest_ip': dest_ip if direction == 'OUTPUT' else '',
            'interface': interface
        }
        if _port_rule_identity(candidate) in existing_keys:
            duplicate_rules.append({'port': int(port), 'message': '规则已存在'})
            continue
        try:
            cmd = _build_iptables_dedupe_cmd(
                direction=direction,
                action=action,
                protocol=protocol,
                port=port,
                source_ip=source_ip,
                dest_ip=dest_ip,
                interface=interface
            )
            _run_remote_shell(host, cmd)
            created_rules.append(candidate)
        except Exception as e:
            failed_rules.append({'port': int(port), 'error': str(e)})

    persist_cmd = ''
    persist_error = ''
    if created_rules:
        try:
            persist_cmd = _persist_host_firewall_rules(host)
        except Exception as e:
            persist_error = str(e)

        if USE_LOCAL_FILE_STORE:
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            for rule in created_rules:
                existing_rules.append({
                    'id': str(uuid.uuid4()),
                    'host_id': int(host.get('id', 0) or 0),
                    'host_ip': host_ip,
                    'target_ip': host_ip,
                    'direction': direction,
                    'action': action,
                    'protocol': protocol,
                    'port': int(rule['port']),
                    'source_ip': rule.get('source_ip', ''),
                    'dest_ip': rule.get('dest_ip', ''),
                    'interface': interface,
                    'comment': comment,
                    'command': _build_iptables_rule_cmd(
                        direction=direction,
                        action=action,
                        protocol=protocol,
                        port=rule['port'],
                        source_ip=source_ip,
                        dest_ip=dest_ip,
                        interface=interface
                    ),
                    'persist_command': persist_cmd,
                    'created_at': now,
                    'created_by': str(getattr(current_user, 'username', '') or ''),
                    'enabled': 1
                })
            _write_port_rules_store(existing_rules)

    added_ports = [item['port'] for item in created_rules]
    return jsonify({
        'success': bool(created_rules),
        'message': f'已添加 {len(created_rules)} 条规则' + (f'，{len(duplicate_rules)} 条重复已跳过' if duplicate_rules else '') + (f'，{len(failed_rules)} 条失败' if failed_rules else ''),
        'added_ports': added_ports,
        'duplicates': duplicate_rules,
        'failed_ports': failed_rules,
        'persist_error': persist_error,
        'rule_view_url': url_for('rules_in', host_id=host_id) if direction == 'INPUT' else url_for('rules_out', host_id=host_id),
        'security_notice': '执行iptables需要root权限，建议使用root运行后端进程或配置sudo NOPASSWD。'
    }), 200 if created_rules else 409


@app.route('/api/port-to-rule', methods=['POST'])
@login_required
@permission_required('iptab_add')
def port_to_rule_api():
    payload = request.get_json(silent=True) or {}
    return _port_to_rule_impl(payload)


@app.route('/api/port-detection/add-rules', methods=['POST'])
@login_required
@permission_required('iptab_add')
def port_detection_add_rules_api():
    # compatibility endpoint for old frontend
    payload = request.get_json(silent=True) or {}
    return _port_to_rule_impl(payload)


# 查看规则
@app.route("/rules_in", methods=['GET'])
@login_required
def rules_in():
    all_params = dict(request.args)
    host_id = all_params['host_id']
    try:
        host = _load_host_connection_info(host_id)
        if not host:
            return jsonify({'success': False, 'message': f'主机不存在: host_id={host_id}'}), 404
        hostname = host['ip_address']
        port = host['ssh_port']
        user = host['username']
        pwd = host['password']
        auth_method = host['auth_method']
        private_key = host['private_key']
        if auth_method == 'password':
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -nL INPUT --line-number -t filter')
        else:
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -nL INPUT --line-number -t filter')
        data_list = get_rule(iptables_output)
        host_options = _get_rule_view_hosts()
        return render_template('rule.html', data_list=data_list, id=host_id, host_options=host_options)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


@app.route("/rules_out", methods=['GET'])
@login_required
def rules_out():
    all_params = dict(request.args)
    host_id = all_params['host_id']
    try:
        host = _load_host_connection_info(host_id)
        if not host:
            return jsonify({'success': False, 'message': f'主机不存在: host_id={host_id}'}), 404
        hostname = host['ip_address']
        port = host['ssh_port']
        user = host['username']
        pwd = host['password']
        auth_method = host['auth_method']
        private_key = host['private_key']
        if auth_method == 'password':
            iptables_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                                            cmd='iptables -nL OUTPUT --line-number -t filter')
        else:
            iptables_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                               cmd='iptables -nL OUTPUT --line-number -t filter')
        data_list = get_rule(iptables_output)
        host_options = _get_rule_view_hosts()
        return render_template('rule.html', data_list=data_list, id=host_id, host_options=host_options)
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


@app.route("/rules_conflicts", methods=['GET'])
@login_required
@permission_required('iptab_view')
def rules_conflicts():
    host_id = request.args.get('host_id')
    direction = str(request.args.get('direction') or 'INPUT').upper()
    if direction not in ('INPUT', 'OUTPUT'):
        return jsonify({'success': False, 'message': '无效方向，仅支持 INPUT/OUTPUT'}), 400
    if not host_id:
        return jsonify({'success': False, 'message': '缺少主机ID'}), 400

    try:
        host = _load_host_connection_info(host_id)
        if not host:
            return jsonify({'success': False, 'message': f'主机不存在: host_id={host_id}'}), 404

        if host['auth_method'] == 'password':
            iptables_output = pwd_shell_cmd(
                hostname=host['ip_address'],
                user=host['username'],
                port=host['ssh_port'],
                pwd=host['password'],
                cmd=f'iptables -nL {direction} --line-number -t filter'
            )
        else:
            iptables_output = sshkey_shell_cmd(
                hostname=host['ip_address'],
                user=host['username'],
                port=host['ssh_port'],
                private_key_str=host['private_key'],
                cmd=f'iptables -nL {direction} --line-number -t filter'
            )

        rules = get_rule(iptables_output)
        conflicts = _detect_rule_conflicts(rules)
        return jsonify({
            'success': True,
            'host_id': host_id,
            'direction': direction,
            'rules_count': len(rules),
            'conflicts': conflicts,
            'conflict_count': len(conflicts)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'冲突检测失败: {str(e)}'}), 500


# 修改规则
@app.route("/rules_update", methods=['POST'])
@login_required
@permission_required('iptab_edit')  # 添加规则编辑权限
def rules_update():
    all_params = request.get_json()
    host_id = all_params['host_id']
    rule_id = all_params['rule_id']
    direction = all_params['direction']
    auth_object_error = _validate_auth_object(all_params.get('auth_object'))
    if auth_object_error:
        return jsonify({'success': False, 'message': auth_object_error}), 400
    # 获取规则的具体数据
    try:
        host = _load_host_connection_info(host_id)
        if not host:
            return jsonify({'success': False, 'message': f'主机不存在: host_id={host_id}'}), 404
        hostname = host['ip_address']
        port = host['ssh_port']
        user = host['username']
        pwd = host['password']
        auth_method = host['auth_method']
        private_key = host['private_key']
        operating_system = host['operating_system']
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
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    else:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
                else:
                    if all_params['limit'] == '':
                        # tcp 或udp的所有端口
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['description'])
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                if all_params['limit'] == '':
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
                else:
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

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
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    else:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'],
                                all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
                else:
                    if all_params['limit'] == '':
                        # tcp 或udp的所有端口
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['description'])
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                if all_params['limit'] == '':
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
                else:
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

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
    print(all_params)
    host_id = all_params['host_id']
    rule_id = all_params['rule_id']
    direction = all_params['direction']
    protocol = (all_params.get('protocol') or '').lower()
    port = (all_params.get('port') or '').strip()
    auth_object = (all_params.get('auth_object') or '').strip()

    # 基础参数校验，避免明显非法请求进入SSH阶段
    if protocol in ('tcp', 'udp') and not port:
        return jsonify({'success': False, 'message': '端口不能为空'}), 400
    auth_object_error = _validate_auth_object(auth_object)
    if auth_object_error:
        return jsonify({'success': False, 'message': auth_object_error}), 400
    # 获取规则的具体数据
    try:
        host = _load_host_connection_info(host_id)
        if not host:
            return jsonify({'success': False, 'message': f'主机不存在: host_id={host_id}'}), 404
        hostname = host['ip_address']
        port = host['ssh_port']
        user = host['username']
        pwd = host['password']
        auth_method = host['auth_method']
        private_key = host['private_key']
        operating_system = host['operating_system']
        if auth_method == 'password':
            # 正常的tcp或udp规则
            if 'tcp' in all_params['protocol'] or 'udp' in all_params['protocol']:
                # 正常的端口
                if '-1/-1' not in all_params['port']:
                    # 添加规则中的：正常端口中的范围端口
                    if '-' in all_params['port']:
                        new_port = all_params['port'].replace("-", ":")
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    else:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
                else:
                    if all_params['limit'] == '':
                        # tcp 或udp的所有端口
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['description'])
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                if all_params['limit'] == '':
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
                else:
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

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
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], new_port,
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    # 添加规则中的: 正常端口中的多个端口
                    elif ',' in all_params['port']:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m comment --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} -m multiport --dports {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])

                    else:
                        if all_params['limit'] == '':
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m comment  --comment "{}"'.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['description'])
                        else:
                            cmd = 'iptables -I {}  {} -s {} -p {} --dport {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                                direction, rule_id, all_params['auth_object'], all_params['protocol'], all_params['port'],
                                all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
                else:
                    # tcp 或udp的所有端口
                    if all_params['limit'] == '':
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m comment  --comment "{}"'.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['description'])
                    else:
                        cmd = 'iptables -I {}  {} -s {} -p {} -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                            direction, rule_id, all_params['auth_object'], all_params['protocol'],
                            all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'])
            # ICMP 或 all 协议的规则
            else:
                if all_params['limit'] == '':
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m comment  --comment "{}"'.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['description'])
                else:
                    cmd = 'iptables -I {}  {} -s {} -p {}  -j {} -m hashlimit --hashlimit-mode srcip,dstport --hashlimit-above {} --hashlimit-name {} -m comment  --comment "{}" '.format(
                        direction, rule_id, all_params['auth_object'], all_params['protocol'],
                        all_params['auth_policy'], all_params['limit'], rule_id, all_params['description'], )

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
        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='防火墙规则',
            operation_summary=f"添加防火墙规则: {all_params['protocol']} {all_params['port']} ({direction})",
            operation_details=json.dumps({
                "host_id": host_id,
                "host_ip": hostname,
                "rule_id": rule_id,
                "direction": direction,
                "protocol": all_params['protocol'],
                "port": all_params['port'],
                "policy": all_params['auth_policy'],
                "source": all_params['auth_object'],
                "description": all_params['description'],
                "operating_system": operating_system,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )

        data_list = get_rule(iptables_output)
        return render_template('rule.html', data_list=data_list, id=host_id)
    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='防火墙规则',
            operation_summary=f"添加防火墙规则失败: {all_params.get('protocol')} {all_params.get('port')}",
            operation_details=json.dumps({
                "host_id": host_id,
                "rule_id": rule_id,
                "direction": direction,
                "request_data": all_params,  # 完整请求参数
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        # 错误处理
        return jsonify({'success': False, 'message': f"保存失败: {str(e)}"}), 500


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
        host = _load_host_connection_info(host_id)
        if not host:
            return jsonify({'success': False, 'message': f'主机不存在: host_id={host_id}'}), 404
        hostname = host['ip_address']
        port = host['ssh_port']
        user = host['username']
        pwd = host['password']
        auth_method = host['auth_method']
        private_key = host['private_key']
        operating_system = host['operating_system']
        deleted_rule = None
        list_cmd = f'iptables -nL {direction} --line-number -t filter'
        del_cmd = 'iptables -D {} {}'.format(direction, rule_id)
        if auth_method == 'password':
            before_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd, cmd=list_cmd)
            before_rules = get_rule(before_output)
            deleted_rule = next((item for item in before_rules if str(item.get('num', '')) == str(rule_id)), None)
            pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd, cmd=del_cmd)
            if operating_system == 'centos' or operating_system == 'redhat':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd,
                              cmd='iptables-save > /etc/iptables/rules.v4')
            refreshed_output = pwd_shell_cmd(hostname=hostname, user=user, port=port, pwd=pwd, cmd=list_cmd)
        else:
            before_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key, cmd=list_cmd)
            before_rules = get_rule(before_output)
            deleted_rule = next((item for item in before_rules if str(item.get('num', '')) == str(rule_id)), None)
            sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key, cmd=del_cmd)
            if operating_system == 'centos' or operating_system == 'redhat':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/sysconfig/iptables')
            elif operating_system == 'debian':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            elif operating_system == 'ubuntu':
                sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key,
                                 cmd='iptables-save > /etc/iptables/rules.v4')
            refreshed_output = sshkey_shell_cmd(hostname=hostname, user=user, port=port, private_key_str=private_key, cmd=list_cmd)
        if deleted_rule:
            _remove_port_rules_by_runtime_rule(hostname, direction, deleted_rule)
        data_list = get_rule(refreshed_output)
        host_options = _get_rule_view_hosts()
        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='防火墙规则',
            operation_summary=f"删除防火墙规则: ID {rule_id} (方向: {direction})",
            operation_details=json.dumps({
                "host_id": host_id,
                "host_ip": hostname,
                "rule_id": rule_id,
                "direction": direction,
                "operating_system": operating_system,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return render_template('rule.html', data_list=data_list, id=host_id, host_options=host_options)
    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='防火墙规则',
            operation_summary=f"删除防火墙规则失败: ID {rule_id} (方向: {direction})",
            operation_details=json.dumps({
                "host_id": host_id,
                "rule_id": rule_id,
                "direction": direction,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 查看主机
# 主机管理页面路由 - 读取数据库并返回数据到前端
@app.route("/hosts", methods=['GET'])
@login_required
@permission_required('hosts_view')  # 添加主机查看权限
def hosts():
    all_params = dict(request.args)
    page = all_params.get('page', '1')  # 默认为第1页
    search_keyword = all_params.get('search', '')  # 获取搜索关键词
    page_size = 10
    start = (int(page) - 1) * page_size
    end = int(page) * page_size
    try:
        host_list = []
        if USE_LOCAL_FILE_STORE:
            items = _read_hosts_from_store()
            if search_keyword:
                key = search_keyword.lower()
                items = [
                    item for item in items
                    if key in str(item.get('host_name', '')).lower()
                    or key in str(item.get('host_identifier', '')).lower()
                    or key in str(item.get('ip_address', '')).lower()
                ]
            items = sorted(items, key=lambda item: item.get('created_at', ''), reverse=True)
            for host in items:
                host_list.append({
                    'id': host.get('id'),
                    'ssh_port': host.get('ssh_port', 22),
                    'username': host.get('username', ''),
                    'auth_method': host.get('auth_method', 'password'),
                    'host_name': host.get('host_name', ''),
                    'host_identifier': host.get('host_identifier', ''),
                    'ip_address': host.get('ip_address', ''),
                    'operating_system': host.get('operating_system', ''),
                    'created_at': host.get('created_at', ''),
                    'status': host.get('status', 'unknown'),
                    'last_checked_at': host.get('last_checked_at', ''),
                    'last_check_error': host.get('last_check_error', '')
                })
        else:
            db = get_db()
            cursor = db.cursor()
            if search_keyword:
                cursor.execute('''
                SELECT id, username, auth_method, host_name, host_identifier, ip_address, 
                       operating_system, created_at, ssh_port, status, last_checked_at, last_check_error
                FROM hosts 
                WHERE host_name LIKE ? OR host_identifier LIKE ? OR ip_address LIKE ?
                ORDER BY created_at DESC
                ''', (f'%{search_keyword}%', f'%{search_keyword}%', f'%{search_keyword}%'))
            else:
                cursor.execute('''
                SELECT id, username, auth_method, host_name, host_identifier, ip_address, 
                       operating_system, created_at, ssh_port, status, last_checked_at, last_check_error
                FROM hosts 
                ORDER BY created_at DESC
                ''')
            hosts = cursor.fetchall()
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
                    'created_at': host['created_at'],
                    'status': host['status'] if 'status' in host.keys() else 'unknown',
                    'last_checked_at': host['last_checked_at'] if 'last_checked_at' in host.keys() else '',
                    'last_check_error': host['last_check_error'] if 'last_check_error' in host.keys() else ''
                })

        # 计算总页数（考虑搜索结果）
        total_items = len(host_list)
        total_pages = max(1, math.ceil(total_items / page_size)) if total_items else 1
        display_start = (start + 1) if total_items > 0 else 0
        display_end = min(end, total_items) if total_items > 0 else 0

        # 将主机数据和搜索关键词传递到模板
        return render_template('host.html',
                               host_list=host_list[start:end],
                               sum=total_items,
                               start=display_start,
                               end=display_end,  # 处理最后一页可能不足一页的情况
                               current_page=page,
                               total_pages=total_pages,
                               search_keyword=search_keyword)  # 传递搜索关键词到前端
    except Exception as e:
        # 错误处理
        return f"获取主机数据失败: {str(e)}", 500


# 添加主机
@app.route('/host_add', methods=['POST'])
@login_required
@permission_required('hosts_add')  # 添加主机添加权限
def add_host():
    data = None
    try:
        data = request.get_json()
        error_message, ssh_port = _validate_host_payload(data, is_update=False)
        if error_message:
            return jsonify({'success': False, 'message': error_message}), 400

        if USE_LOCAL_FILE_STORE:
            items = _read_hosts_from_store()
            identifier = data['host_identifier'].strip()
            if any(str(item.get('host_identifier', '')).strip() == identifier for item in items):
                return jsonify({'success': False, 'message': '主机标识已存在，请更换为唯一值（如 web-02）'}), 409
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            items.append({
                'id': _next_host_id(items),
                'host_name': data['host_name'],
                'host_identifier': identifier,
                'ip_address': data['ip_address'],
                'operating_system': data['operating_system'],
                'ssh_port': ssh_port,
                'username': data.get('username', ''),
                'auth_method': data.get('auth_method', 'password'),
                'password': encrypt_host_secret(data.get('password', '')),
                'private_key': encrypt_host_secret(data.get('private_key', '')),
                'status': 'unknown',
                'last_checked_at': '',
                'last_check_error': '',
                'created_at': now,
                'updated_at': now
            })
            _write_hosts_to_store(items)
        else:
            db = get_db()
            cursor = db.cursor()
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
                ssh_port,
                data.get('username', ''),
                data.get('auth_method', 'password'),
                encrypt_host_secret(data.get('password', '')),
                encrypt_host_secret(data.get('private_key', '')),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ))
            db.commit()
        # 【修改】日志记录增加operation_summary和JSON格式的operation_details
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='主机',
            operation_summary=f"添加了主机: {data['host_name']} ({data['ip_address']})",  # 简短摘要
            operation_details=json.dumps({  # 详细JSON数据
                "host_name": data['host_name'],
                "ip_address": data['ip_address'],
                "operating_system": data['operating_system'],
                "ssh_port": data.get('ssh_port', 22),
                "auth_method": data.get('auth_method', 'password')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '主机添加成功'})

    except sqlite3.IntegrityError:
        # 【修改】确保data已定义
        data = data or {}
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='主机',
            operation_summary=f"添加主机失败: {data.get('host_name', '未知主机')}",
            operation_details=json.dumps({
                "error": "主机标识已存在",
                "host_identifier": data.get('host_identifier')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': '主机标识已存在，请更换为唯一值（如 web-02）'}), 409
    except Exception as e:
        # 【修改】确保data已定义并提供默认值
        data = data or {}
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='主机',
            operation_summary=f"添加主机失败: {data.get('host_name', '未知主机')}",
            operation_details=json.dumps({
                "error": str(e),
                "host_data": {
                    "host_name": data.get('host_name'),
                    "ip_address": data.get('ip_address')
                }
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/host_test_connection', methods=['POST'])
@login_required
def host_test_connection():
    """
    测试主机SSH连通性，仅用于校验连接参数，不写入数据库。
    """
    test_start = time.time()
    data = request.get_json() or {}
    request_host_id = data.get('id')

    if not (current_user.has_permission('hosts_add') or current_user.has_permission('hosts_edit')):
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='测试连接',
            operation_object='主机',
            operation_summary=f"测试主机连接失败: ID {request_host_id} (无权限)",
            operation_details=json.dumps({
                "host_id": request_host_id,
                "error": "没有操作权限",
                "elapsed_ms": int((time.time() - test_start) * 1000),
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': '没有操作权限，请联系管理员获取权限'}), 403

    conn_data, error_message = _build_host_connection_payload(data)
    if error_message:
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='测试连接',
            operation_object='主机',
            operation_summary=f"测试主机连接失败: ID {request_host_id} (参数校验失败)",
            operation_details=json.dumps({
                "host_id": request_host_id,
                "error": error_message,
                "elapsed_ms": int((time.time() - test_start) * 1000),
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': error_message}), 400

    try:
        test_cmd = 'echo CONNECTION_OK'
        if conn_data['auth_method'] == 'password':
            output = pwd_shell_cmd(
                hostname=conn_data['ip_address'],
                port=conn_data['ssh_port'],
                user=conn_data['username'],
                pwd=conn_data['password'],
                cmd=test_cmd
            )
        else:
            output = sshkey_shell_cmd(
                hostname=conn_data['ip_address'],
                port=conn_data['ssh_port'],
                user=conn_data['username'],
                private_key_str=conn_data['private_key'],
                cmd=test_cmd
            )
        if 'CONNECTION_OK' not in (output or ''):
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='测试连接',
                operation_object='主机',
                operation_summary=f"测试主机连接失败: {conn_data['ip_address']}:{conn_data['ssh_port']} (返回异常)",
                operation_details=json.dumps({
                    "host_id": request_host_id,
                    "host_ip": conn_data['ip_address'],
                    "ssh_port": conn_data['ssh_port'],
                    "username": conn_data['username'],
                    "auth_method": conn_data['auth_method'],
                    "error": "连接建立成功，但命令执行返回异常",
                    "elapsed_ms": int((time.time() - test_start) * 1000),
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': '连接建立成功，但命令执行返回异常'}), 500
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='测试连接',
            operation_object='主机',
            operation_summary=f"测试主机连接成功: {conn_data['ip_address']}:{conn_data['ssh_port']}",
            operation_details=json.dumps({
                "host_id": request_host_id,
                "host_ip": conn_data['ip_address'],
                "ssh_port": conn_data['ssh_port'],
                "username": conn_data['username'],
                "auth_method": conn_data['auth_method'],
                "elapsed_ms": int((time.time() - test_start) * 1000),
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '主机连接测试成功'})
    except Exception as e:
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='测试连接',
            operation_object='主机',
            operation_summary=f"测试主机连接失败: {conn_data['ip_address']}:{conn_data['ssh_port']}",
            operation_details=json.dumps({
                "host_id": request_host_id,
                "host_ip": conn_data['ip_address'],
                "ssh_port": conn_data['ssh_port'],
                "username": conn_data['username'],
                "auth_method": conn_data['auth_method'],
                "error": str(e),
                "error_type": type(e).__name__,
                "elapsed_ms": int((time.time() - test_start) * 1000),
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': f'主机连接测试失败: {str(e)}'}), 500


@app.route('/host_refresh_status', methods=['POST'])
@login_required
@permission_required('hosts_view')
def host_refresh_status():
    """
    立即刷新单台主机状态，供主机管理页面手动触发。
    """
    payload = request.get_json(silent=True) or {}
    host_id = payload.get('id') or request.args.get('id')
    if not host_id:
        return jsonify({'success': False, 'message': '缺少主机ID'}), 400

    try:
        if USE_LOCAL_FILE_STORE:
            host = _find_host_in_store(host_id)
        else:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('''
            SELECT id, ip_address, ssh_port, username, auth_method, password, private_key
            FROM hosts WHERE id = ?
            ''', (host_id,))
            host = cursor.fetchone()
        if not host:
            return jsonify({'success': False, 'message': '主机不存在'}), 404

        result = _check_and_update_host_status(None if USE_LOCAL_FILE_STORE else cursor, host)
        if not USE_LOCAL_FILE_STORE:
            db.commit()
        return jsonify({
            'success': True,
            'message': '主机状态已刷新',
            'data': result
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'刷新状态失败: {str(e)}'}), 500


# 删除主机
@app.route('/host_del', methods=['DELETE'])
@login_required
@permission_required('hosts_del')  # 添加主机删除权限
def del_host():
    host = None
    host_id = request.args.get('id')
    try:
        if USE_LOCAL_FILE_STORE:
            items = _read_hosts_from_store()
            host = None
            remained = []
            for item in items:
                if str(item.get('id')) == str(host_id):
                    host = item
                else:
                    remained.append(item)
        else:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('SELECT host_name, ip_address, operating_system FROM hosts WHERE id = ?', (host_id,))
            host_row = cursor.fetchone()
            if host_row:
                columns = [column[0] for column in cursor.description]
                host = dict(zip(columns, host_row))
            else:
                host = None

        if not host:
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='主机',
                operation_summary=f"删除主机失败: ID {host_id} (主机不存在)",
                operation_details=json.dumps({
                    "host_id": host_id,
                    "error": "主机不存在",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': '主机不存在'}), 404

        if USE_LOCAL_FILE_STORE:
            _write_hosts_to_store(remained)
        else:
            cursor.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
            db.commit()

        # 【修复3】现在可以安全访问所有字段
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='主机',
            operation_summary=f"删除主机: {host['host_name']} ({host['ip_address']})",
            operation_details=json.dumps({
                "host_id": host_id,
                "host_name": host['host_name'],
                "ip_address": host['ip_address'],
                "operating_system": host['operating_system'],
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '主机删除成功'})
    except Exception as e:
        # 【修复4】确保host_info是可序列化的字典
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='主机',
            operation_summary=f"删除主机失败: ID {host_id}",
            operation_details=json.dumps({
                "host_id": host_id,
                "host_info": host,  # 现在是字典而非Row对象
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


# 修改主机
@app.route('/host_update', methods=['POST'])
@permission_required('hosts_edit')  # 添加主机编辑权限
@login_required
def update_host():
    data = request.get_json()
    if not isinstance(data, dict) or not data.get('id'):
        return jsonify({'success': False, 'message': '缺少主机ID'}), 400
    host_id = data['id']
    original_host_name = None
    try:
        error_message, ssh_port = _validate_host_payload(data, is_update=True)
        if error_message:
            return jsonify({'success': False, 'message': error_message}), 400

        if USE_LOCAL_FILE_STORE:
            items = _read_hosts_from_store()
            host = None
            for item in items:
                if str(item.get('id')) == str(host_id):
                    host = item
                    break
            if not host:
                return jsonify({'success': False, 'message': '主机不存在'}), 404
            original_host_name = host.get('host_name', '')
            original_ip = host.get('ip_address', '')
        else:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('SELECT host_name, ip_address FROM hosts WHERE id = ?', (host_id,))
            host = cursor.fetchone()
            if not host:
                return jsonify({'success': False, 'message': '主机不存在'}), 404
            original_host_name = host['host_name']
            original_ip = host['ip_address']

        # 不修改密码
        password_value = data.get('password')
        private_key_value = data.get('private_key')
        keep_original_auth = (
                (password_value is None or (isinstance(password_value, str) and not password_value.strip()))
                and (private_key_value is None or (isinstance(private_key_value, str) and not private_key_value.strip()))
        )

        if USE_LOCAL_FILE_STORE:
            identifier = data['host_identifier'].strip()
            for item in items:
                if str(item.get('id')) != str(host_id) and str(item.get('host_identifier', '')).strip() == identifier:
                    return jsonify({'success': False, 'message': '主机标识已存在，请更换为唯一值（如 web-02）'}), 409
            host['host_name'] = data['host_name']
            host['host_identifier'] = identifier
            host['ip_address'] = data['ip_address']
            host['operating_system'] = data['operating_system']
            host['ssh_port'] = ssh_port
            host['username'] = data['username']
            host['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if not keep_original_auth:
                host['auth_method'] = data['auth_method']
                host['password'] = encrypt_host_secret(data.get('password', ''))
                host['private_key'] = encrypt_host_secret(data.get('private_key', ''))
            _write_hosts_to_store(items)
        else:
            if keep_original_auth:
                cursor.execute(
                    'UPDATE hosts SET host_name = ?, host_identifier = ?, ip_address = ?, operating_system = ?, ssh_port = ?, username = ?, updated_at = ? WHERE id = ?;',
                    (data['host_name'], data['host_identifier'], data['ip_address'], data['operating_system'],
                     ssh_port, data['username'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), host_id))
                db.commit()
                if cursor.rowcount == 0:
                    return jsonify({'success': False, 'message': '主机不存在'}), 404
                return jsonify({'success': True, 'message': '主机编辑成功'})
            else:
                cursor.execute(
                    'UPDATE hosts SET host_name = ?, host_identifier = ?, ip_address = ?, operating_system = ?, ssh_port = ?, username = ?, auth_method = ?, password = ?, private_key = ? ,updated_at = ? WHERE id = ?;',
                    (data['host_name'], data['host_identifier'], data['ip_address'], data['operating_system'],
                     ssh_port, data['username'], data['auth_method'],
                     encrypt_host_secret(data['password']), encrypt_host_secret(data['private_key']),
                     datetime.now().strftime('%Y-%m-%d %H:%M:%S'), host_id))
                db.commit()
        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='编辑',
            operation_object='主机',
            operation_summary=f"编辑主机: {original_host_name} -> {data['host_name']}",
            operation_details=json.dumps({
                "host_id": host_id,
                "original": {
                    "host_name": original_host_name,
                    "ip_address": original_ip
                },
                "updated": {
                    "host_name": data['host_name'],
                    "ip_address": data['ip_address'],
                    "ssh_port": data['ssh_port'],
                    "operating_system": data['operating_system'],
                    "auth_method": data.get('auth_method')
                },
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '主机编辑成功'})
    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='编辑',
            operation_object='主机',
            operation_summary=f"编辑主机失败: ID {host_id}",
            operation_details=json.dumps({
                "host_id": host_id,
                "update_data": data,
                "original_host_name": original_host_name if 'original_host_name' in locals() else None,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route("/ssh_key_guide", methods=['GET'])
@login_required
def ssh_key_guide():
    return render_template("ssh_key_guide.html")


@app.route("/ssh_key_setup", methods=['POST'])
@login_required
@permission_required_any(['ssh_key_manage', 'hosts_add'])
def ssh_key_setup():
    try:
        validate_csrf_request()
    except Exception as csrf_error:
        return jsonify({'success': False, 'message': str(csrf_error)}), 403

    data = request.get_json(silent=True) or {}
    host_ip = (data.get('host_ip') or '').strip()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    key_type = (data.get('key_type') or 'ed25519').strip().lower()
    ssh_port = data.get('ssh_port', 22)

    if not host_ip:
        return jsonify({'success': False, 'message': '目标主机IP不能为空'}), 400
    if not username:
        return jsonify({'success': False, 'message': 'SSH用户名不能为空'}), 400
    if not password:
        return jsonify({'success': False, 'message': '请先输入目标主机密码（用于自动安装公钥）'}), 400
    if key_type not in ('ed25519', 'rsa'):
        return jsonify({'success': False, 'message': '密钥类型仅支持 ed25519 或 rsa'}), 400
    try:
        ssh_port = int(ssh_port)
        if ssh_port < 1 or ssh_port > 65535:
            raise ValueError
    except ValueError:
        return jsonify({'success': False, 'message': 'SSH端口必须是 1-65535 的整数'}), 400

    try:
        comment = f"iptables-web-{username}@{host_ip}"
        private_key_str, public_key_str = generate_ssh_key_pair(key_type=key_type, key_comment=comment)
        private_path, public_path = save_generated_key_files(
            host_ip=host_ip,
            key_type=key_type,
            private_key_str=private_key_str,
            public_key_str=public_key_str
        )
        install_public_key_with_password(
            hostname=host_ip,
            port=ssh_port,
            user=username,
            password=password,
            public_key_str=public_key_str
        )
        verify_key_authentication(
            hostname=host_ip,
            port=ssh_port,
            user=username,
            private_key_str=private_key_str
        )
        save_ssh_key_setup_record(
            host_ip=host_ip,
            ssh_port=ssh_port,
            target_username=username,
            key_type=key_type,
            private_key=private_key_str,
            public_key=public_key_str,
            private_key_path=private_path,
            public_key_path=public_path,
            setup_status='success',
            error_message=''
        )

        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='新增',
            operation_object='SSH密钥',
            operation_summary=f"一键配置主机SSH密钥成功: {host_ip}",
            operation_details=json.dumps({
                "host_ip": host_ip,
                "ssh_port": ssh_port,
                "target_username": username,
                "key_type": key_type,
                "private_key_path": private_path,
                "public_key_path": public_path,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )

        return jsonify({
            'success': True,
            'message': 'SSH密钥已自动配置并验证成功，可直接复制私钥到主机添加页面',
            'data': {
                'host_ip': host_ip,
                'ssh_port': ssh_port,
                'username': username,
                'key_type': key_type,
                'private_key': private_key_str,
                'public_key': public_key_str,
                'private_key_path': private_path,
                'public_key_path': public_path
            }
        })
    except Exception as e:
        try:
            save_ssh_key_setup_record(
                host_ip=host_ip,
                ssh_port=ssh_port,
                target_username=username,
                key_type=key_type,
                private_key='',
                public_key='',
                private_key_path='',
                public_key_path='',
                setup_status='failed',
                error_message=str(e)
            )
        except Exception as record_error:
            app.logger.error(f"写入 SSH 密钥配置失败记录失败: {str(record_error)}")

        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='新增',
            operation_object='SSH密钥',
            operation_summary=f"一键配置主机SSH密钥失败: {host_ip}",
            operation_details=json.dumps({
                "host_ip": host_ip,
                "ssh_port": ssh_port,
                "target_username": username,
                "key_type": key_type,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route("/ssh_key_setup_records", methods=['GET'])
@login_required
@permission_required_any(['ssh_key_manage', 'hosts_add'])
def ssh_key_setup_records():
    limit = request.args.get('limit', 20)
    keyword = (request.args.get('keyword') or '').strip()
    status = (request.args.get('status') or 'all').strip().lower()
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 20
    limit = max(1, min(limit, 100))

    try:
        if USE_LOCAL_FILE_STORE:
            records = _read_ssh_key_records_store()
            filtered = []
            key_lower = keyword.lower()
            for row in records:
                if keyword:
                    hay = f"{row.get('host_ip','')} {row.get('target_username','')} {row.get('key_type','')}".lower()
                    if key_lower not in hay:
                        continue
                revoke_status = row.get('revoke_status') or 'active'
                setup_status = row.get('setup_status') or 'success'
                if status == 'active':
                    if not (setup_status == 'success' and revoke_status == 'active'):
                        continue
                elif status == 'revoked':
                    if revoke_status != 'revoked':
                        continue
                elif status == 'setup_failed':
                    if setup_status == 'success':
                        continue
                elif status == 'revoke_failed':
                    if revoke_status != 'failed':
                        continue
                filtered.append(row)
            filtered.sort(key=lambda x: int(x.get('id', 0)), reverse=True)
            total = len(filtered)
            data_rows = filtered[:limit]
            out = []
            for row in data_rows:
                out.append({
                    'id': row.get('id'),
                    'host_ip': row.get('host_ip', ''),
                    'ssh_port': row.get('ssh_port', 22),
                    'target_username': row.get('target_username', ''),
                    'key_type': row.get('key_type', ''),
                    'has_private_key': bool(row.get('private_key')),
                    'public_key': row.get('public_key', ''),
                    'private_key_path': row.get('private_key_path', ''),
                    'public_key_path': row.get('public_key_path', ''),
                    'setup_status': row.get('setup_status', 'success'),
                    'error_message': row.get('error_message', ''),
                    'operator_user_id': row.get('operator_user_id'),
                    'operator_username': row.get('operator_username', ''),
                    'created_at': row.get('created_at', ''),
                    'revoke_status': row.get('revoke_status', 'active'),
                    'revoke_message': row.get('revoke_message', ''),
                    'revoked_at': row.get('revoked_at', '')
                })
            return jsonify({
                'success': True,
                'data': out,
                'meta': {'total': total, 'keyword': keyword, 'status': status}
            })

        db = get_db()
        cursor = db.cursor()
        where_clauses = []
        query_params = []

        if keyword:
            where_clauses.append('(host_ip LIKE ? OR target_username LIKE ? OR key_type LIKE ?)')
            keyword_like = f'%{keyword}%'
            query_params.extend([keyword_like, keyword_like, keyword_like])

        if status == 'active':
            where_clauses.append("setup_status = 'success' AND (revoke_status IS NULL OR revoke_status = '' OR revoke_status = 'active')")
        elif status == 'revoked':
            where_clauses.append("revoke_status = 'revoked'")
        elif status == 'setup_failed':
            where_clauses.append("setup_status != 'success'")
        elif status == 'revoke_failed':
            where_clauses.append("revoke_status = 'failed'")

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ''

        count_sql = f"SELECT COUNT(*) AS total FROM ssh_key_setup_records {where_sql}"
        cursor.execute(count_sql, tuple(query_params))
        total = cursor.fetchone()['total']

        data_sql = f'''
        SELECT id, host_ip, ssh_port, target_username, key_type, private_key, public_key,
               private_key_path, public_key_path, setup_status, error_message,
               operator_user_id, operator_username, created_at,
               revoke_status, revoke_message, revoked_at
        FROM ssh_key_setup_records
        {where_sql}
        ORDER BY id DESC
        LIMIT ?
        '''
        cursor.execute(data_sql, tuple(query_params + [limit]))
        rows = cursor.fetchall()
        records = []
        for row in rows:
            records.append({
                'id': row['id'],
                'host_ip': row['host_ip'],
                'ssh_port': row['ssh_port'],
                'target_username': row['target_username'],
                'key_type': row['key_type'],
                'has_private_key': bool(row['private_key']),
                'public_key': row['public_key'] or '',
                'private_key_path': row['private_key_path'] or '',
                'public_key_path': row['public_key_path'] or '',
                'setup_status': row['setup_status'] or 'success',
                'error_message': row['error_message'] or '',
                'operator_user_id': row['operator_user_id'],
                'operator_username': row['operator_username'] or '',
                'created_at': row['created_at'] or '',
                'revoke_status': row['revoke_status'] or 'active',
                'revoke_message': row['revoke_message'] or '',
                'revoked_at': row['revoked_at'] or ''
            })
        return jsonify({
            'success': True,
            'data': records,
            'meta': {
                'total': total,
                'keyword': keyword,
                'status': status
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'获取配置记录失败: {str(e)}'}), 500


@app.route("/ssh_key_setup_record/<int:record_id>", methods=['DELETE'])
@login_required
@permission_required_any(['ssh_key_manage', 'hosts_add'])
def delete_ssh_key_setup_record(record_id):
    try:
        validate_csrf_request()
    except Exception as csrf_error:
        return jsonify({'success': False, 'message': str(csrf_error)}), 403

    try:
        if USE_LOCAL_FILE_STORE:
            records = _read_ssh_key_records_store()
            record = next((item for item in records if int(item.get('id', 0)) == int(record_id)), None)
            if not record:
                return jsonify({'success': False, 'message': '配置记录不存在'}), 404
            if record.get('setup_status') == 'success' and (record.get('revoke_status') or 'active') != 'revoked':
                return jsonify({
                    'success': False,
                    'message': '请先执行“删除目标主机密钥”，再删除配置记录'
                }), 409
            remained = [item for item in records if int(item.get('id', 0)) != int(record_id)]
            _write_ssh_key_records_store(remained)
            removed_files = []
            remove_errors = []
            for file_path in [record.get('private_key_path'), record.get('public_key_path')]:
                if not file_path:
                    continue
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        removed_files.append(file_path)
                except Exception as file_error:
                    remove_errors.append(f"{file_path}: {str(file_error)}")
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='SSH密钥',
                operation_summary=f"删除SSH密钥配置记录: #{record_id}",
                operation_details=json.dumps({
                    "record_id": record_id,
                    "host_ip": record.get('host_ip'),
                    "ssh_port": record.get('ssh_port'),
                    "target_username": record.get('target_username'),
                    "key_type": record.get('key_type'),
                    "setup_status": record.get('setup_status'),
                    "removed_files": removed_files,
                    "remove_errors": remove_errors,
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            message = '配置记录删除成功'
            if remove_errors:
                message += '（部分本地密钥文件删除失败）'
            return jsonify({
                'success': True,
                'message': message,
                'data': {
                    'record_id': record_id,
                    'removed_files': removed_files,
                    'remove_errors': remove_errors
                }
            })

        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
        SELECT id, host_ip, ssh_port, target_username, key_type, private_key_path, public_key_path, setup_status, revoke_status
        FROM ssh_key_setup_records
        WHERE id = ?
        ''', (record_id,))
        record = cursor.fetchone()
        if not record:
            return jsonify({'success': False, 'message': '配置记录不存在'}), 404
        if record['setup_status'] == 'success' and (record['revoke_status'] or 'active') != 'revoked':
            return jsonify({
                'success': False,
                'message': '请先执行“删除目标主机密钥”，再删除配置记录'
            }), 409

        cursor.execute('DELETE FROM ssh_key_setup_records WHERE id = ?', (record_id,))
        db.commit()

        removed_files = []
        remove_errors = []
        for file_path in [record['private_key_path'], record['public_key_path']]:
            if not file_path:
                continue
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    removed_files.append(file_path)
            except Exception as file_error:
                remove_errors.append(f"{file_path}: {str(file_error)}")

        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='SSH密钥',
            operation_summary=f"删除SSH密钥配置记录: #{record_id}",
            operation_details=json.dumps({
                "record_id": record_id,
                "host_ip": record['host_ip'],
                "ssh_port": record['ssh_port'],
                "target_username": record['target_username'],
                "key_type": record['key_type'],
                "setup_status": record['setup_status'],
                "removed_files": removed_files,
                "remove_errors": remove_errors,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )

        message = '配置记录删除成功'
        if remove_errors:
            message += '（部分本地密钥文件删除失败）'
        return jsonify({
            'success': True,
            'message': message,
            'data': {
                'record_id': record_id,
                'removed_files': removed_files,
                'remove_errors': remove_errors
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'删除配置记录失败: {str(e)}'}), 500


@app.route("/ssh_key_setup_record/<int:record_id>/remove_target_key", methods=['POST'])
@login_required
@permission_required_any(['ssh_key_manage', 'hosts_add'])
def remove_target_key_by_record(record_id):
    try:
        validate_csrf_request()
    except Exception as csrf_error:
        return jsonify({'success': False, 'message': str(csrf_error)}), 403

    try:
        if USE_LOCAL_FILE_STORE:
            records = _read_ssh_key_records_store()
            record = next((item for item in records if int(item.get('id', 0)) == int(record_id)), None)
            if not record:
                return jsonify({'success': False, 'message': '配置记录不存在'}), 404
            if record.get('revoke_status') == 'revoked':
                return jsonify({'success': False, 'message': '该记录对应的目标主机公钥已删除'}), 409
            if not record.get('private_key') or not record.get('public_key'):
                return jsonify({'success': False, 'message': '记录缺少私钥或公钥信息，无法执行删除'}), 400
            private_key_plain = decrypt_host_secret(record.get('private_key'))
            remove_public_key_with_private_key(
                hostname=record.get('host_ip'),
                port=record.get('ssh_port'),
                user=record.get('target_username'),
                private_key_str=private_key_plain,
                public_key_str=record.get('public_key')
            )
            revoked_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            record['revoke_status'] = 'revoked'
            record['revoke_message'] = '目标主机公钥已删除'
            record['revoked_at'] = revoked_at
            _write_ssh_key_records_store(records)
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='SSH密钥',
                operation_summary=f"删除目标主机公钥成功: 记录#{record_id}",
                operation_details=json.dumps({
                    "record_id": record_id,
                    "host_ip": record.get('host_ip'),
                    "ssh_port": record.get('ssh_port'),
                    "target_username": record.get('target_username'),
                    "operation_time": revoked_at
                }),
                success=1
            )
            return jsonify({
                'success': True,
                'message': '目标主机公钥已删除',
                'data': {'record_id': record_id, 'revoked_at': revoked_at}
            })

        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
        SELECT id, host_ip, ssh_port, target_username, private_key, public_key, revoke_status
        FROM ssh_key_setup_records
        WHERE id = ?
        ''', (record_id,))
        record = cursor.fetchone()
        if not record:
            return jsonify({'success': False, 'message': '配置记录不存在'}), 404
        if record['revoke_status'] == 'revoked':
            return jsonify({'success': False, 'message': '该记录对应的目标主机公钥已删除'}), 409
        if not record['private_key'] or not record['public_key']:
            return jsonify({'success': False, 'message': '记录缺少私钥或公钥信息，无法执行删除'}), 400

        private_key_plain = decrypt_host_secret(record['private_key'])
        remove_public_key_with_private_key(
            hostname=record['host_ip'],
            port=record['ssh_port'],
            user=record['target_username'],
            private_key_str=private_key_plain,
            public_key_str=record['public_key']
        )

        revoked_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
        UPDATE ssh_key_setup_records
        SET revoke_status = ?, revoke_message = ?, revoked_at = ?
        WHERE id = ?
        ''', ('revoked', '目标主机公钥已删除', revoked_at, record_id))
        db.commit()

        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='SSH密钥',
            operation_summary=f"删除目标主机公钥成功: 记录#{record_id}",
            operation_details=json.dumps({
                "record_id": record_id,
                "host_ip": record['host_ip'],
                "ssh_port": record['ssh_port'],
                "target_username": record['target_username'],
                "operation_time": revoked_at
            }),
            success=1
        )
        return jsonify({
            'success': True,
            'message': '目标主机公钥已删除',
            'data': {'record_id': record_id, 'revoked_at': revoked_at}
        })
    except Exception as e:
        if USE_LOCAL_FILE_STORE:
            try:
                records = _read_ssh_key_records_store()
                record = next((item for item in records if int(item.get('id', 0)) == int(record_id)), None)
                if record:
                    record['revoke_status'] = 'failed'
                    record['revoke_message'] = str(e)
                    _write_ssh_key_records_store(records)
            except Exception:
                pass
            return jsonify({'success': False, 'message': f'删除目标主机公钥失败: {str(e)}'}), 500

        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                'UPDATE ssh_key_setup_records SET revoke_status = ?, revoke_message = ? WHERE id = ?',
                ('failed', str(e), record_id)
            )
            db.commit()
        except Exception:
            pass
        return jsonify({'success': False, 'message': f'删除目标主机公钥失败: {str(e)}'}), 500


@app.route("/ssh_key_setup_record/<int:record_id>/private_key", methods=['POST'])
@login_required
@permission_required_any(['ssh_key_manage', 'hosts_add'])
def get_private_key_by_record(record_id):
    try:
        validate_csrf_request()
    except Exception as csrf_error:
        return jsonify({'success': False, 'message': str(csrf_error)}), 403

    try:
        if USE_LOCAL_FILE_STORE:
            records = _read_ssh_key_records_store()
            row = next((item for item in records if int(item.get('id', 0)) == int(record_id)), None)
            if not row:
                return jsonify({'success': False, 'message': '配置记录不存在'}), 404
            if row.get('setup_status') != 'success':
                return jsonify({'success': False, 'message': '该记录配置失败，不支持查看私钥'}), 400
            if row.get('revoke_status') == 'revoked':
                return jsonify({'success': False, 'message': '该记录已删除目标主机公钥，禁止再次查看私钥'}), 403
            if not row.get('private_key'):
                return jsonify({'success': False, 'message': '该记录缺少私钥信息'}), 400
            private_key = decrypt_host_secret(row.get('private_key'))
            return jsonify({
                'success': True,
                'data': {
                    'id': row.get('id'),
                    'host_ip': row.get('host_ip'),
                    'ssh_port': row.get('ssh_port'),
                    'target_username': row.get('target_username'),
                    'key_type': row.get('key_type'),
                    'private_key': private_key,
                    'public_key': row.get('public_key') or '',
                    'private_key_path': row.get('private_key_path') or '',
                    'public_key_path': row.get('public_key_path') or '',
                    'created_at': row.get('created_at') or '',
                    'setup_status': row.get('setup_status') or 'success',
                    'revoke_status': row.get('revoke_status') or 'active'
                }
            })

        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
        SELECT id, setup_status, revoke_status, private_key, public_key,
               private_key_path, public_key_path, host_ip, ssh_port, target_username, key_type, created_at
        FROM ssh_key_setup_records
        WHERE id = ?
        ''', (record_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': '配置记录不存在'}), 404
        if row['setup_status'] != 'success':
            return jsonify({'success': False, 'message': '该记录配置失败，不支持查看私钥'}), 400
        if row['revoke_status'] == 'revoked':
            return jsonify({'success': False, 'message': '该记录已删除目标主机公钥，禁止再次查看私钥'}), 403
        if not row['private_key']:
            return jsonify({'success': False, 'message': '该记录缺少私钥信息'}), 400

        private_key = decrypt_host_secret(row['private_key'])
        return jsonify({
            'success': True,
            'data': {
                'id': row['id'],
                'host_ip': row['host_ip'],
                'ssh_port': row['ssh_port'],
                'target_username': row['target_username'],
                'key_type': row['key_type'],
                'private_key': private_key,
                'public_key': row['public_key'] or '',
                'private_key_path': row['private_key_path'] or '',
                'public_key_path': row['public_key_path'] or '',
                'created_at': row['created_at'] or '',
                'setup_status': row['setup_status'] or 'success',
                'revoke_status': row['revoke_status'] or 'active'
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'获取私钥失败: {str(e)}'}), 500


# 查看模板
@app.route("/templates", methods=['GET'])
@login_required
@permission_required('temp_view')
def templates():
    try:
        if USE_LOCAL_FILE_STORE:
            search_keyword = request.args.get('search', '').strip()
            result = _read_templates_from_store()
            if search_keyword:
                key = search_keyword.lower()
                result = [
                    item for item in result
                    if key in str(item.get('template_name', '')).lower()
                    or key in str(item.get('template_identifier', '')).lower()
                ]
            temp_info = []
            for res in result:
                data_list = []
                for idx, rule in enumerate(res.get('rules', []), start=1):
                    data_list.append({
                        'rule_id': rule.get('rule_id', idx),
                        'policy': rule.get('policy', ''),
                        'protocol': rule.get('protocol', ''),
                        'port': rule.get('port', ''),
                        'auth_object': rule.get('auth_object', ''),
                        'description': rule.get('description', ''),
                        'created_at': rule.get('created_at', res.get('created_at', '')),
                        'updated_at': rule.get('updated_at', res.get('updated_at', '')),
                        'limit': rule.get('limit', ''),
                    })
                temp_info.append({
                    'template_id': res.get('id'),
                    'template_name': res.get('template_name', ''),
                    'direction': res.get('direction', 'INPUT'),
                    'template_identifier': res.get('template_identifier', ''),
                    'updated_at': res.get('updated_at', ''),
                    'rules': data_list,
                })
            total_templates = len(temp_info)
            return render_template(
                'templates.html',
                data_list=temp_info,
                search_keyword=search_keyword,
                sum=total_templates
            )

        db = get_db()
        cursor = db.cursor()
        # 获取搜索关键词
        search_keyword = request.args.get('search', '').strip()

        # 根据是否有搜索关键词构建不同查询
        if search_keyword:
            # 带搜索条件的查询
            cursor.execute('''
            SELECT * FROM templates 
            WHERE template_name LIKE ? OR template_identifier LIKE ?
            ''', (f'%{search_keyword}%', f'%{search_keyword}%'))
        else:
            # 原有的无搜索条件查询
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
                    'updated_at': rule['updated_at'],
                    'limit': rule['limit'],
                })

            temp_info.append({'template_id': template_id,
                              'template_name': res['template_name'],
                              'direction': res['direction'],
                              'template_identifier': res['template_identifier'],
                              'updated_at': res['updated_at'],
                              'rules': data_list,
                              })
            # print(temp_info)

        # 计算符合条件的模板总数
        total_templates = len(temp_info)

    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': '模板名称已存在'}), 409
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

    # 传递搜索关键词和总数到前端
    return render_template(
        'templates.html',
        data_list=temp_info,
        search_keyword=search_keyword,
        sum=total_templates
    )


# 添加模板
@app.route("/temp_add", methods=['POST'])
@login_required
@permission_required('temp_add')
def templates_add():
    data = None
    try:
        data = request.get_json()
        validated_data, error_message = _validate_template_payload(data, is_edit=False)
        if error_message:
            return jsonify({'success': False, 'message': error_message}), 400

        if USE_LOCAL_FILE_STORE:
            templates_data = _read_templates_from_store()
            if any(
                str(item.get('template_name', '')).strip() == validated_data['name']
                for item in templates_data
            ):
                return jsonify({'success': False, 'message': '模板名称已存在'}), 409
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            template_id = _next_id(templates_data)
            rules = []
            for idx, rule in enumerate(validated_data['rules'], start=1):
                rules.append({
                    'rule_id': idx,
                    'policy': rule['policy'],
                    'protocol': rule['protocol'],
                    'port': rule['port'],
                    'auth_object': rule['auth_object'],
                    'description': rule['description'],
                    'limit': rule['limit'],
                    'created_at': now,
                    'updated_at': now
                })
            templates_data.append({
                'id': template_id,
                'template_name': validated_data['name'],
                'template_identifier': validated_data['description'],
                'direction': validated_data['direction'],
                'created_at': now,
                'updated_at': now,
                'rules': rules
            })
            _write_templates_to_store(templates_data)
            rule_count = len(validated_data['rules'])
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='添加',
                operation_object='模板',
                operation_summary=f"添加模板: {validated_data['name']} (规则数: {rule_count})",
                operation_details=json.dumps({
                    "template_id": template_id,
                    "template_name": validated_data['name'],
                    "direction": validated_data['direction'],
                    "description": validated_data['description'],
                    "rule_count": rule_count,
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({'success': True, 'message': '模板添加成功'})

        db = get_db()
        cursor = db.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 插入模板
        cursor.execute('''
        INSERT INTO templates 
        (template_name, template_identifier, direction,created_at, updated_at)
        VALUES (?, ?, ?, ?,?)
        ''', (
            validated_data['name'],
            validated_data['description'],
            validated_data['direction'],
            now,
            now
        ))
        template_id = cursor.lastrowid

        for rule in validated_data['rules']:
            cursor.execute('''
            INSERT INTO rules 
            (template_id, policy, protocol, port, auth_object, description, created_at, updated_at, "limit")
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                template_id,
                rule['policy'],
                rule['protocol'],
                rule['port'],
                rule['auth_object'],
                rule['description'],
                now,
                now,
                rule['limit']
            ))
        db.commit()

        rule_count = len(validated_data['rules'])
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='模板',
            operation_summary=f"添加模板: {validated_data['name']} (规则数: {rule_count})",
            operation_details=json.dumps({
                "template_id": template_id,
                "template_name": validated_data['name'],
                "direction": validated_data['direction'],
                "description": validated_data['description'],
                "rule_count": rule_count,
                "rules": [
                    {
                        "protocol": rule['protocol'],
                        "port": rule['port'],
                        "policy": "允许" if rule['policy'] == 'ACCEPT' else "拒绝",
                        "source": rule['auth_object'],
                        "description": rule['description'],
                        "limit": rule['limit']
                    } for rule in validated_data['rules']
                ],
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '模板添加成功'})

    except sqlite3.IntegrityError:
        # 【修复】记录失败日志
        data = data or {}
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='模板',
            operation_summary=f"添加模板失败: {data.get('name', '未知模板')} (标识已存在)",
            operation_details=json.dumps({
                "template_name": data.get('name'),
                "description": data.get('description'),
                "error": "模板标识已存在",
                "error_type": "IntegrityError",
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': '模板名称已存在'}), 409
    except Exception as e:
        # 【修复】记录失败日志
        data = data or {}
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='添加',
            operation_object='模板',
            operation_summary=f"添加模板失败: {data.get('name', '未知模板')}",
            operation_details=json.dumps({
                "template_name": data.get('name'),
                "request_data": data,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


# 删除模板
@app.route("/temp_del", methods=['DELETE'])
@login_required
@permission_required('temp_del')
def templates_del():
    template_id = request.args.get('temp_id')
    template = None  # 初始化template变量
    try:
        if USE_LOCAL_FILE_STORE:
            templates_data = _read_templates_from_store()
            target = None
            remained = []
            for item in templates_data:
                if str(item.get('id')) == str(template_id):
                    target = item
                else:
                    remained.append(item)
            if not target:
                return jsonify({'success': False, 'message': '模板不存在'}), 404
            _write_templates_to_store(remained)
            rule_count = len(target.get('rules', []))
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='模板',
                operation_summary=f"删除模板: {target.get('template_name', '')} (规则数: {rule_count})",
                operation_details=json.dumps({
                    "template_id": template_id,
                    "template_name": target.get('template_name', ''),
                    "deleted_rules": rule_count,
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({'success': True, 'message': '模板删除成功'})

        db = get_db()
        cursor = db.cursor()
        # 【新增】获取模板名称用于日志
        cursor.execute('SELECT template_name, direction FROM templates WHERE id = ?', (template_id,))
        template = cursor.fetchone()
        if not template:
            return jsonify({'success': False, 'message': '模板不存在'}), 404
        template_name = template['template_name']
        direction = template['direction']

        # 查询模板规则，后续用于清理主机上对应iptables规则
        cursor.execute('''
        SELECT policy, protocol, port, auth_object, description, "limit"
        FROM rules WHERE template_id = ?
        ''', (template_id,))
        template_rules = cursor.fetchall()

        # 获取该模板曾应用过的主机ID，若日志中没有，则兜底扫描所有主机
        applied_host_ids = _collect_template_applied_host_ids(cursor, template_id)
        if applied_host_ids:
            safe_host_ids = [int(host_id) for host_id in applied_host_ids if str(host_id).isdigit()]
            if not safe_host_ids:
                safe_host_ids = [-1]
            placeholders = ','.join(['?'] * len(safe_host_ids))
            cursor.execute('''
            SELECT id, ssh_port, username, ip_address, auth_method, password, private_key, operating_system
            FROM hosts WHERE id IN ({})
            '''.format(placeholders), tuple(safe_host_ids))
        else:
            cursor.execute('''
            SELECT id, ssh_port, username, ip_address, auth_method, password, private_key, operating_system
            FROM hosts
            ''')
        target_hosts = cursor.fetchall()

        deleted_rule_total = 0
        failed_hosts = []
        for host in target_hosts:
            try:
                deleted_count = _delete_template_rules_on_host(host, direction, template_rules)
                deleted_rule_total += deleted_count
            except Exception as host_error:
                failed_hosts.append({
                    'host_id': host['id'],
                    'host_ip': host['ip_address'],
                    'error': str(host_error)
                })

        # 任一主机清理失败时，阻止删除模板，避免模板与主机规则状态不一致
        if failed_hosts:
            return jsonify({
                'success': False,
                'message': '模板规则清理失败，已阻止模板删除',
                'failed_hosts': failed_hosts
            }), 500

        # 查询该模板下的规则数量
        cursor.execute('SELECT COUNT(*) as rule_count FROM rules WHERE template_id = ?', (template_id,))
        rule_count = cursor.fetchone()['rule_count']

        # 删除模板与模板规则
        cursor.execute('DELETE FROM templates WHERE id = ?', (template_id,))
        cursor.execute('DELETE FROM rules WHERE template_id = ?', (template_id,))
        db.commit()
        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='模板',
            operation_summary=f"删除模板: {template_name} (规则数: {rule_count})",
            operation_details=json.dumps({
                "template_id": template_id,
                "template_name": template_name,
                "deleted_rules": rule_count,
                "deleted_host_rules": deleted_rule_total,
                "affected_hosts": len(target_hosts),
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )

        if cursor.rowcount == 0:
            return jsonify({'success': False, 'message': '模板不存在'}), 404
        return jsonify({'success': True, 'message': '模板删除成功'})
    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='模板',
            operation_summary=f"删除模板失败: ID {template_id}",
            operation_details=json.dumps({
                "template_id": template_id,
                "template_name": template['template_name'] if template else None,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


# 修改模板
@app.route("/temp_edit", methods=['POST'])
@login_required
@permission_required('temp_edit')
def templates_edit():
    data = None
    original_template_name = None
    try:
        data = request.get_json()
        validated_data, error_message = _validate_template_payload(data, is_edit=True)
        if error_message:
            return jsonify({'success': False, 'message': error_message}), 400

        if USE_LOCAL_FILE_STORE:
            templates_data = _read_templates_from_store()
            target = None
            for item in templates_data:
                if str(item.get('id')) == str(validated_data['temp_id']):
                    target = item
                    break
            if not target:
                return jsonify({'success': False, 'message': '模板不存在'}), 404
            for item in templates_data:
                if str(item.get('id')) != str(validated_data['temp_id']) and str(item.get('template_name', '')).strip() == validated_data['name']:
                    return jsonify({'success': False, 'message': '模板名称已存在'}), 409
            original_template_name = target.get('template_name', '')
            old_rule_count = len(target.get('rules', []))
            new_rule_count = len(validated_data['rules'])
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            target['template_name'] = validated_data['name']
            target['template_identifier'] = validated_data['description']
            target['direction'] = validated_data['direction']
            target['updated_at'] = now
            new_rules = []
            for idx, rule in enumerate(validated_data['rules'], start=1):
                new_rules.append({
                    'rule_id': idx,
                    'policy': rule['policy'],
                    'protocol': rule['protocol'],
                    'port': rule['port'],
                    'auth_object': rule['auth_object'],
                    'description': rule['description'],
                    'limit': rule.get('limit', ''),
                    'created_at': now,
                    'updated_at': now
                })
            target['rules'] = new_rules
            _write_templates_to_store(templates_data)
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='编辑',
                operation_object='模板',
                operation_summary=f"编辑模板: {original_template_name} -> {validated_data['name']} (规则数: {old_rule_count}→{new_rule_count})",
                operation_details=json.dumps({
                    "template_id": validated_data['temp_id'],
                    "original": {"name": original_template_name, "rule_count": old_rule_count},
                    "updated": {
                        "name": validated_data['name'],
                        "description": validated_data['description'],
                        "direction": validated_data['direction'],
                        "rule_count": new_rule_count
                    },
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({'success': True, 'message': '模板修改成功'})

        db = get_db()
        cursor = db.cursor()

        # 【新增】获取原模板名称用于日志
        cursor.execute('SELECT template_name FROM templates WHERE id = ?', (validated_data['temp_id'],))
        template = cursor.fetchone()
        if not template:
            return jsonify({'success': False, 'message': '模板不存在'}), 404
        original_template_name = template['template_name']

        # 获取修改前后的规则数量
        cursor.execute('SELECT COUNT(*) as old_count FROM rules WHERE template_id = ?', (validated_data['temp_id'],))
        old_rule_count = cursor.fetchone()['old_count']
        new_rule_count = len(validated_data['rules'])
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 修改模板信息
        cursor.execute('''
        UPDATE  templates set template_name = ?, template_identifier = ?, direction = ?, updated_at =? WHERE id = ?;
        ''', (
            validated_data['name'],
            validated_data['description'],
            validated_data['direction'],
            now,
            validated_data['temp_id']
        ))
        # 先删除旧规则
        cursor.execute('DELETE FROM rules WHERE template_id = ?', (validated_data['temp_id'],))
        rule_count = 0

        for rule in validated_data['rules']:
            # 添加新规则
            cursor.execute('''
            INSERT INTO rules 
            (template_id, policy, protocol, port, auth_object, description, created_at, updated_at, "limit")
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                validated_data['temp_id'],
                rule['policy'],
                rule['protocol'],
                rule['port'],
                rule['auth_object'],
                rule['description'],
                now,
                now,
                rule.get('limit', '')  # 添加limit字段
            ))
            rule_count += 1
        db.commit()
        # 【修复】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='编辑',
            operation_object='模板',
            operation_summary=f"编辑模板: {original_template_name} -> {validated_data['name']} (规则数: {old_rule_count}→{new_rule_count})",
            operation_details=json.dumps({
                "template_id": validated_data['temp_id'],
                "original": {
                    "name": original_template_name,
                    "rule_count": old_rule_count
                },
                "updated": {
                    "name": validated_data['name'],
                    "description": validated_data['description'],
                    "direction": validated_data['direction'],
                    "rule_count": new_rule_count
                },
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '模板修改成功'})

    except sqlite3.IntegrityError:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='编辑',
            operation_object='模板',
            operation_summary=f"编辑模板失败: {original_template_name or '未知模板'}",
            operation_details=json.dumps({
                "template_id": data.get('temp_id') if isinstance(data, dict) else None,
                "error": "模板名称已存在",
                "error_type": "IntegrityError",
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': '模板名称已存在'}), 409
    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='编辑',
            operation_object='模板',
            operation_summary=f"编辑模板失败: {original_template_name or '未知模板'}",
            operation_details=json.dumps({
                "template_id": data.get('temp_id'),
                "update_data": data,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': str(e)}), 500


# 应用模板获取主机列表
@app.route("/temp_host_api", methods=['GET'])
@login_required
def temp_host_api():
    try:
        if USE_LOCAL_FILE_STORE:
            host_list = []
            hosts = sorted(_read_hosts_from_store(), key=lambda x: x.get('created_at', ''), reverse=True)
            for host in hosts:
                host_list.append({
                    'id': host.get('id'),
                    'host_name': host.get('host_identifier', '')
                })
            return jsonify({'success': True, 'data': host_list})

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
    all_params = request.get_json(silent=True) or {}
    template_id = all_params.get('template_id')
    host_ids_list = all_params.get('host_ids') or []
    try:
        if not template_id:
            return jsonify({'success': False, 'message': '缺少模板ID'}), 400
        if not isinstance(host_ids_list, list) or len(host_ids_list) == 0:
            return jsonify({'success': False, 'message': '请至少选择一台主机'}), 400

        cursor = None
        if not USE_LOCAL_FILE_STORE:
            db = get_db()
            cursor = db.cursor()
        template_name, direction, cmd_list, build_error = _build_template_apply_payload(cursor, template_id)
        if build_error:
            return jsonify({'success': False, 'message': build_error}), 404
        if not cmd_list:
            return jsonify({'success': False, 'message': '模板无可应用规则'}), 400

        hosts = _get_hosts_by_ids(cursor, host_ids_list)
        if not hosts:
            return jsonify({'success': False, 'message': '未找到目标主机'}), 404

        failed_hosts = []
        for host in hosts:
            try:
                for cmd in cmd_list:
                    _run_cmd_on_host(host, cmd)
                _persist_iptables(host)
            except Exception as host_error:
                failed_hosts.append({
                    'host_id': host['id'],
                    'host_ip': host['ip_address'],
                    'error': str(host_error)
                })

        if failed_hosts:
            return jsonify({
                'success': False,
                'message': '部分主机应用失败',
                'failed_hosts': failed_hosts
            }), 500

        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='应用',
            operation_object='模板',
            operation_summary=f"应用模板到主机: {template_name} ({len(hosts)}台主机)",
            operation_details=json.dumps({
                "template_id": template_id,
                "template_name": template_name,
                "direction": direction,
                "applied_hosts": [
                    {"host_id": host['id'], "host_name": host['host_name'] or host['host_identifier']}
                    for host in hosts
                ],
                "applied_rules": len(cmd_list),
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': "成功"})
    except Exception as e:
        # 【修复】记录失败日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='应用',
            operation_object='模板',
            operation_summary=f"应用模板失败: ID {template_id}",
            operation_details=json.dumps({
                "template_id": template_id,
                "host_ids": host_ids_list,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        # 错误处理，同样返回JSON格式
        return jsonify({
            'success': False,
            'message': f"获取主机数据失败: {str(e)}"
        }), 500


@app.route("/temp_to_hosts_precheck", methods=['POST'])
@login_required
@permission_required('iptab_add')
def temp_to_hosts_precheck():
    all_params = request.get_json(silent=True) or {}
    template_id = all_params.get('template_id')
    host_ids_list = all_params.get('host_ids') or []
    try:
        if not template_id:
            return jsonify({'success': False, 'message': '缺少模板ID'}), 400
        if not isinstance(host_ids_list, list) or len(host_ids_list) == 0:
            return jsonify({'success': False, 'message': '请至少选择一台主机'}), 400

        cursor = None
        if not USE_LOCAL_FILE_STORE:
            db = get_db()
            cursor = db.cursor()
        template_name, _, cmd_list, build_error = _build_template_apply_payload(cursor, template_id)
        if build_error:
            return jsonify({'success': False, 'message': build_error}), 404
        hosts = _get_hosts_by_ids(cursor, host_ids_list)
        if not hosts:
            return jsonify({'success': False, 'message': '未找到目标主机'}), 404

        check_results = []
        for host in hosts:
            host_item = {
                'host_id': host['id'],
                'host_name': host['host_name'] or host['host_identifier'],
                'host_ip': host['ip_address'],
                'ok': True,
                'message': '连接与权限检查通过'
            }
            try:
                _run_cmd_on_host(host, 'iptables -S >/dev/null 2>&1 || iptables -L >/dev/null 2>&1')
            except Exception as host_error:
                host_item['ok'] = False
                host_item['message'] = str(host_error)
            check_results.append(host_item)

        passed_count = len([item for item in check_results if item['ok']])
        return jsonify({
            'success': True,
            'message': '预检查完成',
            'data': {
                'template_id': template_id,
                'template_name': template_name,
                'rule_count': len(cmd_list),
                'total_hosts': len(check_results),
                'passed_hosts': passed_count,
                'failed_hosts': len(check_results) - passed_count,
                'hosts': check_results
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'预检查失败: {str(e)}'}), 500


@app.route("/temp_copy", methods=['POST'])
@login_required
@permission_required('temp_add')
def temp_copy():
    payload = request.get_json(silent=True) or {}
    template_id = payload.get('template_id')
    if not template_id:
        return jsonify({'success': False, 'message': '缺少模板ID'}), 400
    try:
        if USE_LOCAL_FILE_STORE:
            templates_data = _read_templates_from_store()
            source_template = next((item for item in templates_data if str(item.get('id')) == str(template_id)), None)
            if not source_template:
                return jsonify({'success': False, 'message': '模板不存在'}), 404
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            copied_name = f"{source_template.get('template_name', '')}-副本"
            copied_identifier = f"{source_template.get('template_identifier', '')}（复制于{datetime.now().strftime('%m-%d %H:%M')}）"
            new_template_id = _next_id(templates_data)
            copied_rules = []
            for idx, rule in enumerate(source_template.get('rules', []), start=1):
                copied_rule = dict(rule)
                copied_rule['rule_id'] = idx
                copied_rule['created_at'] = now
                copied_rule['updated_at'] = now
                copied_rules.append(copied_rule)
            templates_data.append({
                'id': new_template_id,
                'template_name': copied_name,
                'template_identifier': copied_identifier,
                'direction': source_template.get('direction', 'INPUT'),
                'created_at': now,
                'updated_at': now,
                'rules': copied_rules
            })
            _write_templates_to_store(templates_data)
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='复制',
                operation_object='模板',
                operation_summary=f"复制模板: {source_template.get('template_name', '')} -> {copied_name}",
                operation_details=json.dumps({
                    'source_template_id': template_id,
                    'source_template_name': source_template.get('template_name', ''),
                    'new_template_id': new_template_id,
                    'new_template_name': copied_name,
                    'rule_count': len(copied_rules),
                    'operation_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({'success': True, 'message': '模板复制成功'})

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT template_name, template_identifier, direction FROM templates WHERE id = ?', (template_id,))
        source_template = cursor.fetchone()
        if not source_template:
            return jsonify({'success': False, 'message': '模板不存在'}), 404

        cursor.execute('''
        SELECT policy, protocol, port, auth_object, description, "limit"
        FROM rules WHERE template_id = ?
        ''', (template_id,))
        source_rules = cursor.fetchall()

        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        copied_name = f"{source_template['template_name']}-副本"
        copied_identifier = f"{source_template['template_identifier']}（复制于{datetime.now().strftime('%m-%d %H:%M')}）"
        cursor.execute('''
        INSERT INTO templates (template_name, template_identifier, direction, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ''', (copied_name, copied_identifier, source_template['direction'], now, now))
        new_template_id = cursor.lastrowid

        for rule in source_rules:
            cursor.execute('''
            INSERT INTO rules (template_id, policy, protocol, port, auth_object, description, created_at, updated_at, "limit")
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                new_template_id,
                rule['policy'],
                rule['protocol'],
                rule['port'],
                rule['auth_object'],
                rule['description'],
                now,
                now,
                rule['limit']
            ))
        db.commit()

        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='复制',
            operation_object='模板',
            operation_summary=f"复制模板: {source_template['template_name']} -> {copied_name}",
            operation_details=json.dumps({
                'source_template_id': template_id,
                'source_template_name': source_template['template_name'],
                'new_template_id': new_template_id,
                'new_template_name': copied_name,
                'rule_count': len(source_rules),
                'operation_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '模板复制成功'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': '模板复制失败，模板名称冲突'}), 409
    except Exception as e:
        return jsonify({'success': False, 'message': f'模板复制失败: {str(e)}'}), 500


# 系统设置
@app.route("/systemseting", methods=['GET'])
@login_required
@permission_required('sys_view')  # 添加系统设置查看权限
def systemseting():
    return render_template('systemseting.html')


# 系统配置接口
@app.route('/api/system-config', methods=['GET', 'POST'])
@login_required  # 添加登录验证
def get_system_config():
    if request.method == "GET":
        @permission_required('sys_view')
        def get_config():
            try:
                if USE_LOCAL_FILE_STORE:
                    config = _read_system_config_store()
                    return jsonify(config or {})
                db = get_db()
                config = db.execute('SELECT * FROM system_config ORDER BY id DESC LIMIT 1').fetchone()
                return jsonify(dict(config)) if config else jsonify({})
            except Exception as e:
                app.logger.error(f"获取系统配置失败: {str(e)}")
                return jsonify({'error': '获取系统配置失败'}), 500

        # 调用嵌套函数并返回结果
        return get_config()
    else:
        @permission_required('sys_edit')
        def update_config():
            data = None
            try:
                data = request.get_json()
                if USE_LOCAL_FILE_STORE:
                    original_config = _read_system_config_store()
                    if not original_config:
                        return jsonify({'error': '系统配置不存在'}), 404
                    updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    original_config['system_name'] = data['system_name']
                    original_config['session_timeout'] = int(data['default_session_timeout'])
                    original_config['log_retention_time'] = str(data['log_retention_days'])
                    original_config['color_mode'] = data['color_mode']
                    original_config['password_strategy'] = data['password_strategy']
                    original_config['updated_at'] = updated_at
                    _write_system_config_store(original_config)
                    log_operation(
                        user_id=current_user.id,
                        username=current_user.username,
                        operation_type='编辑',
                        operation_object='系统设置',
                        operation_summary=f"更新系统设置: {data['system_name']}",
                        operation_details=json.dumps({
                            "updated": {
                                "system_name": data['system_name'],
                                "session_timeout": data['default_session_timeout'],
                                "log_retention": data['log_retention_days'],
                                "color_mode": data['color_mode'],
                                "password_strategy": data['password_strategy']
                            },
                            "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }),
                        success=1
                    )
                    return jsonify({'success': True, 'message': '保存系统配置成功'})

                db = get_db()
                cursor = db.cursor()
                # 获取原始配置用于日志
                cursor.execute('SELECT * FROM system_config ORDER BY id DESC LIMIT 1')
                original_row = cursor.fetchone()
                if not original_row:
                    return jsonify({'error': '系统配置不存在'}), 404
                original_config = dict(original_row)

                system_name = data['system_name']
                default_session_timeout = data['default_session_timeout']
                log_retention_time = data['log_retention_days']
                color_mode = data['color_mode']
                password_strategy = data['password_strategy']
                updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # 动态更新字段，兼容不同版本的 system_config 表结构
                cursor.execute("PRAGMA table_info(system_config)")
                available_columns = {row[1] for row in cursor.fetchall()}
                update_pairs = [
                    ('system_name', system_name),
                    ('session_timeout', default_session_timeout),
                    ('log_retention_time', log_retention_time),
                    ('color_mode', color_mode),
                    ('password_strategy', password_strategy),
                    ('updated_at', updated_at)
                ]

                set_clause = ', '.join([f"{col} = ?" for col, _ in update_pairs])
                values = [val for _, val in update_pairs]
                values.append(original_config.get('id', 1))
                cursor.execute(
                    f"UPDATE system_config SET {set_clause} WHERE id = ?",
                    tuple(values)
                )
                db.commit()
                # 【修复】记录成功日志
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='编辑',
                    operation_object='系统设置',
                    operation_summary=f"更新系统设置: {data['system_name']}",
                    operation_details=json.dumps({
                        "original": {
                            "system_name": original_config['system_name'],
                            "session_timeout": original_config['session_timeout'],
                            "log_retention": original_config['log_retention_time'],
                            "color_mode": original_config['color_mode']
                        },
                        "updated": {
                            "system_name": data['system_name'],
                            "session_timeout": data['default_session_timeout'],
                            "log_retention": data['log_retention_days'],
                            "color_mode": data['color_mode'],
                            "password_strategy": data['password_strategy']
                        },
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=1
                )
                return jsonify({'success': True, 'message': '保存系统配置成功'})
            except Exception as e:
                # 【修复】记录失败日志
                data = data or {}
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='编辑',
                    operation_object='系统设置',
                    operation_summary=f"更新系统设置失败",
                    operation_details=json.dumps({
                        "update_data": data,
                        "error": str(e),
                        "error_type": type(e).__name__,
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )
                app.logger.error(f"保存系统配置失败: {str(e)}")
                return jsonify({'error': '保存系统配置失败'}), 500

        # 调用嵌套函数并返回结果
        return update_config()


# 获取会话超时时间（从数据库）
def get_session_timeout():
    """从数据库获取会话超时时间（分钟），默认30分钟"""
    try:
        if USE_LOCAL_FILE_STORE:
            config = _read_system_config_store()
            return int(config.get('session_timeout', 30))
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
        if USE_LOCAL_FILE_STORE:
            users = _read_users_from_store()
            target = None
            for user in users:
                if str(user.get('id')) == str(self.id):
                    target = user
                    break
            if not target:
                return False
            role_ids = {str(role_id) for role_id in (target.get('role_ids') or [])}
            for role in _read_roles_from_store():
                if str(role.get('id')) in role_ids:
                    if permission_code in (role.get('permission_codes') or []):
                        return True
            return False

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
    if USE_LOCAL_FILE_STORE:
        users = _read_users_from_store()
        roles = _read_roles_from_store()
        user = next((item for item in users if str(item.get('id')) == str(user_id)), None)
        if not user or user.get('status') != 'active':
            return None
        role_map = {str(role.get('id')): role for role in roles}
        user_roles = []
        for role_id in user.get('role_ids', []):
            role = role_map.get(str(role_id))
            if role:
                user_roles.append({'id': role.get('id'), 'name': role.get('role_name')})
        return User(
            user_id=user.get('id'),
            username=user.get('username'),
            roles=user_roles
        )

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

        if USE_LOCAL_FILE_STORE:
            user_data = next(
                (item for item in _read_users_from_store() if item.get('username') == username),
                None
            )
        else:
            db = get_db()
            user_data = db.execute('SELECT id, username, password, status FROM user WHERE username = ?',
                                   (username,)).fetchone()

        if not user_data:
            return jsonify(success=False, message='用户名不存在') if request.headers.get(
                'X-Requested-With') == 'XMLHttpRequest' else \
                render_template('login.html', error='用户名不存在')

        if user_data.get('status') != 'active':
            return jsonify(success=False, message='用户已被禁用') if request.headers.get(
                'X-Requested-With') == 'XMLHttpRequest' else \
                render_template('login.html', error='用户已被禁用')

        try:
            password_ok = verify_user_password(user_data.get('password', ''), password)
        except ValueError as verify_error:
            app.logger.error(f"登录密码校验失败: {str(verify_error)}")
            return jsonify(success=False, message=str(verify_error)) if request.headers.get(
                'X-Requested-With') == 'XMLHttpRequest' else \
                render_template('login.html', error=str(verify_error))

        if not password_ok:
            return jsonify(success=False, message='密码不正确') if request.headers.get(
                'X-Requested-With') == 'XMLHttpRequest' else \
                render_template('login.html', error='密码不正确')

        # 加载用户角色信息
        user = load_user(user_data.get('id'))
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
    if USE_LOCAL_FILE_STORE:
        if request.method == "GET":
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                try:
                    users_data = [{'username': item.get('username', '')} for item in _read_users_from_store()]
                    return jsonify({"success": True, "users": users_data})
                except Exception:
                    return jsonify({"success": False, "message": "获取用户列表失败"}), 500
            users_data = _read_users_from_store()
            roles_map = {str(role.get('id')): role.get('role_name', '') for role in _read_roles_from_store()}
            user_list = []
            for item in users_data:
                role_names = [roles_map.get(str(role_id), '') for role_id in item.get('role_ids', []) if roles_map.get(str(role_id))]
                user_list.append({
                    'id': item.get('id'),
                    'roles': ', '.join(role_names) if role_names else 'None',
                    'username': item.get('username', ''),
                    'email': item.get('email', ''),
                    'status': item.get('status', 'active'),
                    'created_at': item.get('created_at', '')
                })
            return render_template('systemseting.html', user_list=user_list)

        user_data = request.get_json() or {}
        username = (user_data.get('username') or '').strip()
        password = user_data.get('password') or ''
        email = (user_data.get('email') or '').strip()
        status = user_data.get('status', 'active')
        role_id = user_data.get('role')
        if not username or not password or not email or not role_id:
            return jsonify({"success": False, "message": "用户名、密码、邮箱、角色为必填项"}), 400
        users_data = _read_users_from_store()
        if any(item.get('username') == username for item in users_data):
            return jsonify({"success": False, "message": "用户名已存在，请更换！"}), 409
        if any(item.get('email') == email for item in users_data):
            return jsonify({"success": False, "message": "邮箱已存在，请更换！"}), 409
        try:
            role_id_int = int(role_id)
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": "无效的角色ID格式"}), 400
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        user_id = _next_id(users_data)
        users_data.append({
            'id': user_id,
            'username': username,
            'password': hash_user_password(password),
            'email': email,
            'status': status,
            'role_ids': [role_id_int],
            'created_at': now,
            'updated_at': now
        })
        _write_users_to_store(users_data)
        return jsonify({"success": True, "message": "用户添加成功！"}), 200

    # 如果是查看用户管理页面
    if request.method == "GET":
        # 新增：如果是AJAX请求，返回用户列表JSON数据（用于日志筛选）
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            try:
                db = get_db()
                cursor = db.cursor()
                cursor.execute('SELECT DISTINCT username FROM operation_logs ORDER BY username')
                users = [{'username': row['username']} for row in cursor.fetchall()]
                return jsonify({"success": True, "users": users})
            except Exception as e:
                app.logger.error(f"获取用户列表失败: {str(e)}")
                return jsonify({"success": False, "message": "获取用户列表失败"}), 500

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
                return render_template('systemseting.html', user_list=user_list)
            except Exception as e:
                # 添加异常情况下的响应
                return jsonify({
                    "success": False,
                    "message": f"获取用户列表失败: {str(e)}"
                }), 500

        # 调用嵌套函数并返回结果
        return get_users()
    # 如果是添加用户
    elif request.method == 'POST':
        db = get_db()

        @permission_required('user_add')
        def add_user():
            # 初始化可能在日志中使用的变量
            username = ""
            email = ""
            role_id = ""
            status = "active"
            user_data = None  # 初始化user_data变量
            try:
                # 获取JSON数据而非表单数据
                user_data = request.get_json()
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
                hashed_password = hash_user_password(password)
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
                # 【修复】记录成功日志（添加summary和JSON格式details）
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='添加',
                    operation_object='用户',
                    operation_summary=f"添加用户: {username}",  # 简略摘要
                    operation_details=json.dumps({  # JSON格式详细信息
                        "user_id": user_id,
                        "username": username,
                        "email": email,
                        "status": status,
                        "role_id": role_id,
                        "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=1
                )

                return jsonify({
                    "success": True,
                    "message": "用户添加成功！"
                }), 200

            except sqlite3.IntegrityError as e:
                db.rollback()
                # 【修复】记录失败日志（添加summary和JSON格式details）
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='添加',
                    operation_object='用户',
                    operation_summary=f"添加用户失败: {username} (用户名/邮箱已存在)",  # 简略摘要
                    operation_details=json.dumps({  # JSON格式详细信息
                        "username": username,
                        "email": email,
                        "conflict_field": "用户名" if db.execute("SELECT 1 FROM user WHERE username = ?",
                                                                 (username,)).fetchone() else "邮箱",
                        "error": "用户名或邮箱已存在",
                        "error_type": "IntegrityError",
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )
                return jsonify({
                    "success": False,
                    "message": "用户名或邮箱已存在，请更换！"
                }), 409
            except Exception as e:
                # 【修复】记录失败日志（添加summary和JSON格式details）
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='添加',
                    operation_object='用户',
                    operation_summary=f"添加用户失败: {username}",  # 简略摘要
                    operation_details=json.dumps({  # JSON格式详细信息
                        "username": username,
                        "email": email,
                        "role_id": role_id,
                        "request_data": {
                            "username": username,
                            "email": email,
                            "status": status,
                            "role_id": role_id
                        },
                        "error": str(e),
                        "error_type": type(e).__name__,
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )

                if 'db' in locals():
                    db.rollback()
                return jsonify({
                    "success": False,
                    "message": f"添加失败：{str(e)}"
                }), 500

        # 调用嵌套函数并返回结果
        return add_user()


@app.route('/user_edit', methods=['GET', 'POST'])
@login_required
@permission_required('user_edit')
def user_edit():
    if USE_LOCAL_FILE_STORE:
        users_data = _read_users_from_store()
        roles_data = _read_roles_from_store()
        if request.method == 'GET':
            user_id = request.args.get('id')
            user = next((item for item in users_data if str(item.get('id')) == str(user_id)), None)
            if not user:
                return jsonify({'success': False, 'message': '用户不存在'}), 404
            roles = [{'id': role.get('id'), 'role_name': role.get('role_name', '')} for role in roles_data]
            return jsonify({
                'success': True,
                'user': {
                    'id': user.get('id'),
                    'username': user.get('username', ''),
                    'email': user.get('email', ''),
                    'status': user.get('status', 'active')
                },
                'roles': roles,
                'user_roles': user.get('role_ids', [])
            })
        data = request.get_json() or {}
        user_id = data.get('id')
        user = next((item for item in users_data if str(item.get('id')) == str(user_id)), None)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        user['username'] = data.get('username', user.get('username', ''))
        user['email'] = data.get('email', user.get('email', ''))
        user['status'] = data.get('status', user.get('status', 'active'))
        if data.get('password'):
            user['password'] = hash_user_password(data.get('password'))
        if 'role' in data:
            role_payload = data.get('role', [])
            if isinstance(role_payload, list):
                role_list = role_payload
            elif role_payload is None:
                role_list = []
            else:
                role_list = [role_payload]
            user['role_ids'] = [int(role_id) for role_id in role_list if str(role_id).isdigit()]
        user['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        _write_users_to_store(users_data)
        return jsonify({'success': True, 'message': '用户更新成功'})

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
        # 初始化可能在日志中使用的变量，避免"赋值前引用"
        data = request.get_json() or {}  # 确保data是字典，避免None
        user_id = data.get('id', 'unknown')  # 安全获取用户ID
        original_username = "未知用户"
        original_status = "unknown"
        username = "unknown"
        email = "unknown"
        status = "unknown"
        roles = []
        operation_type = "编辑"

        db = get_db()
        try:
            cursor = db.cursor()
            # 获取用户当前信息，用于处理部分更新情况（添加status字段）
            # 【修改】重命名变量，避免与Flask-Login的current_user冲突
            cursor.execute('SELECT username, email, status FROM user WHERE id = ?', (user_id,))
            user_data = cursor.fetchone()  # 将变量名从current_user改为user_data
            if not user_data:
                # 记录用户不存在日志
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='编辑',
                    operation_object='用户',
                    operation_summary=f"编辑用户失败: ID {user_id} (用户不存在)",
                    operation_details=json.dumps({
                        "user_id": user_id,
                        "error": "用户不存在",
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )
                return jsonify({'success': False, 'message': '用户不存在'}), 404

            # 更新变量值（确保所有日志变量都已初始化）
            original_username = user_data['username']
            original_status = user_data['status']
            username = data.get('username', original_username)
            email = data.get('email', user_data['email'])
            status = data.get('status', user_data['status'])
            roles = data.get('role', [])
            operation_type = '禁用' if status == 'inactive' and original_status == 'active' else '编辑'

            # 更新用户基本信息
            if 'password' in data and data['password']:
                # 如果提供了新密码，则更新密码
                hashed_password = hash_user_password(data['password'])
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
            # 【新增】记录成功日志
            details = f"用户名: {original_username}, 状态变更: {original_status}→{status}"
            if 'role' in data:
                details += f", 角色变更: {data.get('role')}"
            # 记录成功日志（标准化格式）
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type=operation_type,
                operation_object='用户',
                operation_summary=f"{operation_type}用户: {original_username}",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "user_id": user_id,
                    "original_info": {
                        "username": original_username,
                        "email": user_data['email'],
                        "status": original_status
                    },
                    "updated_info": {
                        "username": username,
                        "email": email,
                        "status": status,
                        "roles": roles,
                        "password_updated": 'password' in data and bool(data['password'])
                    },
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({'success': True, 'message': '用户更新成功'})
        except sqlite3.IntegrityError:
            db.rollback()
            # 【新增】记录失败日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='编辑',
                operation_object='用户',
                operation_summary=f"编辑用户失败: {original_username} (用户名/邮箱已存在)",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "user_id": user_id,
                    "conflict_info": {
                        "username": username,
                        "email": email,
                        "conflict_field": "用户名" if db.execute("SELECT 1 FROM user WHERE username = ?",
                                                                 (username,)).fetchone() else "邮箱"
                    },
                    "error": "用户名或邮箱已存在",
                    "error_type": "IntegrityError",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': '用户名或邮箱已存在'}), 409
        except Exception as e:
            db.rollback()
            # 【新增】记录失败日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='编辑',
                operation_object='用户',
                operation_summary=f"编辑用户失败: {original_username}",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "user_id": user_id,
                    "user_info": {
                        "original_username": original_username,
                        "target_username": username,
                        "email": email
                    },
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': f"更新用户失败: {str(e)}"}), 500


@app.route('/user_del', methods=['DELETE'])
@login_required
@permission_required('user_del')
def user_del():
    user_id = request.args.get('id')
    if USE_LOCAL_FILE_STORE:
        if int(user_id) == int(current_user.id):
            return jsonify({'success': False, 'message': '不能删除当前登录用户'}), 400
        users_data = _read_users_from_store()
        remained = [item for item in users_data if str(item.get('id')) != str(user_id)]
        if len(remained) == len(users_data):
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        _write_users_to_store(remained)
        return jsonify({'success': True, 'message': '用户删除成功'})

    # 防止删除自己
    if int(user_id) == current_user.id:
        return jsonify({'success': False, 'message': '不能删除当前登录用户'}), 400
    db = get_db()
    # 初始化变量，避免赋值前引用问题
    username = "未知用户"  # <-- 添加默认值
    cursor = None  # <-- 初始化cursor
    try:
        cursor = db.cursor()

        # 【新增】获取用户名用于日志
        cursor.execute('SELECT username FROM user WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='用户',
                operation_summary=f"删除用户失败: ID {user_id} (用户不存在)",
                operation_details=json.dumps({
                    "user_id": user_id,
                    "error": "用户不存在",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        username = user['username']
        # 删除用户角色关联
        cursor.execute('DELETE FROM user_roles WHERE user_id = ?', (user_id,))
        # 删除用户
        cursor.execute('DELETE FROM user WHERE id = ?', (user_id,))
        if cursor.rowcount == 0:
            db.rollback()
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='用户',
                operation_summary=f"删除用户失败: ID {user_id} (用户不存在)",
                operation_details=json.dumps({
                    "user_id": user_id,
                    "error": "用户不存在",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        db.commit()
        # 【新增】记录成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='用户',
            operation_summary=f"删除用户: {username}",
            operation_details=json.dumps({
                "user_id": user_id,
                "username": username,
                "deleted_roles": cursor.rowcount,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '用户删除成功'})
    except Exception as e:
        db.rollback()
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='用户',
            operation_summary=f"删除用户: {username}",
            operation_details=json.dumps({
                "user_id": user_id,
                "username": username,
                "deleted_roles": cursor.rowcount,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': False, 'message': f"删除用户失败: {str(e)}"}), 500


@app.route('/user/<int:user_id>/roles', methods=['POST'])
@login_required
@permission_required('user_assign')
def assign_user_roles(user_id):
    data = request.get_json()
    roles = data['roles']
    if USE_LOCAL_FILE_STORE:
        users_data = _read_users_from_store()
        target = next((item for item in users_data if str(item.get('id')) == str(user_id)), None)
        if not target:
            return jsonify({'success': False, 'message': '用户不存在'}), 404
        target['role_ids'] = [int(role_id) for role_id in roles if str(role_id).isdigit()]
        target['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        _write_users_to_store(users_data)
        return jsonify({'success': True, 'message': '角色分配成功'})

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
    if USE_LOCAL_FILE_STORE:
        roles_data = _read_roles_from_store()
        users_data = _read_users_from_store()
        if request.method == 'GET':
            role_list = []
            for role in roles_data:
                role_id = role.get('id')
                user_count = sum(1 for user in users_data if role_id in (user.get('role_ids') or []))
                role_list.append({
                    'id': role_id,
                    'role_name': role.get('role_name', ''),
                    'role_description': role.get('role_description', ''),
                    'permissions': role.get('permission_codes', []),
                    'user_count': user_count,
                    'created_at': role.get('created_at', ''),
                    'updated_at': role.get('updated_at', '')
                })
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': True, 'roles': role_list})
            return render_template('systemseting.html', role_list=role_list)

        if not current_user.has_permission('role_add'):
            return jsonify(success=False, message='没有添加角色权限'), 403
        role_data = request.get_json() or {}
        role_name = (role_data.get('role_name') or '').strip()
        if not role_name:
            return jsonify({"success": False, "message": "角色名不能为空"}), 400
        if any(role.get('role_name') == role_name for role in roles_data):
            return jsonify({"success": False, "message": "角色名称已存在"}), 409
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        role_id = _next_id(roles_data)
        permission_codes = _permission_codes_from_payload(role_data.get('permissions', []))
        roles_data.append({
            'id': role_id,
            'role_name': role_name,
            'role_description': role_data.get('role_description', ''),
            'permission_codes': permission_codes,
            'created_at': now,
            'updated_at': now
        })
        _write_roles_to_store(roles_data)
        return jsonify({"success": True, "message": "角色添加成功！"}), 200

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
        # 【修复】提前初始化role_data变量，确保所有代码路径都能访问
        role_data = None  # <-- 添加此行，在try块外初始化变量
        try:
            # 获取JSON数据（而非表单数据）
            role_data = request.get_json()
            if not role_data:
                return jsonify({"success": False, "message": "请求数据格式错误，应为JSON"}), 400
            cursor = db.cursor()

            # 创建角色 - 使用role_data而非request.form
            role_name = role_data.get('role_name')
            role_description = role_data.get('role_description', '')

            cursor.execute(''' 
                INSERT INTO roles (role_name, role_description, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                 ''', (
                role_name,  # <-- 修复：从JSON数据获取
                role_description,  # <-- 修复：从JSON数据获取，提供默认值
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
            # 获取权限名称列表用于日志
            permission_names = []
            if permissions:
                placeholders = ', '.join(['?'] * len(permissions))
                cursor.execute(f'SELECT code FROM permissions WHERE id IN ({placeholders})', permissions)
                permission_names = [row['code'] for row in cursor.fetchall()]
            db.commit()
            # 【新增】记录成功日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='添加',
                operation_object='角色',
                operation_summary=f"添加角色: {role_name}",  # 简略摘要
                operation_details=json.dumps({  # JSON格式详细信息
                    "role_id": role_id,
                    "role_name": role_name,
                    "role_description": role_description,
                    "permissions": {
                        "count": len(permissions),
                        "permission_ids": permissions,
                        "permission_codes": permission_names
                    },
                    "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({"success": True, "message": "角色添加成功！"}), 200
        except sqlite3.IntegrityError as e:
            db.rollback()
            # 【修复】记录失败日志，确保role_data已初始化
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='添加',
                operation_object='角色',
                operation_summary=f"添加角色失败: {(role_data.get('role_name') if role_data else '未知角色')} (角色名称已存在)",
                # 安全获取角色名
                operation_details=json.dumps({
                    "role_name": role_data.get('role_name') if role_data else None,
                    "role_description": role_data.get('role_description', '') if role_data else '',
                    "permissions": {
                        "count": len(role_data.get('permissions', [])) if role_data else 0,
                        "permission_ids": role_data.get('permissions', []) if role_data else []
                    },
                    "error": "角色名称已存在",
                    "error_type": "IntegrityError",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({"success": False, "message": f"错误：{str(e)}"}), 500
        except Exception as e:
            db.rollback()
            # 【修复】确保role_data已初始化，避免赋值前引用
            role_data = role_data or {}  # <-- 添加此行确保role_data是字典
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='添加',
                operation_object='角色',
                operation_summary=f"添加角色失败: {role_data.get('role_name', '未知角色')}",  # 现在安全了
                operation_details=json.dumps({
                    "role_name": role_data.get('role_name'),
                    "role_description": role_data.get('role_description', ''),
                    "permissions": {
                        "count": len(role_data.get('permissions', [])),
                        "permission_ids": role_data.get('permissions', [])
                    },
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({"success": False, "message": f"错误：{str(e)}"}), 500


@app.route('/role_edit', methods=['GET', 'POST'])
@login_required
@permission_required('role_edit')
def role_edit():
    if USE_LOCAL_FILE_STORE:
        roles_data = _read_roles_from_store()
        if request.method == 'GET':
            role_id = request.args.get('id')
            role = next((item for item in roles_data if str(item.get('id')) == str(role_id)), None)
            if not role:
                return jsonify({'success': False, 'message': '角色不存在'}), 404
            return jsonify({
                'success': True,
                'role': {
                    'id': role.get('id'),
                    'role_name': role.get('role_name', ''),
                    'role_description': role.get('role_description', '')
                },
                'permissions': role.get('permission_codes', [])
            })
        data = request.get_json() or {}
        role_id = data.get('id')
        role = next((item for item in roles_data if str(item.get('id')) == str(role_id)), None)
        if not role:
            return jsonify({'success': False, 'message': '角色不存在'}), 404
        role['role_name'] = data.get('role_name', role.get('role_name', ''))
        role['role_description'] = data.get('role_description', role.get('role_description', ''))
        if 'permissions' in data and isinstance(data.get('permissions'), list):
            role['permission_codes'] = _permission_codes_from_payload(data.get('permissions'))
        role['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        _write_roles_to_store(roles_data)
        return jsonify({'success': True, 'message': '角色更新成功'})

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
        role_id = data.get('id')
        db = get_db()
        # 初始化变量，避免赋值前引用
        original_role_name = "未知角色"
        permissions = []
        permission_codes = []

        try:
            cursor = db.cursor()
            # 获取原角色名称用于日志
            cursor.execute('SELECT role_name FROM roles WHERE id = ?', (role_id,))
            role = cursor.fetchone()
            if not role:
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='编辑',
                    operation_object='角色',
                    operation_summary=f"编辑角色失败: 角色ID {role_id} (角色不存在)",
                    operation_details=json.dumps({
                        "role_id": role_id,
                        "error": "角色不存在",
                        "error_type": "NotFoundError",
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )
                return jsonify(success=False, message='角色不存在'), 404
            original_role_name = role['role_name']

            # 初始化权限变量
            permissions = data.get('permissions', [])

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
                cursor.execute('DELETE FROM role_permissions WHERE role_id = ?', (role_id,))
                permissions = data['permissions']
                if permissions:
                    cursor.executemany('''
                    INSERT INTO role_permissions (role_id, permission_id)
                    VALUES (?, ?)
                    ''', [(role_id, p) for p in permissions])

                # 获取权限名称用于日志详情
                if permissions:
                    placeholders = ', '.join(['?'] * len(permissions))
                    cursor.execute(f'SELECT code FROM permissions WHERE id IN ({placeholders})', permissions)
                    permission_codes = [row['code'] for row in cursor.fetchall()]

            db.commit()
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='编辑',
                operation_object='角色',
                operation_summary=f"编辑角色: {original_role_name} → {data['role_name']}",
                operation_details=json.dumps({
                    "role_id": role_id,
                    "original_role_name": original_role_name,
                    "new_role_name": data['role_name'],
                    "role_description": data['role_description'],
                    "permissions": {
                        "count": len(permissions),
                        "permission_ids": permissions,
                        "permission_codes": permission_codes
                    },
                    "updated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({'success': True, 'message': '角色更新成功'})

        except Exception as e:
            db.rollback()
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='编辑',
                operation_object='角色',
                operation_summary=f"编辑角色失败: {original_role_name}",
                operation_details=json.dumps({
                    "role_id": role_id,
                    "original_role_name": original_role_name,
                    "request_data": {
                        "new_role_name": data.get('role_name'),
                        "role_description": data.get('role_description'),
                        "permission_count": len(permissions)
                    },
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': f"更新角色失败: {str(e)}"}), 500


@app.route('/role_del', methods=['DELETE'])
@login_required
@permission_required('role_del')
def role_del():
    role_id = request.args.get('id')
    if USE_LOCAL_FILE_STORE:
        if int(role_id) == 1:
            return jsonify({'success': False, 'message': '不能删除默认管理员角色'}), 400
        roles_data = _read_roles_from_store()
        users_data = _read_users_from_store()
        role_id_int = int(role_id)
        if any(role_id_int in (user.get('role_ids') or []) for user in users_data):
            return jsonify({'success': False, 'message': '该角色已分配给用户，请先移除用户关联'}), 400
        remained = [item for item in roles_data if int(item.get('id', 0)) != role_id_int]
        if len(remained) == len(roles_data):
            return jsonify({'success': False, 'message': '角色不存在'}), 404
        _write_roles_to_store(remained)
        return jsonify({'success': True, 'message': '角色删除成功'})

    # 防止删除管理员角色
    if int(role_id) == 1:
        return jsonify({'success': False, 'message': '不能删除默认管理员角色'}), 400
    db = get_db()
    # 初始化变量避免赋值前引用
    role_name = "未知角色"
    deleted_permissions_count = 0

    try:
        cursor = db.cursor()
        # 获取角色名称用于日志
        cursor.execute('SELECT role_name FROM roles WHERE id = ?', (role_id,))
        role = cursor.fetchone()
        if not role:
            # 【优化】角色不存在日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='角色',
                operation_summary=f"删除角色失败: 角色ID {role_id} (角色不存在)",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "role_id": role_id,
                    "error": "角色不存在",
                    "error_type": "NotFoundError",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify(success=False, message='角色不存在'), 404
        role_name = role['role_name']

        # 检查是否有关联用户
        cursor.execute('SELECT COUNT(*) as count FROM user_roles WHERE role_id = ?', (role_id,))
        count = cursor.fetchone()['count']
        if count > 0:
            # 【新增】关联用户存在时记录日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='角色',
                operation_summary=f"删除角色失败: {role_name} (已分配给{count}个用户)",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "role_id": role_id,
                    "role_name": role_name,
                    "user_count": count,
                    "error": "角色已分配给用户，无法删除",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            db.rollback()
            return jsonify({'success': False, 'message': f'该角色已分配给{count}个用户，请先移除用户关联'}), 400

        # 删除角色权限关联
        cursor.execute('DELETE FROM role_permissions WHERE role_id = ?', (role_id,))
        deleted_permissions_count = cursor.rowcount  # 记录删除的权限关联数量

        # 删除角色
        cursor.execute('DELETE FROM roles WHERE id = ?', (role_id,))
        deleted_role_count = cursor.rowcount

        if deleted_role_count == 0:
            db.rollback()
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='删除',
                operation_object='角色',
                operation_summary=f"删除角色失败: 角色ID {role_id} (角色不存在)",
                operation_details=json.dumps({
                    "role_id": role_id,
                    "error": "角色不存在",
                    "error_type": "NotFoundError",
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({'success': False, 'message': '角色不存在'}), 404

        db.commit()
        # 【优化】删除成功日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='角色',
            operation_summary=f"删除角色: {role_name} (ID: {role_id})",  # 简略摘要
            operation_details=json.dumps({  # JSON详细信息
                "role_id": role_id,
                "role_name": role_name,
                "deleted_permissions_count": deleted_permissions_count,
                "deleted_role_count": deleted_role_count,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=1
        )
        return jsonify({'success': True, 'message': '角色删除成功'})

    except Exception as e:
        db.rollback()
        # 【优化】异常日志
        log_operation(
            user_id=current_user.id,
            username=current_user.username,
            operation_type='删除',
            operation_object='角色',
            operation_summary=f"删除角色失败: {role_name}",  # 简略摘要
            operation_details=json.dumps({  # JSON详细信息
                "role_id": role_id,
                "role_name": role_name,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }),
            success=0
        )
        return jsonify({'success': False, 'message': f"删除角色失败: {str(e)}"}), 500


@app.route('/roles/<int:role_id>/permissions', methods=['GET', 'POST'])
@login_required
@permission_required('role_assign')  # 分配权限需要role_assign权限
def role_permissions(role_id):
    if USE_LOCAL_FILE_STORE:
        roles_data = _read_roles_from_store()
        role = next((item for item in roles_data if int(item.get('id', 0)) == int(role_id)), None)
        if not role:
            return jsonify({"success": False, "message": "角色不存在"}), 404
        if request.method == 'GET':
            all_permissions = _build_permission_response(role.get('permission_codes') or [])
            return jsonify({"success": True, "permissions": all_permissions})
        permissions = request.json.get('permissions', [])
        role['permission_codes'] = _permission_codes_from_payload(permissions)
        role['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        _write_roles_to_store(roles_data)
        return jsonify({"success": True, "message": "权限分配成功！"})

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
        cursor = db.cursor()
        # 初始化变量避免赋值前引用
        role_name = "未知角色"
        old_permissions = []
        permission_codes = []
        try:
            # 获取角色名称和现有权限用于日志
            cursor.execute('SELECT role_name FROM roles WHERE id = ?', (role_id,))
            role = cursor.fetchone()
            if not role:
                # 【优化】角色不存在日志
                log_operation(
                    user_id=current_user.id,
                    username=current_user.username,
                    operation_type='分配',
                    operation_object='角色权限',
                    operation_summary=f"分配角色权限失败: 角色ID {role_id} (角色不存在)",  # 简略摘要
                    operation_details=json.dumps({  # JSON详细信息
                        "role_id": role_id,
                        "error": "角色不存在",
                        "error_type": "NotFoundError",
                        "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }),
                    success=0
                )
                return jsonify({"success": False, "message": "角色不存在"}), 404
            role_name = role['role_name']
            # 获取原权限列表用于变更对比
            cursor.execute('SELECT permission_id FROM role_permissions WHERE role_id = ?', (role_id,))
            old_permissions = [row['permission_id'] for row in cursor.fetchall()]
            # 先删除现有权限
            cursor.execute('DELETE FROM role_permissions WHERE role_id = ?', (role_id,))
            # 添加新权限
            if permissions:
                cursor.executemany('''
                INSERT INTO role_permissions (role_id, permission_id)
                VALUES (?, ?)
                ''', [(role_id, p) for p in permissions])
                # 获取权限代码用于日志详情
                placeholders = ', '.join(['?'] * len(permissions))
                cursor.execute(f'SELECT id, code FROM permissions WHERE id IN ({placeholders})', permissions)
                permission_codes = {row['id']: row['code'] for row in cursor.fetchall()}
            db.commit()
            # 【优化】分配成功日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='分配',
                operation_object='角色权限',
                operation_summary=f"分配角色权限: {role_name} (权限数量: {len(permissions)})",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "role_id": role_id,
                    "role_name": role_name,
                    "permission_changes": {
                        "old_count": len(old_permissions),
                        "new_count": len(permissions),
                        "added": list(set(permissions) - set(old_permissions)),
                        "removed": list(set(old_permissions) - set(permissions)),
                        "total_changed": abs(len(permissions) - len(old_permissions))
                    },
                    "current_permissions": {
                        "count": len(permissions),
                        "permission_ids": permissions,
                        "permission_codes": permission_codes  # 权限代码映射
                    },
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=1
            )
            return jsonify({"success": True, "message": "权限分配成功！"})
        except Exception as e:
            db.rollback()
            # 【优化】分配失败日志
            log_operation(
                user_id=current_user.id,
                username=current_user.username,
                operation_type='分配',
                operation_object='角色权限',
                operation_summary=f"分配角色权限失败: {role_name}",  # 简略摘要
                operation_details=json.dumps({  # JSON详细信息
                    "role_id": role_id,
                    "role_name": role_name,
                    "requested_permissions": {
                        "count": len(permissions),
                        "permission_ids": permissions
                    },
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "operation_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }),
                success=0
            )
            return jsonify({"success": False, "message": f"权限分配失败：{str(e)}"}), 500


# 操作日志
@app.route("/logs", methods=['GET'])
@login_required
@permission_required('log_view')
def logs():
    def build_filter_conditions():
        query_conditions = []
        query_params = []

        operation_type = request.args.get('operation_type')
        operation_object = request.args.get('operation_object')
        success = request.args.get('success')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        search_keyword = request.args.get('search', '').strip()
        username = request.args.get('username')

        if operation_type:
            type_values = [t.strip() for t in operation_type.split(',') if t.strip()]
            if len(type_values) == 1:
                query_conditions.append("operation_type = ?")
                query_params.append(type_values[0])
            elif len(type_values) > 1:
                placeholders = ', '.join(['?'] * len(type_values))
                query_conditions.append(f"operation_type IN ({placeholders})")
                query_params.extend(type_values)

        if operation_object:
            object_values = [o.strip() for o in operation_object.split(',') if o.strip()]
            if len(object_values) == 1:
                query_conditions.append("operation_object = ?")
                query_params.append(object_values[0])
            elif len(object_values) > 1:
                placeholders = ', '.join(['?'] * len(object_values))
                query_conditions.append(f"operation_object IN ({placeholders})")
                query_params.extend(object_values)

        if success is not None and success != '':
            success_values = [int(s.strip()) for s in success.split(',') if s.strip().isdigit()]
            if len(success_values) == 1:
                query_conditions.append("success = ?")
                query_params.append(success_values[0])
            elif len(success_values) > 1:
                placeholders = ', '.join(['?'] * len(success_values))
                query_conditions.append(f"success IN ({placeholders})")
                query_params.extend(success_values)

        if username:
            query_conditions.append("username = ?")
            query_params.append(username)

        if start_time:
            start_time = start_time.replace('T', ' ')
            if len(start_time) <= 16:
                start_time += ":00"
            query_conditions.append("operation_time >= ?")
            query_params.append(start_time)

        if end_time:
            end_time = end_time.replace('T', ' ')
            if len(end_time) <= 16:
                end_time += ":00"
            query_conditions.append("operation_time <= ?")
            query_params.append(end_time)

        if search_keyword:
            query_conditions.append("(username LIKE ? OR operation_summary LIKE ? OR operation_details LIKE ?)")
            search_param = f'%{search_keyword}%'
            query_params.extend([search_param, search_param, search_param])

        where_clause = "WHERE " + " AND ".join(query_conditions) if query_conditions else ""
        return where_clause, query_params

    def filter_logs_store(items):
        operation_type = request.args.get('operation_type')
        operation_object = request.args.get('operation_object')
        success = request.args.get('success')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        search_keyword = request.args.get('search', '').strip().lower()
        username = request.args.get('username')

        op_types = {t.strip() for t in (operation_type or '').split(',') if t.strip()}
        op_objects = {o.strip() for o in (operation_object or '').split(',') if o.strip()}
        success_set = {int(s.strip()) for s in (success or '').split(',') if s.strip().isdigit()}

        start_val = start_time.replace('T', ' ') if start_time else ''
        if start_val and len(start_val) <= 16:
            start_val += ':00'
        end_val = end_time.replace('T', ' ') if end_time else ''
        if end_val and len(end_val) <= 16:
            end_val += ':00'

        filtered = []
        for item in items:
            if op_types and item.get('operation_type') not in op_types:
                continue
            if op_objects and item.get('operation_object') not in op_objects:
                continue
            if success_set and int(item.get('success', 0)) not in success_set:
                continue
            if username and item.get('username') != username:
                continue
            op_time = item.get('operation_time', '')
            if start_val and op_time < start_val:
                continue
            if end_val and op_time > end_val:
                continue
            if search_keyword:
                haystack = ' '.join([
                    str(item.get('username', '')),
                    str(item.get('operation_summary', '')),
                    str(item.get('operation_details', ''))
                ]).lower()
                if search_keyword not in haystack:
                    continue
            filtered.append(item)
        filtered.sort(key=lambda x: x.get('operation_time', ''), reverse=True)
        return filtered

    if USE_LOCAL_FILE_STORE:
        items = _read_operation_logs_from_store()

        if request.args.get('get_operation_types') == 'true':
            types = sorted({item.get('operation_type', '') for item in items if item.get('operation_type')})
            return jsonify({"success": True, "types": types})

        filtered_logs = filter_logs_store(items)

        if request.args.get('export') == 'csv':
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(['操作时间', '操作用户', '操作类型', '操作对象', '操作内容', '结果'])
            for row in filtered_logs[:5000]:
                writer.writerow([
                    row.get('operation_time', ''),
                    row.get('username', ''),
                    row.get('operation_type', ''),
                    row.get('operation_object', ''),
                    row.get('operation_summary', ''),
                    '成功' if int(row.get('success', 0)) else '失败'
                ])
            filename = f"operation_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            return Response(
                output.getvalue(),
                mimetype='text/csv; charset=utf-8',
                headers={'Content-Disposition': f'attachment; filename="{filename}"'}
            )

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 10, type=int)
            offset = (page - 1) * per_page
            paged = filtered_logs[offset: offset + per_page]
            for item in paged:
                details = item.get('operation_details')
                if isinstance(details, str):
                    try:
                        item['operation_details'] = json.loads(details)
                    except json.JSONDecodeError:
                        pass
            total = len(filtered_logs)
            return jsonify({
                'success': True,
                'data': paged,
                'pagination': {
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'pages': (total + per_page - 1) // per_page
                }
            })
        return render_template('logs.html')

    # 获取操作类型列表
    if request.args.get('get_operation_types') == 'true':
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('SELECT DISTINCT operation_type FROM operation_logs ORDER BY operation_type')
            types = [row['operation_type'] for row in cursor.fetchall()]
            return jsonify({"success": True, "types": types})
        except Exception as e:
            app.logger.error(f"获取操作类型失败: {str(e)}")
            return jsonify({"success": False, "message": "获取操作类型失败"}), 500

    # 导出 CSV（按当前筛选条件）
    if request.args.get('export') == 'csv':
        try:
            db = get_db()
            cursor = db.cursor()
            where_clause, query_params = build_filter_conditions()
            cursor.execute(f"""
                SELECT operation_time, username, operation_type, operation_object, operation_summary, success
                FROM operation_logs
                {where_clause}
                ORDER BY operation_time DESC
                LIMIT 5000
            """, query_params)
            rows = cursor.fetchall()

            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(['操作时间', '操作用户', '操作类型', '操作对象', '操作内容', '结果'])
            for row in rows:
                writer.writerow([
                    row['operation_time'],
                    row['username'],
                    row['operation_type'],
                    row['operation_object'] or '',
                    row['operation_summary'] or '',
                    '成功' if row['success'] else '失败'
                ])

            filename = f"operation_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            return Response(
                output.getvalue(),
                mimetype='text/csv; charset=utf-8',
                headers={
                    'Content-Disposition': f'attachment; filename="{filename}"'
                }
            )
        except Exception as e:
            app.logger.error(f"导出日志失败: {str(e)}")
            return jsonify({"success": False, "message": f"导出日志失败: {str(e)}"}), 500

    # AJAX 获取分页日志
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        offset = (page - 1) * per_page

        try:
            db = get_db()
            cursor = db.cursor()
            where_clause, query_params = build_filter_conditions()

            cursor.execute(f"SELECT COUNT(*) as total FROM operation_logs {where_clause}", query_params.copy())
            total = cursor.fetchone()['total']

            query_params_paginated = query_params.copy()
            query_params_paginated.extend([per_page, offset])
            cursor.execute(f"""
                SELECT id, user_id, username, operation_type, operation_object,
                       operation_summary, operation_details, success, operation_time
                FROM operation_logs
                {where_clause}
                ORDER BY operation_time DESC
                LIMIT ? OFFSET ?
            """, query_params_paginated)

            logs = cursor.fetchall()
            log_list = []
            for log in logs:
                log_dict = dict(log)
                if log_dict['operation_details']:
                    try:
                        log_dict['operation_details'] = json.loads(log_dict['operation_details'])
                    except json.JSONDecodeError:
                        pass
                log_list.append(log_dict)

            return jsonify({
                'success': True,
                'data': log_list,
                'pagination': {
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'pages': (total + per_page - 1) // per_page
                }
            })
        except Exception as e:
            app.logger.error(f"日志查询失败: {str(e)}")
            return jsonify({'success': False, 'message': f"日志查询失败: {str(e)}"}), 500

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
