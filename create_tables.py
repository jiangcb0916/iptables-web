#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/7/25 17:05
# @Author  : lsy
# @FileName: 创建主机表.py
# @Software: PyCharm
# @Function:
import sqlite3
from sqlite3 import Error


def create_connection(db_file):
    """创建数据库连接"""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)
    return conn


def create_hosts_table(conn):
    """创建主机表"""
    try:
        sql_create_hosts_table = """
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_name TEXT NOT NULL,           -- 主机名称
            host_identifier TEXT UNIQUE NOT NULL, -- 主机标识，唯一
            ip_address TEXT NOT NULL,          -- IP地址
            operating_system TEXT,             -- 操作系统
            ssh_port INTEGER DEFAULT 22,       -- SSH端口，默认22
            username TEXT NOT NULL,            -- 用户名
            auth_method TEXT NOT NULL,         -- 认证方式：password或key
            password TEXT,                     -- 密码，当auth_method为password时使用
            private_key TEXT,                  -- 私钥，当auth_method为key时使用
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_hosts_table)
        print("主机表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_template_table(conn):
    """创建模板表"""
    try:
        sql_create_hosts_table = """
        CREATE TABLE IF NOT EXISTS templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_name TEXT UNIQUE NOT NULL,   -- 模板名称
            template_identifier TEXT NOT NULL, -- 模板简介，唯一
            direction TEXT DEFAULT 'INPUT',   -- 方向
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_hosts_table)
        print("模板表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_rule_table(conn):
    """创建规则表"""
    try:
        sql_create_hosts_table = """
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            template_id TEXT  NOT NULL,   -- 模板ID
            policy TEXT  NOT NULL,   -- 授权策略
            protocol TEXT NOT NULL, -- 协议
            port TEXT DEFAULT '-1/-1',        -- 单端口
            auth_object TEXT DEFAULT '0.0.0.0/0',        -- 授权对象
            description TEXT ,        -- 注释
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_hosts_table)
        print("规则表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_user_table(conn):
    """创建用户表"""
    try:
        sql_create_hosts_table = """
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT  NOT NULL,   -- 用户名
            password TEXT  NOT NULL,   -- 密码
            email TEXT  NOT NULL,   -- 邮箱
            status TEXT  NOT NULL,   -- 状态
            role_id TEXT NOT NULL, -- 角色
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_hosts_table)
        print("规则表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_system_config_table(conn):
    """创建系统设置表"""
    try:
        sql_create_hosts_table = """
        CREATE TABLE IF NOT EXISTS system_config (
            id TEXT  NOT NULL,   -- id
            system_name TEXT  NOT NULL,   -- 系统名称
            session_timeout INTEGER NOT NULL DEFAULT 30,   -- 会话超时时间（分钟）
            log_retention_time TEXT  NOT NULL,   -- 日志保留时间
            color_mode TEXT NOT NULL DEFAULT 'light',   -- 色调模式：light或dark
            password_strategy TEXT  NOT NULL,   -- 密码策略
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_hosts_table)
        print("系统设置表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def create_role_table(conn):
    """创建角色表"""
    try:
        sql_create_hosts_table = """
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_name TEXT  NOT NULL,   -- 角色名称
            role_description TEXT  NOT NULL,   -- 角色描述
            sys_view TEXT  NOT NULL,   -- 查看系统设置
            sys_edit TEXT  NOT NULL,  -- 编辑系统设置
            user_view TEXT  NOT NULL,  -- 查看用户列表
            user_add TEXT  NOT NULL,  -- 添加用户
            user_edit TEXT  NOT NULL,  -- 编辑用户
            user_status TEXT  NOT NULL, -- 用户状态：启用或禁用用户
            iptab_view TEXT  NOT NULL, -- 查看防火墙规则
            iptab_add TEXT  NOT NULL, -- 添加防火墙规则
            iptab_edit TEXT  NOT NULL, -- 编辑防火墙规则
            iptab_del TEXT  NOT NULL, -- 删除防火墙规则
            log_view TEXT  NOT NULL,  -- 查看操作日志
            hosts_view TEXT  NOT NULL,  --查看主机
            hosts_edit TEXT  NOT NULL,  -- 编辑主机
            hosts_add TEXT  NOT NULL,  -- 新增主机
            hosts_del  TEXT  NOT NULL,  -- 删除主机
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- 创建时间
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor = conn.cursor()
        cursor.execute(sql_create_hosts_table)
        print("规则表创建成功")
    except Error as e:
        print(f"创建表时出错: {e}")


def main():
    database = "firewall_management.db"  # 数据库文件名

    # 创建数据库连接
    conn = create_connection(database)

    if conn is not None:
        # 创建主机表
        create_hosts_table(conn)
        # 创建模板表
        create_template_table(conn)
        # 创建规则表
        create_rule_table(conn)
        # 创建用户表
        create_user_table(conn)
        # 创建系统设置表
        create_system_config_table(conn)
        # 创建角色表
        create_role_table(conn)
        conn.close()
    else:
        print("无法创建数据库连接")


if __name__ == '__main__':
    main()
