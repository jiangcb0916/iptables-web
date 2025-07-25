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


def main():
    database = "firewall_management.db"  # 数据库文件名

    # 创建数据库连接
    conn = create_connection(database)

    if conn is not None:
        # 创建主机表
        create_hosts_table(conn)
        conn.close()
    else:
        print("无法创建数据库连接")


if __name__ == '__main__':
    main()