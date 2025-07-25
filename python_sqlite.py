#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2025/7/23 16:56
# @Author  : lsy
# @FileName: python_sqlite.py
# @Software: PyCharm
# @Function:
import sqlite3
from sqlite3 import Error


def create_connection(db_file):
    """创建与 SQLite 数据库的连接"""
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(f"成功连接到 SQLite 数据库，版本：{sqlite3.version}")
        return conn
    except Error as e:
        print(f"连接错误: {e}")
    return conn


def create_table(conn, create_table_sql):
    """根据 SQL 语句创建表"""
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
        print("表创建成功")
    except Error as e:
        print(f"创建表错误: {e}")


def insert_data(conn, data):
    """插入数据到表中"""
    sql = ''' INSERT INTO users(name, email, age)
              VALUES(?, ?, ?) '''
    cur = conn.cursor()
    cur.execute(sql, data)
    conn.commit()
    return cur.lastrowid  # 返回插入的记录ID


def select_all_data(conn):
    """查询表中所有数据"""
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")

    rows = cur.fetchall()
    print("\n所有用户数据:")
    for row in rows:
        print(row)


def select_data_by_id(conn, user_id):
    """根据ID查询数据"""
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))

    row = cur.fetchone()
    print(f"\nID为{user_id}的用户: {row}")


def update_data(conn, user):
    """更新数据"""
    sql = ''' UPDATE users
              SET name = ?, email = ?, age = ?
              WHERE id = ? '''
    cur = conn.cursor()
    cur.execute(sql, user)
    conn.commit()
    print(f"\nID为{user[3]}的用户已更新")


def delete_data(conn, user_id):
    """删除数据"""
    sql = 'DELETE FROM users WHERE id=?'
    cur = conn.cursor()
    cur.execute(sql, (user_id,))
    conn.commit()
    print(f"\nID为{user_id}的用户已删除")


def main():
    database = "example.db"  # 数据库文件名

    # 创建用户表的SQL语句
    sql_create_users_table = """ CREATE TABLE IF NOT EXISTS users (
                                        id integer PRIMARY KEY AUTOINCREMENT,
                                        name text NOT NULL,
                                        email text NOT NULL UNIQUE,
                                        age integer
                                    ); """

    # 创建数据库连接
    conn = create_connection(database)

    if conn is not None:
        # 创建用户表
        create_table(conn, sql_create_users_table)

        # 插入数据
        user1_id = insert_data(conn, ('张三', 'zhangsan@example.com', 25))
        user2_id = insert_data(conn, ('李四', 'lisi@example.com', 30))
        print(f"\n插入的用户ID: {user1_id}, {user2_id}")

        # 查询所有数据
        select_all_data(conn)

        # 根据ID查询
        select_data_by_id(conn, 1)

        # 更新数据
        update_data(conn, ('张三', 'zhangsan_new@example.com', 26, 1))

        # 再次查询所有数据
        select_all_data(conn)

        # 删除数据
        delete_data(conn, 2)

        # 最后查询所有数据
        select_all_data(conn)

        # 关闭连接
        conn.close()
        print("\n数据库连接已关闭")
    else:
        print("无法创建数据库连接")


if __name__ == '__main__':
    main()
