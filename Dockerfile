# 从轻量级Python镜像出发，选择3.11版本以确保兼容最新的语言特性
FROM python:3.11-alpine

# 创建项目目录结构，为后续操作奠定基础
RUN mkdir -p /iptables-web

# 将当前目录下的所有内容复制到容器内的指定路径，构建起应用的骨架
ADD . /iptables-web

# 设定工作目录，使后续命令均在此环境中执行，提高效率
WORKDIR /iptables-web

# 调整系统时区至亚洲/上海，确保日志记录等时间相关数据的一致性
RUN ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# 利用阿里云提供的PyPI镜像源安装依赖包，加速构建过程同时保证软件包来源的安全可靠
RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/

# 指定入口点，当容器启动时自动运行主程序app.py，开启应用程序之旅
ENTRYPOINT ["python3", "/iptables-web/app.py"]