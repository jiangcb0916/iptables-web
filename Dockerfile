FROM python:alpine3.21
RUN mkdir -p /iptables-web
ADD . /iptables-web
WORKDIR /iptables-web
RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/
ENTRYPOINT ["/usr/local/bin/python3.13", "/iptables-web/app.py"]