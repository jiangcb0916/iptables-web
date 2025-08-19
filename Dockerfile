FROM python:latest
ADD iptables-web/ /
RUN pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/ && cd /iptables-web
CMD ["flask","run"]
EXPOSE 5000