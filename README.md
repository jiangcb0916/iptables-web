


扩展：https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html

```shell
docker build -t iptables_web:v0.4 .
docker run --net=host -d -it  iptables_web:v0.4  sh

# 持久化
#centos
iptables-save > /etc/sysconfig/iptables

# debina and ubuntu
# 前提条件：apt install iptables-persistent

apt install iptables-persistent
```


主机表
    主机名称
    主机标识
    IP地址
    操作系统
    ssh端口
    用户名
    认证方式
    秘钥或密码，由认证方式决定