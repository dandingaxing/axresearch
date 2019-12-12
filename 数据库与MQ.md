
## MQ官网[http://www.rabbitmq.com/]
## MQ中文文档[http://rabbitmq.mr-ping.com/]


## MQ安装( 3.7.6 版本为例, 环境：centos6.9 )
1. 下载MQ[http://www.rabbitmq.com/install-rpm.html] rpm安装包, 官网链接地址[https://github.com/rabbitmq/rabbitmq-server/releases/download/v3.7.6/rabbitmq-server-3.7.6-1.el6.noarch.rpm|https://dl.bintray.com/rabbitmq/all/rabbitmq-server/3.7.6/rabbitmq-server-3.7.6-1.el6.noarch.rpm]

2. rpm 安装
    - rpm -ivh rabbitmq-server-3.7.6-1.el6.noarch.rpm

3. 安装需要依赖如下：erlang>1.9.x, socat
    1. 安装 erlang 需要自己下载，因为 yum 安装的版本太低
        - erlang 官网[http://www.erlang.org], 下载地址[http://erlang.org/download/otp_src_20.3.tar.gz]
        - erlang 解压与安装
        - tar -xzvf otp_src_20.3.tar.gz
        - cd otp_src_20.3
        - ./configure
        - make && make install
    2. socat 可以直接使用 yum install socat 进行安装

4. 继续安装MQ
    - rpm -ivh rabbitmq-server-3.7.6-1.el6.noarch.rpm

5. 



## MQ 简单配置与使用
1. 安装成功后需要配置 用户，权限，vhost等才可以进行相应用户的访问与使用
2. MQ默认web访问端口[15672], 地址例子[http://192.168.183.129:15672]
3. MQ 用户管理：
    - 可以在后台直接配置，也可以使用 rabbitmqctl 命令来写
    - 步骤：
        1: 配置用户
        2：配置用户权限[permission]
        3：一个用户的permission权限包含如下字段：Virtual host, Configure regexpm, Write regexp, Read regexp 
        4: 默认 permission 权限例子如下：Virtual host(/), Configure regexp(.*), Write regexp(.*), Read regexp(.*)
    - 参考网址[https://blog.csdn.net/becivells/article/details/52044654]
    - 参考网址[https://www.cnblogs.com/lori/p/7852534.html]
4. 


