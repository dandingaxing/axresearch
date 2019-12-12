

## 切换php-fpm的版本
 ```
    # 找到php-fpm的启动脚本, centos6.9 在 /etc/rc.d/init.d/php-fpm
    find / -name 'php-fpm'
    
    # 定位到 init.d 目录
    cd /etc/rc.d/init.d

    # 复制当前php-fpm脚本, 分别为 5.6 版本和 7 版本
    cp php-fpm php-fpm-5.6
    cp php-fpm php-fpm-7

    # 停止当前php-fpm
    service php-fpm stop

    # 修改 php-fpm-7 中的bin启动文件路径
    vim php-fpm-7
        修改: prefix=/xxxsoftdir/php/php5.6   # 之前的php目录位置
        为:   prefix=/xxxsoftdir/php/php7     # php7 的目录位置

    # 重新启动php-fpm
    service php-fpm start

    # 注意点: 
        1. 一定要注意, 这里只是网页web 使用php-fpm的时候切换为php7, 但是命令行下 php -v 还是之前的5.6 版本, 因为 /usr/bin/php 等默认的系统命令并没有变
        2. 因此要在命令行下使用php7 还是要用最保险的办法: /xxxsoftdir/php/php7/bin/php -f xxxx.php 这样的方式
        3. 要使用 pecl 安装文件也是同样的道理, 也要使用最保险的办法: /xxxsoftdir/php/php7/bin/pecl install xxxx
        4. 有时候要从 pecl 官网下载 .tgz 包直接安装, 这样插件会安装到php7下面. 示例步骤如下:
            1. wget http://pecl.php.net/get/swoole-4.0.4.tgz
            2. /xxxsoftdir/php/php7/bin/pecl install swoole-4.0.4.tgz
            3. 将生成的 swoole.so 文件配置到 php7 配置文件的 php.ini
 ```
