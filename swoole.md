

## swoole 类与命名空间: 子类可以调用父类的所有方法和属性

##. swoole_server: 强大的TCP/UDP Server框架 [ server 提供 基类框架 ]
    1. swoole_http_server 是 swoole_server 的子类，内置了Http的支持 ( swoole_http_server extends swoole_server )
    2. swoole_websocket_server 是 swoole_http_server 的子类，内置了WebSocket的支持 ( swoole_websocket_server extends swoole_http_server )
    3. swoole_redis_server 是 swoole_server 的子类，内置了Redis服务器端协议的支持, ( swoole_redis_server extends swoole_server )

## swoole_server
 1. 方法与函数
    - 构造方法 swoole_server::__construct(string $host, int $port = 0, int $mode = SWOOLE_PROCESS, int $sock_type = SWOOLE_SOCK_TCP);
        1. $host参数用来指定监听的ip地址，如127.0.0.1，或者外网地址，或者0.0.0.0监听全部地址
            - IPv4使用 127.0.0.1表示监听本机，0.0.0.0表示监听所有地址
            - IPv6使用::1表示监听本机，:: (相当于0:0:0:0:0:0:0:0) 表示监听所有地址
        2. $port监听的端口，如9501
            - 如果$sock_type为UnixSocket Stream/Dgram，此参数将被忽略
            - 监听小于1024端口需要root权限
            - 如果此端口被占用server->start时会失败
        3. $mode运行的模式
            - SWOOLE_PROCESS多进程模式（默认）
            - SWOOLE_BASE基本模式
        4. $sock_type指定Socket的类型，支持TCP、UDP、TCP6、UDP6、UnixSocket Stream/Dgram 6种
            - swoole支持的Socket类型
            - SWOOLE_TCP/SWOOLE_SOCK_TCP tcp ipv4 socket
            - SWOOLE_TCP6/SWOOLE_SOCK_TCP6 tcp ipv6 socket
            - SWOOLE_UDP/SWOOLE_SOCK_UDP udp ipv4 socket
            - SWOOLE_UDP6/SWOOLE_SOCK_UDP6 udp ipv6 socket
            - SWOOLE_UNIX_DGRAM unix socket dgram
            - SWOOLE_UNIX_STREAM unix socket stream
        5. 使用$sock_type | SWOOLE_SSL可以启用SSL隧道加密。启用SSL后必须配置ssl_key_file和ssl_cert_file
        6. 1.7.11版本增加了对Unix Socket的支持，详细请参见 /wiki/page/16.html
        7. 构造函数中的参数与swoole_server::addlistener中是完全相同的
        8. 监听端口失败，在1.9.16以上版本会抛出异常，可以使用try/catch捕获异常，在1.9.16以下版本抛出致命错误
        9. 高负载的服务器，请务必调整Linux内核参数
        10. 3种Server运行模式介绍

    - function swoole_server->set(array $setting);
        1. swoole_server->set函数用于设置swoole_server运行时的各项参数。服务器启动后通过$serv->setting来访问set函数设置的参数数组。
        2. swoole_server->set只能在swoole_server->start前调用
        3. swoole_server->set()函数所设置的参数会保存到swoole_server::$setting属性上。在回调函数中可以访问运行参数的值。
        4. 配置选项:
            - reactor_num
                1. Reactor线程数，reactor_num => 2，通过此参数来调节主进程内事件处理线程的数量，以充分利用多核。默认会启用CPU核数相同的数量。
                2. reactor_num建议设置为CPU核数的1-4倍, reactor_num最大不得超过SWOOLE_CPU_NUM * 4
            - worker_num
                1. 设置启动的Worker进程数。
                2. 业务代码是全异步非阻塞的，这里设置为CPU的1-4倍最合理
                3. 业务代码为同步阻塞，需要根据请求响应时间和系统负载来调整
                4. 默认设置为SWOOLE_CPU_NUM，最大不得超过SWOOLE_CPU_NUM * 1000
                5. 比如1个请求耗时100ms，要提供1000QPS的处理能力，那必须配置100个进程或更多。但开的进程越多，占用的内存就会大大增加，而且进程间切换的开销就会越来越大。所以这里适当即可。不要配置过大。
                6. 每个进程占用40M内存，那100个进程就需要占用4G内存
            - max_request
                1. 设置worker进程的最大任务数，默认为0，一个worker进程在处理完超过此数值的任务后将自动退出，进程退出后会释放所有内存和资源。
                2. 这个参数的主要作用是解决PHP进程内存溢出问题。PHP应用程序有缓慢的内存泄漏，但无法定位到具体原因、无法解决，可以通过设置max_request解决。
            - max_conn (max_connection)
                1. 服务器程序，最大允许的连接数，如max_connection => 10000, 此参数用来设置Server最大允许维持多少个TCP连接。超过此数量后，新进入的连接将被拒绝。
            - task_worker_num
                1. 配置Task进程的数量，配置此参数后将会启用task功能。所以Server务必要注册onTask、onFinish2个事件回调函数。如果没有注册，服务器程序将无法启动。
            - task_ipc_mode
                1. 设置task进程与worker进程之间通信的方式。
                2. 1: 使用unix socket通信，默认模式; 2: 使用消息队列通信; 3: 使用消息队列通信，并设置为争抢模式
                3. 模式2和模式3的不同之处是，模式2支持定向投递，$serv->task($data, $task_worker_id) 可以指定投递到哪个task进程。模式3是完全争抢模式，task进程会争抢队列，将无法使用定向投递，task/taskwait将无法指定目标进程ID，即使指定了$task_worker_id，在模式3下也是无效的。
                4. 模式3会影响sendMessage方法，使sendMessage发送的消息会随机被某一个task进程获取
            - task_max_request
                1. 设置task进程的最大任务数。一个task进程在处理完超过此数值的任务后将自动退出。这个参数是为了防止PHP进程内存溢出。如果不希望进程自动退出可以设置为0。
            - task_tmpdir
                1. 设置task的数据临时目录，在swoole_server中，如果投递的数据超过8192字节，将启用临时文件来保存数据。这里的task_tmpdir就是用来设置临时文件保存的位置。
                2. Swoole默认会使用/tmp目录存储task数据，如果你的Linux内核版本过低，/tmp目录不是内存文件系统，可以设置为 /dev/shm/
            - dispatch_mode
                1. 数据包分发策略。可以选择3种类型，默认为2
                    - 1，轮循模式，收到会轮循分配给每一个worker进程
                    - 2，固定模式，根据连接的文件描述符分配worker。这样可以保证同一个连接发来的数据只会被同一个worker处理
                    - 3，抢占模式，主进程会根据Worker的忙闲状态选择投递，只会投递给处于闲置状态的Worker
                    - 4，IP分配，根据客户端IP进行取模hash，分配给一个固定的worker进程。可以保证同一个来源IP的连接数据总会被分配到同一个worker进程。算法为 ip2long(ClientIP) % worker_num
                    - 5，UID分配，需要用户代码中调用 $serv-> bind() 将一个连接绑定1个uid。然后swoole根据UID的值分配到不同的worker进程。算法为 UID % worker_num，如果需要使用字符串作为UID，可以使用crc32(UID_STRING)
            - dispatch_func
                1. 设置dispatch函数，swoole底层了内置了5种dispatch_mode，如果仍然无法满足需求。可以使用编写C++函数或PHP函数，实现dispatch逻辑。使用方法：
                    ```
                        $serv->set(array(
                            'dispatch_func' => 'my_dispatch_function',
                        ));
                    ```
                2. 设置dispatch_func后底层会自动忽略dispatch_mode配置
                3. dispatch_func对应的函数不存在，底层将抛出致命错误
                4. 如果需要dispatch一个超过8K的包，dispatch_func只能获取到 0-8180 字节的内容
                5. dispatch_func在1.9.7或更高版本可用
                6. dispatch_func在1.9.18或更高版本可以设置为PHP函数
                7. dispatch_func仅在SWOOLE_PROCESS模式下有效，UDP/TCP/UnixSocket均有效

            - message_queue_key
                1. 设置消息队列的KEY，仅在task_ipc_mode = 2/3时使用。设置的Key仅作为Task任务队列的KEY，此参数的默认值为ftok($php_script_file, 1)
                2. task队列在server结束后不会销毁，重新启动程序后，task进程仍然会接着处理队列中的任务。如果不希望程序重新启动后执行旧的Task任务。可以手工删除此消息队列。
                    ```
                        ipcs -q 
                        ipcrm -Q [msgkey]
                    ```

            - daemonize
                1. 守护进程化。设置daemonize => 1时，程序将转入后台作为守护进程运行。长时间运行的服务器端程序必须启用此项。
                2. 如果不启用守护进程，当ssh终端退出后，程序将被终止运行。
                3. 启用守护进程后，标准输入和输出会被重定向到 log_file
                4. 如果未设置log_file，将重定向到 /dev/null，所有打印屏幕的信息都会被丢弃
                5. 启用守护进程后，CWD（当前目录）环境变量的值会发生变更，相对路径的文件读写会出错。PHP程序中必须使用绝对路径

            - backlog
                1. Listen队列长度，如backlog => 128，此参数将决定最多同时有多少个等待accept的连接。

            - log_file
                1. log_file => '/data/log/swoole.log', 指定swoole错误日志文件。在swoole运行期发生的异常信息会记录到这个文件中。默认会打印到屏幕。
                2. 注意log_file不会自动切分文件，所以需要定期清理此文件。观察log_file的输出，可以得到服务器的各类异常信息和警告。
                3. log_file中的日志仅仅是做运行时错误记录，没有长久存储的必要。
                4. 开启守护进程模式后(daemonize => true)，标准输出将会被重定向到log_file。在PHP代码中echo/var_dump/print等打印到屏幕的内容会写入到log_file文件

            - log_level
                1. 设置swoole_server错误日志打印的等级，范围是0-5。低于log_level设置的日志信息不会抛出。
                    ```
                       $serv->set(array(
                            'log_level' => 1,
                        )); 
                    ```

            - heartbeat_check_interval
                1. 启用心跳检测，此选项表示每隔多久轮循一次，单位为秒。如 heartbeat_check_interval => 60，表示每60秒，遍历所有连接，如果该连接在60秒内，没有向服务器发送任何数据，此连接将被强制关闭。
                2. swoole_server并不会主动向客户端发送心跳包，而是被动等待客户端发送心跳。服务器端的heartbeat_check仅仅是检测连接上一次发送数据的时间，如果超过限制，将切断连接。
                3. heartbeat_check仅支持TCP连接

            - heartbeat_idle_time
                1. 与heartbeat_check_interval配合使用。表示连接最大允许空闲的时间。如
                    ```
                        array(
                            'heartbeat_idle_time' => 600,
                            'heartbeat_check_interval' => 60,
                        );
                    ```
                2. 表示每60秒遍历一次，一个连接如果600秒内未向服务器发送任何数据，此连接将被强制关闭
                3. 启用heartbeat_idle_time后，服务器并不会主动向客户端发送数据包
                4. 如果只设置了heartbeat_idle_time未设置heartbeat_check_interval底层将不会创建心跳检测线程，PHP代码中可以调用heartbeat方法手工处理超时的连接

            - open_eof_check
                1. 打开EOF检测，此选项将检测客户端连接发来的数据，当数据包结尾是指定的字符串时才会投递给Worker进程。否则会一直拼接数据包，直到超过缓存区或者超时才会中止。当出错时底层会认为是恶意连接，丢弃数据并强制关闭连接。
                2. 此配置仅对STREAM类型的Socket有效，如TCP、Unix Socket Stream
                    ```
                        array(
                            'open_eof_check' => true, //打开EOF检测
                            'package_eof' => "\r\n", //设置EOF
                        )
                    ```
                3. 常见的Memcache/SMTP/POP等协议都是以\r\n结束的，就可以使用此配置。开启后可以保证Worker进程一次性总是收到一个或者多个完整的数据包。

            - open_eof_split
                1. 启用EOF自动分包。当设置open_eof_check后，底层检测数据是否以特定的字符串结尾来进行数据缓冲。但默认只截取收到数据的末尾部分做对比。这时候可能会产生多条数据合并在一个包内。
                2. 启用open_eof_split参数后，底层会从数据包中间查找EOF，并拆分数据包。onReceive每次仅收到一个以EOF字串结尾的数据包。
                3. 启用open_eof_split参数后，无论参数open_eof_check是否设置，open_eof_split都将生效。
                4. open_eof_split在1.7.15以上版本可用

            - package_eof
                1. 与 open_eof_check 或者 open_eof_split 配合使用，设置EOF字符串。
                2. package_eof最大只允许传入8个字节的字符串

            - open_length_check
                1. 打开包长检测特性。包长检测提供了固定包头+包体这种格式协议的解析。启用后，可以保证Worker进程onReceive每次都会收到一个完整的数据包。
                2. 长度协议提供了3个选项来控制协议细节。
                3. 此配置仅对STREAM类型的Socket有效，如TCP、Unix Socket Stream
                    ```
                        struct
                        {
                            uint32_t type;
                            uint32_t uid;
                            uint32_t length;
                            uint32_t serid;
                            char body[0];
                        }
                        
                        // 以上通信协议的设计中，包头长度为4个整型，16字节，length长度值在第3个整型处。因此package_length_offset设置为8，0-3字节为type，4-7字节为uid，8-11字节为length，12-15字节为serid。

                        $server->set(array(
                            'open_length_check' => true,
                            'package_max_length' => 81920,
                            'package_length_type' => 'N',
                            'package_length_offset' => 8,
                            'package_body_offset' => 16,
                        ));
                        
                        // 如果配置好了，可能就不需要额外处理粘包的问题了
                    ```

            - package_length_type
                1. 长度值的类型，接受一个字符参数，与php的 pack 函数一致。目前Swoole支持10种类型：
                    - c：有符号、1字节
                    - C：无符号、1字节
                    - s ：有符号、主机字节序、2字节
                    - S：无符号、主机字节序、2字节
                    - n：无符号、网络字节序、2字节
                    - N：无符号、网络字节序、4字节
                    - l：有符号、主机字节序、4字节（小写L）
                    - L：无符号、主机字节序、4字节（大写L）
                    - v：无符号、小端字节序、2字节
                    - V：无符号、小端字节序、4字节

            - package_length_func
                1. 设置长度解析函数，支持C++或PHP的2种类型的函数。长度函数必须返回一个整数。
                3. 返回0，数据不足，需要接收更多数据
                4. 返回-1，数据错误，底层会自动关闭连接
                5. 返回包长度值（包括包头和包体的总长度），底层会自动将包拼好后返回给回调函数
                6. 默认底层最大会读取8K的数据，如果包头的长度较小可能会存在内存复制的消耗。可设置package_body_offset参数，底层只读取包头进行长度解析。

            - package_max_length
                1. 设置最大数据包尺寸，单位为字节。开启open_length_check/open_eof_check/open_http_protocol等协议解析后。swoole底层会进行数据包拼接。这时在数据包未收取完整时，所有数据都是保存在内存中的。
                2. 所以需要设定package_max_length，一个数据包最大允许占用的内存尺寸。如果同时有1万个TCP连接在发送数据，每个数据包2M，那么最极限的情况下，就会占用20G的内存空间。
                    - open_length_check，当发现包长度超过package_max_length，将直接丢弃此数据，并关闭连接，不会占用任何内存。包括websocket、mqtt、http2协议。
                    - open_eof_check，因为无法事先得知数据包长度，所以收到的数据还是会保存到内存中，持续增长。当发现内存占用已超过package_max_length时，将直接丢弃此数据，并关闭连接
                    - open_http_protocol，GET请求最大允许8K，而且无法修改配置。POST请求会检测Content-Length，如果Content-Length超过package_max_length，将直接丢弃此数据，发送http 400错误，并关闭连接
                    - 此参数不宜设置过大，否则会占用很大的内存

            - open_cpu_affinity
                1. 启用CPU亲和性设置。在多核的硬件平台中，启用此特性会将swoole的reactor线程/worker进程绑定到固定的一个核上。可以避免进程/线程的运行时在多个核之间互相切换，提高CPU Cache的命中率。

            - cpu_affinity_ignore
                1. IO密集型程序中，所有网络中断都是用CPU0来处理，如果网络IO很重，CPU0负载过高会导致网络中断无法及时处理，那网络收发包的能力就会下降。
                2. 如果不设置此选项，swoole将会使用全部CPU核，底层根据reactor_id或worker_id与CPU核数取模来设置CPU绑定。
                    - 如果内核与网卡有多队列特性，网络中断会分布到多核，可以缓解网络中断的压力
                    - 此选项必须与open_cpu_affinity同时设置才会生效
                3. ```array('cpu_affinity_ignore' => array(0, 1))```
                4. 接受一个数组作为参数，array(0, 1) 表示不使用CPU0,CPU1，专门空出来处理网络中断。

            - open_tcp_nodelay
                1. 启用open_tcp_nodelay，开启后TCP连接发送数据时会关闭Nagle合并算法，立即发往客户端连接。在某些场景下，如http服务器，可以提升响应速度。

            - tcp_defer_accept
                1. 启用tcp_defer_accept特性，可以设置为一个数值，表示当一个TCP连接有数据发送时才触发accept。
                    ```
                        tcp_defer_accept => 5
                    ```
                2. 启用tcp_defer_accept特性后，accept和onConnect对应的时间会发生变化。如果设置为5秒：
                    - 客户端连接到服务器后不会立即触发accept
                    - 在5秒内客户端发送数据，此时会同时顺序触发accept/onConnect/onReceive
                    - 在5秒内客户端没有发送任何数据，此时会触发accept/onConnect
                3. tcp_defer_accept的可以提高Accept操作的效率

            - ssl_cert_file
                1. 设置SSL隧道加密，设置值为一个文件名字符串，制定cert证书和key私钥的路径。
                    - https应用浏览器必须信任证书才能浏览网页
                    - wss应用中，发起WebSocket连接的页面必须使用https
                    - 浏览器不信任SSL证书将无法使用wss
                    - 文件必须为PEM格式，不支持DER格式，可使用openssl工具进行转换
                2. 使用SSL必须在编译swoole时加入--enable-openssl选项
                    ```
                        $serv = new swoole_server('0.0.0.0', 9501, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
                        $serv->set(array(
                            'ssl_cert_file' => __DIR__.'/config/ssl.crt',
                            'ssl_key_file' => __DIR__.'/config/ssl.key',
                        ));
                    ```

            - ssl_method
                1. 设置OpenSSL隧道加密的算法。Server与Client使用的算法必须一致，否则SSL/TLS握手会失败，连接会被切断。 默认算法为 SWOOLE_SSLv23_METHOD
                    ```
                        $server->set(array(
                            'ssl_method' => SWOOLE_SSLv3_CLIENT_METHOD,
                        ));
                    ```
                2. 此配置在1.7.20或更高版本可用
                3. 支持的类型请参考 预定义常量

            - ssl_ciphers
                1. 启用SSL后，设置ssl_ciphers来改变openssl默认的加密算法。Swoole底层默认使用EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
                    ```
                        $server->set(array(
                            'ssl_ciphers' => 'ALL:!ADH:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP',
                        ));
                    ```
                2. ssl_ciphers 设置为空字符串时，由openssl自行选择加密算法

            - user
                1. 设置worker/task子进程的所属用户。服务器如果需要监听1024以下的端口，必须有root权限。但程序运行在root用户下，代码中一旦有漏洞，攻击者就可以以root的方式执行远程指令，风险很大。配置了user项之后，可以让主进程运行在root权限下，子进程运行在普通用户权限下。
                    ```
                        $serv->set(array('user' => 'apache'));
                    ```
                2. 此配置在swoole-1.7.9以上版本可用
                3. 仅在使用root用户启动时有效

            - group
                1. 设置worker/task子进程的进程用户组。与user配置相同，此配置是修改进程所属用户组，提升服务器程序的安全性。
                    ```
                        $serv->set(array('group' => 'www-data'));
                    ```
                2. 此配置在swoole-1.7.9以上版本可用
                3. 仅在使用root用户启动时有效

            - chroot
                1. 重定向Worker进程的文件系统根目录。此设置可以使进程对文件系统的读写与实际的操作系统文件系统隔离。提升安全性。
                    ```
                        $serv->set(array('chroot' => '/data/server/'));
                    ```
                2. 此配置在swoole-1.7.9以上版本可用

            - pid_file
                1. 在Server启动时自动将master进程的PID写入到文件，在Server关闭时自动删除PID文件。
                    ```
                        $server->set(array(
                            'pid_file' => __DIR__.'/server.pid',
                        ));
                2. 使用时需要注意如果Server非正常结束，PID文件不会删除，需要使用swoole_process::kill($pid, 0)来侦测进程是否真的存在
                3. 此选项在1.9.5或更高版本可用

            - pipe_buffer_size
                1. 调整管道通信的内存缓存区长度。Swoole使用Unix Socket实现进程间通信。
                    ```
                        $server->set([
                            'pipe_buffer_size' => 32 * 1024 *1024, //必须为数字
                        ])
                    ```
                2. swoole的reactor线程与worker进程之间
                3. worker进程与task进程之间
                4. 1.9.16或更高版本已移除此配置项，底层不再限制管道缓存区的长度
                5. 都是使用unix socket进行通信的，在收发大量数据的场景下，需要启用内存缓存队列。此函数可以修改内存缓存的长度。
                    - task_ipc_mode=2/3时会使用消息队列通信不受此参数控制
                    - 管道缓存队列已满会导致reactor线程、worker进程发生阻塞
                    - 此参数在1.7.17以上版本默认为32M，1.7.17以下版本默认为8M

            - buffer_output_size
                1. 配置发送输出缓存区内存尺寸。
                    ```
                        $server->set([
                            'buffer_output_size' => 32 * 1024 *1024, //必须为数字
                        ])
                    ```
                2. 单位为字节，默认为2M，如设置32 * 1024 *1024表示，单次Server->send最大允许发送32M字节的数据
                3. 调用swoole_server->send， swoole_http_server->end/write，swoole_websocket_server->push 等发送数据指令时，单次最大发送的数据不得超过buffer_output_size配置。
                4. 注意此函数不应当调整过大，避免拥塞的数据过多，导致吃光机器内存
                5. 开启大量worker进程时，将会占用worker_num * buffer_output_size字节的内存

            - socket_buffer_size
                1. 配置客户端连接的缓存区长度。从1.8.8版本开始swoole底层对于缓存区控制的参数分离成buffer_output_size和socket_buffer_size两项配置。
                2. 参数buffer_output_size用于设置单次最大发送长度。socket_buffer_size用于设置客户端连接最大允许占用内存数量。
                    ```
                        $server->set([
                            'socket_buffer_size' => 128 * 1024 *1024, //必须为数字
                        ])
                    ```
                3. 单位为字节，如128 * 1024 *1024表示每个TCP客户端连接最大允许有128M待发送的数据
                4. 默认为2M字节

            - enable_unsafe_event
                1. swoole在配置dispatch_mode=1或3后，因为系统无法保证onConnect/onReceive/onClose的顺序，默认关闭了onConnect/onClose事件。
                2. 如果应用程序需要onConnect/onClose事件，并且能接受顺序问题可能带来的安全风险，可以通过设置enable_unsafe_event为true，启用onConnect/onClose事件
                3. enable_unsafe_event配置在1.7.18以上版本可用

            - discard_timeout_request
                1. swoole在配置dispatch_mode=1或3后，系统无法保证onConnect/onReceive/onClose的顺序，因此可能会有一些请求数据在连接关闭后，才能到达Worker进程。
                2. discard_timeout_request配置默认为true，表示如果worker进程收到了已关闭连接的数据请求，将自动丢弃。discard_timeout_request如果设置为false，表示无论连接是否关闭Worker进程都会处理数据请求。
                3. discard_timeout_request 在1.7.16以上可用

            - enable_reuse_port
                1. 设置端口重用，此参数用于优化TCP连接的Accept性能，启用端口重用后多个进程可以同时进行Accept操作。
                    ```
                        enable_reuse_port = true 打开端口重用
                        enable_reuse_port = false 关闭端口重用
                    ```
                2. 仅在Linux-3.9.0以上版本的内核可用
                3. 启用端口重用后可以重复启动同一个端口的Server程序

            - enable_delay_receive
                1. 设置此选项为true后，accept客户端连接后将不会自动加入EventLoop，仅触发onConnect回调。worker进程可以调用$serv->confirm($fd)对连接进行确认，此时才会将fd加入EventLoop开始进行数据收发，也可以调用$serv->close($fd)关闭此连接。
                    ```
                        //开启enable_delay_receive选项
                        $serv->set(array(
                            'enable_delay_receive' => true,
                        ));

                        $serv->on("Connect", function ($serv, $fd, $reactorId) {
                            $serv->after(2000, function() use ($serv, $fd) {
                                //确认连接，开始接收数据
                                $serv->confirm($fd);
                            });
                        });
                    ```
                2. enable_delay_receive在1.8.8或更高版本可用

            - open_http_protocol
                1. 启用Http协议处理，Swoole\Http\Server会自动启用此选项。设置为false表示关闭Http协议处理。

            - open_http2_protocol
                1. 启用HTTP2协议解析，需要依赖--enable-http2编译选项。默认为false

            - open_websocket_protocol
                1. 启用websocket协议处理，Swoole\WebSocket\Server会自动启用此选项。设置为false表示关闭websocket协议处理。
                2. 设置open_websocket_protocol选项为true后，会自动设置open_http_protocol协议也为true。
            
            - open_mqtt_protocol
            - reload_async
            - tcp_fastopen
            - request_slowlog_file
            - enable_coroutine
            - max_coroutine




    - bool swoole_server->on(string $event, mixed $callback);
        1. 注册Server的事件回调函数。
        2. 第1个参数是回调的名称, 大小写不敏感，具体内容参考回调函数列表，事件名称字符串不要加on
        3. 第2个函数是回调的PHP函数，可以是函数名的字符串，类静态方法，对象方法数组，匿名函数。
        4. 重复调用on方法时会覆盖上一次的设定

    - function swoole_server->addListener(string $host, int $port, $type = SWOOLE_SOCK_TCP); 函数别名: bool swoole_server->listen(string $host, int $port, int $type);
        1. Swoole提供了swoole_server::addListener来增加监听的端口。业务代码中可以通过调用swoole_server::connection_info来获取某个连接来自于哪个端口。
        2. 监听1024以下的端口需要root权限
        3. 1.8.0版本增加了多端口监听的功能，监听成功后会返回Swoole\Server\Port对象
        4. 在此对象上可以设置另外的事件回调函数和运行参数
        5. 监听失败返回false，可调用getLastError方法获取错误码
        6. 主服务器是WebSocket或Http协议，新监听的TCP端口默认会继承主Server的协议设置。必须单独调用set方法设置新的协议才会启用新协议 查看详细说明

    - bool swoole_server->addProcess(swoole_process $process);
        1. 添加一个用户自定义的工作进程。此函数通常用于创建一个特殊的工作进程，用于监控、上报或者其他特殊的任务。
        2. 此函数在swoole-1.7.9以上版本可用
        3. $process 为swoole_process对象，注意不需要执行start。在swoole_server启动时会自动创建进程，并执行指定的子进程函数
        4. 创建的子进程可以调用$server对象提供的各个方法，如connection_list/connection_info/stats
        5. 在worker/task进程中可以调用$process提供的方法与子进程进行通信
        6. 在用户自定义进程中可以调用$server->sendMessage与worker/task进程通信

    - bool swoole_server->start()
        1. 启动server，监听所有TCP/UDP端口，函数原型：
        2. 启动成功后会创建worker_num+2个进程。Master进程 + Manager进程 + serv->worker_num个Worker进程。启动失败会立即返回false
        3. 启动成功后将进入事件循环，等待客户端连接请求。start方法之后的代码不会执行
        4. 服务器关闭后，start函数返回true，并继续向下执行
        5. 设置了task_worker_num会增加相应数量的Task进程
        6. 函数列表中start之前的方法仅可在start调用前使用，在start之后的方法仅可在onWorkerStart、onReceive等事件回调函数中使用
        7. 主进程: 主进程内有多个Reactor线程，基于epoll/kqueue进行网络事件轮询。收到数据后转发到worker进程去处理
        8. Manager进程: 对所有worker进程进行管理，worker进程生命周期结束或者发生异常时自动回收，并创建新的worker进程
        9. worker进程
            - 对收到的数据进行处理，包括协议解析和响应请求。
            - 启动失败扩展内会抛出致命错误，请检查php error_log的相关信息。errno={number}是标准的Linux Errno，可参考相关文档。
            - 如果开启了log_file设置，信息会打印到指定的Log文件中。
            - 如果想要在开机启动时，自动运行你的Server，可以在/etc/rc.local文件中加入
                ```
                    /usr/bin/php /data/webroot/www.swoole.com/server.php
                ```

    - bool swoole_server->reload(bool $only_reload_taskworkrer = false)
        1. 重启所有worker进程。
        2. $only_reload_taskworkrer 是否仅重启task进程
        3. 一台繁忙的后端服务器随时都在处理请求，如果管理员通过kill进程方式来终止/重启服务器程序，可能导致刚好代码执行到一半终止。这种情况下会产生数据的不一致。如交易系统中，支付逻辑的下一段是发货，假设在支付逻辑之后进程被终止了。会导致用户支付了货币，但并没有发货，后果非常严重。
        4. Swoole提供了柔性终止/重启的机制，管理员只需要向SwooleServer发送特定的信号，Server的worker进程可以安全的结束。
            - SIGTERM: 向主进程/管理进程发送此信号服务器将安全终止
            - 在PHP代码中可以调用$serv->shutdown()完成此操作
            - SIGUSR1: 向主进程/管理进程发送SIGUSR1信号，将平稳地restart所有worker进程
            - 在PHP代码中可以调用$serv->reload()完成此操作
            - swoole的reload有保护机制，当一次reload正在进行时，收到新的重启信号会丢弃
            - 如果设置了user/group，Worker进程可能没有权限向master进程发送信息，这种情况下必须使用root账户，在shell中执行kill指令进行重启
            - reload指令对addProcess添加的用户进程无效

    - function swoole_server->stop(int $worker_id = -1, bool $waitEvent = false);
        1. 使当前worker进程停止运行，并立即触发onWorkerStop回调函数。
        2. 使用此函数代替exit/die结束Worker进程的生命周期
        3. $waitEvent可以控制退出策略，默认为false表示立即退出，设置为true表示等待事件循环为空时再退出
        4. 如果要结束其他Worker进程，可以在stop里面加上worker_id作为参数或者使用swoole_process::kill($worker_pid)
        5. 此方法在1.8.2或更高版本可用
        6. $waitEvent在1.9.19或更高版本可用
            ```
                # 重启所有worker进程
                # 1.7.7版本增加了仅重启task_worker的功能。只需向服务器发送SIGUSR2即可。
                kill -USR1 主进程PID

                #仅重启task进程
                kill -USR2 主进程PID
            ```

    - void swoole_server->shutdown();
        1. 关闭服务器
        2. 此函数可以用在worker进程内。向主进程发送SIGTERM也可以实现关闭服务器。
            ```
                kill -15 主进程PID
            ```

    - swoole_server->tick
        1. tick定时器，可以自定义回调函数。此函数是swoole_timer_tick的别名。
        2. worker进程结束运行后，所有定时器都会自动销毁
        3. tick/after定时器不能在swoole_server->start之前使用
            ```
                在onReceive中使用
                function onReceive($server, $fd, $from_id, $data) {
                    $server->tick(1000, function() use ($server, $fd) {
                        $server->send($fd, "hello world");
                    });
                }
                在onWorkerStart中使用
                低于1.8.0版本task进程不能使用tick/after定时器，所以需要使用$serv->taskworker进行判断
                task进程可以使用addtimer间隔定时器
                function onWorkerStart(swoole_server $serv, $worker_id)
                {
                    if (!$serv->taskworker) {
                        $serv->tick(1000, function ($id) {
                            var_dump($id);
                        });
                    }
                    else
                    {
                        $serv->addtimer(1000);
                    }
                }
            ```

    - swoole_server->after(int $after_time_ms, mixed $callback_function);
        1. 在指定的时间后执行函数，需要swoole-1.7.7以上版本。
        2. swoole_server::after函数是一个一次性定时器，执行完成后就会销毁。
        3. $after_time_ms 指定时间，单位为毫秒
        4. $callback_function 时间到期后所执行的函数，必须是可以调用的。callback函数不接受任何参数
        5. 低于1.8.0版本task进程不支持after定时器，仅支持addtimer定时器
        6. $after_time_ms 最大不得超过 86400000
        7. 此方法是swoole_timer_after函数的别名

    - function swoole_server->defer(callable $callback);
        1. 延后执行一个PHP函数。Swoole底层会在EventLoop循环完成后执行此函数。此函数的目的是为了让一些PHP代码延后执行，程序优先处理IO事件。底层不保证defer的函数会立即执行，如果是系统关键逻辑，需要尽快执行，请使用after定时器实现。
        2. defer函数的别名是swoole_event_defer
        3. $callback为可执行的函数变量，可以是字符串、数组、匿名函数
        4. 在onWorkerStart回调中执行defer时，必须要等到有事件发生才会回调
        5. defer函数在swoole-1.8.0或更高版本可用
            ```
                // 使用实例
                function query($server, $db) {
                    $server->defer(function() use ($db) {
                        $db->close();
                    });
                }
            ```

    - swoole_server->clearTimer
        1. 清除tick/after定时器，此函数是 swoole_timer_clear 的别名。
            ```
                使用示例
                $timer_id = $server->tick(1000, function ($id) use ($server) {
                    $server->clearTimer($id);
                });
            ```

    - bool swoole_server->close(int $fd, bool $reset = false);
        1. 关闭客户端连接，函数原型：
        2. swoole-1.8.0或更高版本可以使用$reset方法
        3. 操作成功返回true，失败返回false.
        4. Server主动close连接，也一样会触发onClose事件。
        5. 不要在close之后写清理逻辑。应当放置到onClose回调中处理
        6. $reset设置为true会强制关闭连接，丢弃发送队列中的数据

    - bool swoole_server->send(int $fd, string $data, int $extraData = 0);
        1. 向客户端发送数据，函数原型：
        2. $data，发送的数据，TCP协议最大不得超过2M，可修改 buffer_output_size 改变允许发送的最大包长度
        3. UDP协议不得超过65507，UDP包头占8字节, IP包头占20字节，65535-28 = 65507
        4. UDP服务器使用$fd保存客户端IP，$extraData保存server_fd和port
        5. 发送成功会返回true
        6. 发送失败会返回false，调用$server->getLastError()方法可以得到失败的错误码

    - bool swoole_server->sendfile(int $fd, string $filename, int $offset =0, int $length = 0);
        1. 发送文件到TCP客户端连接。使用示例：
        2. sendfile函数调用OS提供的sendfile系统调用，由操作系统直接读取文件并写入socket。sendfile只有2次内存拷贝，使用此函数可以降低发送大量文件时操作系统的CPU和内存占用。
        3. $filename 要发送的文件路径，如果文件不存在会返回false
        4. $offset 指定文件偏移量，可以从文件的某个位置起发送数据。默认为0，表示从文件头部开始发送
        5. $length 指定发送的长度，默认为文件尺寸。
        6. 操作成功返回true，失败返回false

    - bool swoole_server->sendto(string $ip, int $port, string $data, int $server_socket = -1);
        1. 函数原型：
        2. $ip为IPv4字符串，如192.168.1.102。如果IP不合法会返回错误
        3. $port为 1-65535的网络端口号，如果端口错误发送会失败
        4. $data要发送的数据内容，可以是文本或者二进制内容
        5. $server_socket 服务器可能会同时监听多个UDP端口，此参数可以指定使用哪个端口发送数据包
            ```
                示例：
                //向IP地址为220.181.57.216主机的9502端口发送一个hello world字符串。
                $server->sendto('220.181.57.216', 9502, "hello world");
                //向IPv6服务器发送UDP数据包
                $server->sendto('2600:3c00::f03c:91ff:fe73:e98f', 9501, "hello world");
            ```

    - bool swoole_server->sendwait(int $fd, string $send_data);
        1. 阻塞地向客户端发送数据。
        2. 有一些特殊的场景，Server需要连续向客户端发送数据，而swoole_server->send数据发送接口是纯异步的，大量数据发送会导致内存发送队列塞满。
        3. 使用swoole_server->sendwait就可以解决此问题，swoole_server->sendwait会阻塞等待连接可写。直到数据发送完毕才会返回。

    - bool swoole_server->sendMessage(mixed $message, int $dst_worker_id);
        1. 此函数可以向任意worker进程或者task进程发送消息。在非主进程和管理进程中可调用。收到消息的进程会触发onPipeMessage事件。
        2. $message为发送的消息数据内容，没有长度限制，但超过8K时会启动内存临时文件
        3. $dst_worker_id为目标进程的ID，范围是0 ~ (worker_num + task_worker_num - 1)
        4. 在Task进程内调用sendMessage是阻塞等待的，发送消息完成后返回
        5. 在Worker进程内调用sendMessage是异步的，消息会先存到发送队列，可写时向管道发送此消息
        6. 在User进程内调用sendMessage底层会自动判断当前的进程是异步还是同步选择不同的发送方式

    - bool function swoole_server->exist(int $fd)
        1. 检测fd对应的连接是否存在。
        2. $fd对应的TCP连接存在返回true，不存在返回false
        3. 此接口是基于共享内存计算，没有任何IO操作
        4. swoole_server->exist在1.7.18以上版本可用

    - function swoole_server->pause(int $fd);
        1. 停止接收数据。
        2. $fd为连接的文件描述符
        3. 调用此函数后会将连接从EventLoop中移除，不再接收客户端数据。
        4. 此函数不影响发送队列的处理
        5. PROCESS模式下，调用pause后，可能有部分数据已经到达Worker进程，因此仍然可能会触发onReceive事件
        6. 低于4.0.0版本方法仅可用于BASE模式

    - function swoole_server->resume(int $fd);
        1. 恢复数据接收。与pause方法成对使用
        2. $fd为连接的文件描述符
        3. 调用此函数后会将连接重新加入到EventLoop中，继续接收客户端数据
        4. 低于4.0.0版本resume方法仅可用于BASE模式

    - bool|array  swoole_server->getClientInfo(int $fd, int $extraData, bool $ignoreError = false)
        1. swoole_server->getClientInfo函数用来获取连接的信息，别名是swoole_server->connection_info

    - swoole_server::getClientList(int $start_fd = 0, int $pagesize = 10);
        1. 用来遍历当前Server所有的客户端连接，Server::getClientList方法是基于共享内存的，不存在IOWait，遍历的速度很快。另外getClientList会返回所有TCP连接，而不仅仅是当前Worker进程的TCP连接。
        2. 此函数接受2个参数，第1个参数是起始fd，第2个参数是每页取多少条，最大不得超过100。
        3. 调用成功将返回一个数字索引数组，元素是取到的$fd。数组会按从小到大排序。最后一个$fd作为新的start_fd再次尝试获取
        4. 调用失败返回false
        5. 推荐使用 swoole_server::$connections 迭代器来遍历连接 getClientList的别名是connection_list
        6. getClientList仅可用于TCP客户端，UDP服务器需要自行保存客户端信息
        7. SWOOLE_BASE模式下只能获取当前进程的连接
            ```
                // 示例：
                $start_fd = 0;
                while(true)
                {
                    $conn_list = $serv->getClientList($start_fd, 10);
                    if ($conn_list===false or count($conn_list) === 0)
                    {
                        echo "finish\n";
                        break;
                    }
                    $start_fd = end($conn_list);
                    var_dump($conn_list);
                    foreach($conn_list as $fd)
                    {
                        $serv->send($fd, "broadcast");
                    }
                }
            ```

    - bool swoole_server::bind(int $fd, int $uid)
        1. 将连接绑定一个用户定义的UID，可以设置dispatch_mode=5设置以此值进行hash固定分配。可以保证某一个UID的连接全部会分配到同一个Worker进程。
        2. 在默认的dispatch_mode=2设置下，server会按照socket fd来分配连接数据到不同的Worker进程。因为fd是不稳定的，一个客户端断开后重新连接，fd会发生改变。这样这个客户端的数据就会被分配到别的Worker。使用bind之后就可以按照用户定义的UID进行分配。即使断线重连，相同UID的TCP连接数据会被分配相同的Worker进程。
        3. $fd 连接的文件描述符
        4. $uid 指定UID
        5. 未绑定UID时默认使用fd取模进行分配
        6. 同一个连接只能被bind一次，如果已经绑定了UID，再次调用bind会返回false
        7. 可以使用$serv->connection_info($fd) 查看连接所绑定UID的值

    - array swoole_server->stats();
        1. 得到当前Server的活动TCP连接数，启动时间，accpet/close的总次数等信息。
        2. stats()方法在1.7.5+后可用
            ```
                // 返回的结果数组示例：
                array (
                  'start_time' => 1409831644,
                  'connection_num' => 1,
                  'accept_count' => 1,
                  'close_count' => 0,
                );

                // start_time 服务器启动的时间
                // connection_num 当前连接的数量
                // accept_count 接受了多少个连接
                // close_count 关闭的连接数量
                // tasking_num 当前正在排队的任务数
            ```

    - int swoole_server::task(mixed $data, int $dst_worker_id = -1) 
        1. 投递一个异步任务到task_worker池中。此函数是非阻塞的，执行完毕会立即返回。Worker进程可以继续处理新的请求。使用Task功能，必须先设置 task_worker_num，并且必须设置Server的onTask和onFinish事件回调函数。
        2. 参数
            - $data要投递的任务数据，可以为除资源类型之外的任意PHP变量
            - $dst_worker_id可以制定要给投递给哪个task进程，传入ID即可，范围是0 - (serv->task_worker_num -1)
        3. 返回值
            - 调用成功，返回值为整数$task_id，表示此任务的ID。如果有finish回应，onFinish回调中会携带$task_id参数
            - 调用失败，返回值为false，$task_id可能为0，因此必须使用===判断是否失败

    - function Server->taskwait(mixed $data, float $timeout = 0.5, int $dstWorkerId = -1) : string | bool
        1. taskwait与task方法作用相同，用于投递一个异步的任务到task进程池去执行。与task不同的是taskwait是同步等待的，直到任务完成或者超时返回。 $result为任务执行的结果，由$serv->finish函数发出。如果此任务超时，这里会返回false。
        2. 第1个参数为投递的任务数据，可以是任意类型，非字符串类型底层会自动进行串化
        3. 第2个参数为超时时间，浮点型，单位为秒，最小支持1ms粒度，超过规定时间内Task进程未返回数据，taskwait将返回false，不再处理后续的任务结果数据
        4. 第3个参数可以指定要给投递给哪个Task进程，传入ID即可，范围是0 - serv->task_worker_num
        5. $dstWorkerId在1.6.11以上版本可用，可以指定目标Task进程的ID，默认为-1表示随机投递，底层会自动选择一个空闲Task进程
        6. 4.0.4以下版本中taskwait是阻塞接口，如果你的Server是全异步的请使用swoole_server::task和swoole_server::finish,不要使用taskwait
        7. 4.0.4以上版本中taskwait底层会进行协程调度，实现完全的异步IO
        8. taskwait方法不能在task进程中调用

    - array swoole_server->taskWaitMulti(array $tasks, double $timeout = 0.5);
        1. 并发执行多个Task
        2. $tasks 必须为数字索引数组，不支持关联索引数组，底层会遍历$tasks将任务逐个投递到Task进程
        3. $timeout 为浮点型，单位为秒，默认为0.5
        4. 任务完成或超时，返回结果数组。结果数组中每个任务结果的顺序与$tasks对应，如：$tasks[2]对应的结果为$result[2]
        5. 某个任务执行超时不会影响其他任务，返回的结果数据中将不包含超时的任务
        6. taskWaitMulti接口在1.8.8或更高版本可用
        7. 最大并发任务不得超过1024

    - function swoole_server->taskCo(array $tasks, float $timeout = 0.5) : array;
        1. 并发执行Task并进行协程调度。仅用于2.0版本。
        2. $tasks任务列表，必须为数组。底层会遍历数组，将每个元素作为task投递到Task进程池
        3. $timeout超时时间，默认为0.5秒，当规定的时间内任务没有全部完成，立即中止并返回结果
        4. 任务完成或超时，返回结果数组。结果数组中每个任务结果的顺序与$tasks对应，如：$tasks[2]对应的结果为$result[2]
        5. 某个任务执行失败或超时，对应的结果数组项为false，如：$tasks[2]失败了，那么$result[2]的值为false
        6. 最大并发任务不得超过1024
        7. taskCo在2.0.9或更高版本可用
        8. 调度过程
            - $tasks列表中的每个任务会随机投递到一个Task工作进程，投递完毕后，yield让出当前协程，并设置一个$timeout秒的定时器
            - 在onFinish中收集对应的任务结果，保存到结果数组中。判断是否所有任务都返回了结果，如果为否，继续等待。如果为是，进行resume恢复对应协程的运行，并清除超时定时器
            - 在规定的时间内任务没有全部完成，定时器先触发，底层清除等待状态。将未完成的任务结果标记为false，立即resume对应协程

    - swoole_server->finish
        1. 此函数用于在task进程中通知worker进程，投递的任务已完成。此函数可以传递结果数据给worker进程。
        2. 使用swoole_server::finish函数必须为Server设置onFinish回调函数。此函数只可用于task进程的onTask回调中
        3. finish方法可以连续多次调用，Worker进程会多次触发onFinish事件
        4. 在onTask回调函数中调用过finish方法后，return数据依然会触发onFinish事件
        5. swoole_server::finish是可选的。如果worker进程不关心任务执行的结果，不需要调用此函数
        6. 在onTask回调函数中return字符串，等同于调用finish

    - array swoole_server::heartbeat(bool $if_close_connection = true);
        1. 检测服务器所有连接，并找出已经超过约定时间的连接。如果指定if_close_connection，则自动关闭超时的连接。未指定仅返回连接的fd数组。
        2. $if_close_connection是否关闭超时的连接，默认为true
        3. 调用成功将返回一个连续数组，元素是已关闭的$fd。
        4. 调用失败返回false
        5. 需要swoole-1.6.10 以上版本
        6. $if_close_connection 在1.7.4+可用

    - function swoole_server->getLastError()
        1. 获取最近一次操作错误的错误码。业务代码中可以根据错误码类型执行不同的逻辑。
        2. 返回一个整型数字错误码
        3. 发送失败错误
            - 1001 连接已经被Server端关闭了，出现这个错误一般是代码中已经执行了$serv->close()关闭了某个连接，但仍然调用$serv->send()向这个连接发送数据
            - 1002 连接已被Client端关闭了，Socket已关闭无法发送数据到对端
            - 1003 正在执行close，onClose回调函数中不得使用$serv->send()
            - 1004 连接已关闭
            - 1005 连接不存在，传入$fd 可能是错误的
            - 1007 接收到了超时的数据，TCP关闭连接后，可能会有部分数据残留在管道缓存区内，这部分数据会被丢弃
            - 1008 发送缓存区已满无法执行send操作，出现这个错误表示这个连接的对端无法及时收数据导致发送缓存区已塞满
            - 1202 发送的数据超过了 server->buffer_output_size 设置
        4. 进程错误
            - 9007：仅在使用dispatch_mode=3时出现，表示当前没有可用的进程，建议调大worker_num进程数量

    - swoole_server->getSocket
        1. 调用此方法可以得到底层的socket句柄，返回的对象为sockets资源句柄。
        2. 此方法需要依赖PHP的sockets扩展，并且编译swoole时需要开启--enable-sockets选项
        3. 使用socket_set_option函数可以设置更底层的一些socket参数。
            ```
                $socket = $server->getSocket();
                if (!socket_set_option($socket, SOL_SOCKET, SO_REUSEADDR, 1)) {
                    echo 'Unable to set option on socket: '. socket_strerror(socket_last_error()) . PHP_EOL;
                }
            ```
        4. 监听端口, 使用listen方法增加的端口，可以使用Swoole\Server\Port对象提供的getSocket方法。
            ```
                $port = $server->listen('127.0.0.1', 9502, SWOOLE_SOCK_TCP);
                $socket = $port->getSocket();
            ```

    - function swoole_server->protect(int $fd, bool $value = 1);
        1. 设置客户端连接为保护状态，不被心跳线程切断。
        2. $fd 要设置保护状态的客户端连接fd
        3. $value 设置的状态，true表示保护状态，false表示不保护

    - function swoole_server->confirm(int $fd);
        1. 确认连接，与enable_delay_receive或wait_for_bind配合使用。当客户端建立连接后，并不监听可读事件。仅触发onConnect事件回调，在onConnect回调中执行confirm确认连接，这时服务器才会监听可读事件，接收来自客户端连接的数据。
        2. $fd 连接的唯一标识符
        3. 确认成功返回true，
        4. $fd对应的连接不存在、已关闭或已经处于监听状态时，返回false，确认失败

 2. 属性列表
    - swoole_server::$setting
        1. swoole_server::set()函数所设置的参数会保存到swoole_server::$setting属性上。在回调函数中可以访问运行参数的值。
        2. 在swoole-1.6.11+可用, 示例：
            ```
                $serv = new swoole_server('127.0.0.1', 9501);
                $serv->set(array('worker_num' => 4));

                echo $serv->setting['worker_num'];
            ```
    - swoole_server::$master_pid
        1. 返回当前服务器主进程的PID。
        2. 只能在onStart/onWorkerStart之后获取到

    - swoole_server::$manager_pid
        1. 返回当前服务器管理进程的PID。
        2. 只能在onStart/onWorkerStart之后获取到

    - int $server->worker_id;
        1. 得到当前Worker进程的编号，包括Task进程。
        2. 这个属性与onWorkerStart时的$worker_id是相同的。
        3. Worker进程编号范围是[0, $serv->setting['worker_num'])
        4. Task进程编号范围是[$serv->setting['worker_num'], $serv->setting['worker_num'] + $serv->setting['task_worker_num'])
        5. 工作进程重启后worker_id的值是不变的

    - int $serv->worker_pid;
        1. 得到当前Worker进程的操作系统进程ID。与posix_getpid()的返回值相同。

    - swoole_server::$taskworker
        1. true表示当前的进程是Task工作进程
        2. false表示当前的进程是Worker进程
        3. 此属性在swoole-1.7.15以上版本可用

    - swoole_server::$connections
        1. TCP连接迭代器，可以使用foreach遍历服务器当前所有的连接，此属性的功能与swoole_server->connnection_list是一致的，但是更加友好。遍历的元素为单个连接的fd。
        2. 注意$connections属性是一个迭代器对象，不是PHP数组，所以不能用var_dump或者数组下标来访问，只能通过foreach进行遍历操作。
            ```
                foreach($server->connections as $fd)
                {
                    $server->send($fd, "hello");
                }
                echo "当前服务器共有 ".count($server->connections). " 个连接\n";
            ```
        3. 此属性在1.7.16以上版本可用
        4. 连接迭代器依赖pcre库（不是PHP的pcre扩展），未安装pcre库无法使用此功能
        5. pcre库的安装方法， http://wiki.swoole.com/wiki/page/312.html
        6. SWOOLE_BASE模式下不支持跨进程操作TCP连接，因此在BASE模式中，只能在当前进程内使用$connections迭代器。

    - swoole_server::$ports
        1. 监听端口数组，如果服务器监听了多个端口可以遍历swoole_server::$ports得到所有Swoole\Server\Port对象。 其中swoole_server::$ports[0]为构造方法所设置的主服务器端口。
            ```
                $ports = swoole_server::$ports;
                $ports[0]->set($settings);
                $ports[1]->on("Receive", function () {
                    //callback
                });
            ```

 3. 事件回调函数
    - Swoole\Server是事件驱动模式，所有的业务逻辑代码必须写在事件回调函数中。当特定的网络事件发生后，底层会主动回调指定的PHP函数。
    - 共支持13种事件，具体详情请参考各个页面详细页
    - PHP语言有4种回调函数的写法
        ```
            // 匿名函数
            $server->on('Request', function ($req, $resp) {
                echo "hello world";
            });
            
            // 类静态方法
            class A
            {
                static function test($req, $resp)
                {
                    echo "hello world";
                }
            }
            $server->on('Request', 'A::Test');
            $server->on('Request', array('A', 'Test'));
            
            // 函数
            function my_onRequest($req, $resp)
            {
                echo "hello world";
            }
            $server->on('Request', 'my_onRequest');
            
            // 对象方法
            class A
            {
                function test($req, $resp)
                {
                    echo "hello world";
                }
            }

            $object = new A();
            $server->on('Request', array($object, 'test'));
        ```
    - 事件执行顺序
        1. 所有事件回调均在$server->start后发生
        2. 服务器关闭程序终止时最后一次事件是onShutdown
        3. 服务器启动成功后，onStart/onManagerStart/onWorkerStart会在不同的进程内并发执行
        4. onReceive/onConnect/onClose在Worker进程中触发
        5. Worker/Task进程启动/结束时会分别调用一次onWorkerStart/onWorkerStop
        6. onTask事件仅在task进程中发生
        7. onFinish事件仅在worker进程中发生
        8. onStart/onManagerStart/onWorkerStart 3个事件的执行顺序是不确定的
    - 异常捕获
        1. swoole不支持set_exception_handler函数
        2. 如果你的PHP代码有抛出异常逻辑，必须在事件回调函数顶层进行try/catch来捕获异常
            ```
                $serv->on('Receive', function() {
                    try
                    {
                        //some code
                    }
                    catch(Exception $e)
                    {
                        //exception code
                    }
                }
            ```


 4. 事件回调函数
    - onStart; function onStart(swoole_server $server);
        1. Server启动在主进程的主线程回调此函数，函数原型
        2. onStart回调中，仅允许echo、打印Log、修改进程名称。不得执行其他操作。onWorkerStart和onStart回调是在不同进程中并行执行的，不存在先后顺序。

    - onShutdown; function onShutdown(swoole_server $server);   
        1. 此事件在Server正常结束时发生
        2. 在此之前Swoole\Server已进行了如下操作
            - 已关闭所有Reactor线程、HeartbeatCheck线程、UdpRecv线程
            - 已关闭所有Worker进程、Task进程、User进程
            - 已close所有TCP/UDP/UnixSocket监听端口
            - 已关闭主Reactor

    - onWorkerStart; function onWorkerStart(swoole_server $server, int $worker_id);
        1. 此事件在Worker进程/Task进程启动时发生。这里创建的对象可以在进程生命周期内使用。

    - onWorkerStop; function onWorkerStop(swoole_server $server, int $worker_id);
        1. 此事件在worker进程终止时发生。在此函数中可以回收worker进程申请的各类资源。原型：

    - onWorkerExit; function onWorkerExit(swoole_server $server, int $worker_id);
        1. 仅在开启reload_async特性后有效。异步重启特性，会先创建新的Worker进程处理新请求，旧的Worker进程自行退出。

    - onConnect; function onConnect(swoole_server $server, int $fd, int $reactorId);
        1. 有新的连接进入时，在worker进程中回调。函数原型：

    - onReceive; function onReceive(swoole_server $server, int $fd, int $reactor_id, string $data);
        1. 接收到数据时回调此函数，发生在worker进程中。函数原型：

    - onPacket; function onPacket(swoole_server $server, string $data, array $client_info);
        1. 接收到UDP数据包时回调此函数，发生在worker进程中。函数原型：

    - onClose; function onClose(swoole_server $server, int $fd, int $reactorId);
        1. TCP客户端连接关闭后，在worker进程中回调此函数。
        2. onClose回调函数如果发生了致命错误，会导致连接泄漏。通过netstat命令会看到大量CLOSE_WAIT状态的TCP连接
        3. $server 是swoole_server对象
        4. $fd 是连接的文件描述符
        5. $reactorId 来自那个reactor线程

    - onBufferFull; function onBufferFull(Swoole\Server $serv, int $fd);
        1. 当缓存区达到最高水位时触发此事件。
        2. 设置server->buffer_high_watermark选项来控制缓存区高水位线，单位为字节
        3. 触发onBufferFull表明此连接$fd的发送队列已触顶即将塞满，这时不应当再向此$fd发送数据

    - onBufferEmpty; function onBufferEmpty(Swoole\Server $serv, int $fd);
        1. 当缓存区低于最低水位线时触发此事件。
        2. 设置server->buffer_low_watermark来控制缓存区低水位线
        3. 触发此事件后，表明当前的$fd发送队列中的数据已被发出，可以继续向此连接发送数据了

    - onTask; function onTask(swoole_server $serv, int $task_id, int $src_worker_id, mixed $data);
        1. 在task_worker进程内被调用。worker进程可以使用swoole_server_task函数向task_worker进程投递新的任务。当前的Task进程在调用onTask回调函数时会将进程状态切换为忙碌，这时将不再接收新的Task，当onTask函数返回时会将进程状态切换为空闲然后继续接收新的Task。
        2. $task_id是任务ID，由swoole扩展内自动生成，用于区分不同的任务。$task_id和$src_worker_id组合起来才是全局唯一的，不同的worker进程投递的任务ID可能会有相同
        3. $src_worker_id来自于哪个worker进程
        4. $data 是任务的内容

    - onFinish; void onFinish(swoole_server $serv, int $task_id, string $data)
        1. 当worker进程投递的任务在task_worker中完成时，task进程会通过swoole_server->finish()方法将任务处理的结果发送给worker进程。
        2. $task_id是任务的ID
        3. $data是任务处理的结果内容

    - onPipeMessage; void onPipeMessage(swoole_server $server, int $src_worker_id, mixed $message);
        1. 当工作进程收到由 sendMessage 发送的管道消息时会触发onPipeMessage事件。worker/task进程都可能会触发onPipeMessage事件。

    - onWorkerError; void onWorkerError(swoole_server $serv, int $worker_id, int $worker_pid, int $exit_code, int $signal);
        1. 当worker/task_worker进程发生异常后会在Manager进程内回调此函数。

    - onManagerStart; void onManagerStart(swoole_server $serv);
        1. 当管理进程启动时调用它; 在这个回调函数中可以修改管理进程的名称。
        2. 注意manager进程中不能添加定时器; manager进程中可以调用sendMessage接口向其他工作进程发送消息

    - onManagerStop; void onManagerStop(swoole_server $serv);
        1. 当管理进程结束时调用它，函数原型：











 

## swoole_client: TCP/UDP/UnixSocket客户端, 支持异步事件驱动编程

## Coroutine: 协程管理

## AsyncIO: 异步IO

## Memory: 内存管理


## Process: 进程管理, 子进程; 命名空间: new \Swoole\Process; 进程管理模块，可以方便的创建子进程，进程间通信，进程管理。
 1. 创建子进程 swoole_process::__construct; new swoole_process(callable $function, $redirect_stdin_stdout = false, $pipe_type = 2);
    - $function，子进程创建成功后要执行的函数，底层会自动将函数保存到对象的callback属性上。如果希望更改执行的函数，可赋值新的函数到对象的callback属性
    - $redirect_stdin_stdout，重定向子进程的标准输入和输出。启用此选项后，在子进程内输出内容将不是打印屏幕，而是写入到主进程管道。读取键盘输入将变为从管道中读取数据。默认为阻塞读取。
    - $pipe_type，管道类型，启用$redirect_stdin_stdout后，此选项将忽略用户参数，强制为1。如果子进程内没有进程间通信，可以设置为 0
    - 例:
        ```
            // 直接调用 function 函数
            $process = new swoole_process('callback_function');
            // 调用 className 类中的 staticFunction 静态方法
            $process = new swoole_process(array('className', 'staticFunction'));
            // 调用实例化类 $newObject 中的 publicFunction 方法
            $process = new swoole_process(array($newObject, 'publicFunction'));
        ```
    - 额外: use 关键字只可以用在闭包中, 不可以用在正常 function 函数定义中, 如果正常函数需要引用到外部变量, 可以用 global 但是不可以用 use

 2. swoole_process->start
    - 执行fork系统调用，启动进程。
    - 创建成功返回子进程的PID，创建失败返回false。可使用swoole_errno和swoole_strerror得到错误码和错误信息。
    - $process->pid 属性为子进程的PID
    - $process->pipe 属性为管道的文件描述符
    - 子进程会继承父进程的内存和文件句柄
    - 子进程在启动时会清除从父进程继承的EventLoop、Signal、Timer
    - PS 注: 执行后子进程会保持父进程的内存和资源，如父进程内创建了一个redis连接，那么在子进程会保留此对象，所有操作都是对同一个连接进行的。
    - 例:
        ```
            $pid = $process->start();
            print_r($pid);
        ```

 3. swoole_process->name
    - 修改进程名称。此函数是swoole_set_process_name的别名。
    - $process->name("php server.php: worker");
    - 在执行exec后，进程名称会被新的程序重新设置
    - 此方法在swoole-1.7.9以上版本可用
    - name方法应当在start之后的子进程回调函数中使用
    - swoole_set_process_name is not supported on MacOS, 不支持mac
    - 例:
        ```
            $process->name("php server.php: worker");
        ```

 4. bool swoole_process->exec(string $execfile, array $args)
    - 执行一个外部程序，此函数是exec系统调用的封装。
    - $execfile指定可执行文件的绝对路径，如 "/usr/bin/python"
    - $args是一个数组，是exec的参数列表，如 array('test.py', 123)，相当与python test.py 123
    - 执行成功后，当前进程的代码段将会被新程序替换。子进程蜕变成另外一套程序。父进程与当前进程仍然是父子进程关系。
    - 父进程与新进程之间可以通过可以通过标准输入输出进行通信，必须启用标准输入输出重定向。
    - $execfile必须使用绝对路径，否则会报文件不存在错误
    - 由于exec系统调用会使用指定的程序覆盖当前程序，子进程需要读写标准输出与父进程进行通信, 如果未指定redirect_stdin_stdout = true，执行exec后子进程与父进程无法通信
    - 例:
        ```
            // 调用示例
            $process = new \Swoole\Process(function (\Swoole\Process $childProcess) {
                // 不支持这种写法
                // $childProcess->exec('/usr/local/bin/php /var/www/project/yii-best-practice/cli/yii 
                t/index -m=123 abc xyz');

                 // 封装 exec 系统调用
                 // 绝对路径
                 // 参数必须分开放到数组中
                $childProcess->exec('/usr/local/bin/php', ['/var/www/project/yii-best-practice/cli/yii', 
                't/index', '-m=123', 'abc', 'xyz']); // exec 系统调用
            });
            $process->start(); // 启动子进程
            父进程与exec进程使用管道进行通信:

            // exec - 与exec进程进行管道通信
            use Swoole\Process;
            $process = new Process(function (Process $worker) {
                $worker->exec('/bin/echo', ['hello']);
                $worker->write('hello');
            }, true); // 需要启用标准输入输出重定向
            $process->start();
            echo "from exec: ". $process->read(). "\n";

            // 执行 shell 命令
            // exec方法与PHP提供的shell_exec不同，它是更底层的系统调用封装。如果需要执行一条shell命令，请使用以下方法：

            $worker->exec('/bin/sh', array('-c', "cp -rf /data/test/* /tmp/test/"));
        ```

 5. int swoole_process->write(string $data);
    - 向管道内写入数据。
    - $data的长度在Linux系统下最大不超过8K，MacOS/FreeBSD下最大不超过2K
    - 在子进程内调用write，父进程可以调用read接收此数据
    - 在父进程内调用write，子进程可以调用read接收此数据
    - Swoole底层使用Unix Socket实现通信，Unix Socket是内核实现的全内存通信，无任何IO消耗。在1进程write，1进程read，每次读写1024字节数据的测试中，100万次通信仅需1.02秒。
    - 管道通信默认的方式是流式，write写入的数据在read可能会被底层合并。可以设置swoole_process构造函数的第三个参数为2改变为数据报式。MacOS/FreeBSD可以设置net.local.dgram.maxdgram内核参数修改最大长度
    - 异步模式
        1. 如果进程内使用了异步IO，比如swoole_event_add，进程内执行write操作将变为异步模式。swoole底层会监听可写事件，自动完成管道写入。
        2. 异步模式下如果SOCKET缓存区已满，Swoole的处理逻辑请参考 swoole_event_write
    - 同步模式
        1. 进程内未使用任何异步IO，当前管道为同步阻塞模式，如果缓存区已满，将阻塞等待直到write操作完成。
        2. Task进程就是同步阻塞的模式，如果管道的缓存区已满，调用write时会发生阻塞
    - 乱序丢包
        1. 很多网络文章提到DGRAM模式下会出现丢包、乱序问题，实际上这些问题仅存在于Internet网络的UDP通信。UnixSocket是Linux内核实现的内存数据队列，不会出现丢包乱序问题。write写入和read读取的顺序是完全一致的。write返回成功后一定是可以read到的。

 6. function swoole_process->read(int $buffer_size=8192) : string | bool;
    - 从管道中读取数据。
    - $buffer_size是缓冲区的大小，默认为8192，最大不超过64K
    - 管道类型为DGRAM数据报时，read可以读取完整的一个数据包
    - 管道类型为STREAM时，read是流式的，需要自行处理包完整性问题
    - 读取成功返回二进制数据字符串，读取失败返回false
    - 这里是同步阻塞读取的，可以使用swoole_event_add将管道加入到事件循环中，变为异步模式, 例:
        ```
            function callback_function_async(swoole_process $worker)
            {
                $GLOBALS['worker'] = $worker;
                swoole_event_add($worker->pipe, function($pipe) {
                    $worker = $GLOBALS['worker'];
                    $recv = $worker->read();

                    echo "From Master: $recv\n";

                    //send data to master
                    $worker->write("hello master\n");

                    sleep(2);

                    $worker->exit(0);
                });
            }
        ```
    - 注意事项: 由于Swoole底层使用了epoll的LT模式，因此swoole_event_add添加的事件监听，在事件发生后回调函数中必须调用read方法读取socket中的数据，否则底层会持续触发事件回调。

 7. function swoole_process->setTimeout(double $timeout)
    - 设置管道读写操作的超时时间。
    - $timeout单位为秒，支持浮点型，如1.5表示1s+500ms
    - 设置成功返回true
    - 设置失败返回false，可使用swoole_errno获取错误码
    - 设置成功后，调用recv和write在规定时间内未读取或写入成功，将返回false，可使用swoole_errno获取错误码。
    - 在1.9.21或更高版本可用

 8. function swoole_process->setBlocking(bool $blocking = true);
    - 设置管道是否为阻塞模式。默认Process的管道为同步阻塞。
    - $blocking 布尔型，默认为true，设置为false时管道为非阻塞模式
    - 需要1.10.3/2.1.2或更高版本
    - 非阻塞模式
        1. 在异步程序中使用swoole_event_add添加管道事件监听时底层会自动将管道设置为非阻塞
        2. 在异步程序中使用swoole_event_write异步写入数据时底层会自动将管道设置为非阻塞

 9. bool swoole_process->useQueue(int $msgkey = 0, int $mode = 2);
    - 启用消息队列作为进程间通信。
    - $msgkey是消息队列的key，默认会使用ftok(__FILE__, 1)作为KEY
    - $mode通信模式，默认为2，表示争抢模式，所有创建的子进程都会从队列中取数据
    - 如果创建消息队列失败，会返回false。可使用swoole_strerror(swoole_errno()) 得到错误码和错误信息。
    - 使用模式2后，创建的子进程无法进行单独通信，比如发给特定子进程。
    - $process对象并未执行start，也可以执行push/pop向队列推送/提取数据
    - 消息队列通信方式与管道不可共用。消息队列不支持EventLoop，使用消息队列后只能使用同步阻塞模式
    - CygWin 环境不支持消息队列，请勿在此环境下使用
    - 非阻塞
        1. 在1.9.2或更高版本中增加了swoole_process::IPC_NOWAIT的支持，可将队列设置为非阻塞。在非阻塞模式下，队列已满调用push方法、队列已空调用pop方法时将不再阻塞立即返回。
        ```
            //设置为非阻塞模式
            $process->useQueue($key, $mode | swoole_process::IPC_NOWAIT);
        ```

 10. array swoole_process->statQueue();
    - 查看消息队列状态。
    - 返回一个数组，包括2项信息, 例:
        ```
            // queue_num 队列中的任务数量
            // queue_bytes 队列数据的总字节数
            array(
              "queue_num" => 10,
              "queue_bytes" => 161,
            );
        ```
 11. function swoole_process->freeQueue();
    - 删除队列。此方法与useQueue成对使用，useQueue创建队列，使用freeQueue销毁队列。销毁队列后队列中的数据会被清空。
    - 如果程序中只调用了useQueue方法，未调用freeQueue在程序结束时并不会清除数据。重新运行程序时可以继续读取上次运行时留下的数据。
    - 系统重启时消息队列中的数据会被丢弃。
    - 文档其实说的有点问题，要想继续读取上次运行的数据，必须在useQueue时指定上次的msqid才行。

 12. bool swoole_process->push(string $data);
    - 投递数据到消息队列中。
    - $data要投递的数据，长度受限与操作系统内核参数的限制。默认为8192，最大不超过65536
    - 操作失败会返回false，成功返回true
    - 默认模式下（阻塞模式），如果队列已满，push方法会阻塞等待
    - 非阻塞模式下，如果队列已满，push方法会立即返回false

 13. string swoole_process->pop(int $maxsize = 8192);
    - 从队列中提取数据。
    - $maxsize表示获取数据的最大尺寸，默认为8192
    - 操作成功会返回提取到的数据内容，失败返回false
    - 默认模式下，如果队列中没有数据，pop方法会阻塞等待
    - 非阻塞模式下，如果队列中没有数据，pop方法会立即返回false，并设置错误码为ENOMSG

 14. bool swoole_process->close(int $which = 0);
    - 用于关闭创建的好的管道。
    - $which 指定关闭哪一个管道，默认为0表示同时关闭读和写，1：关闭写，2关闭读
    - 有一些特殊的情况swoole_process对象无法释放，如果持续创建进程会导致连接泄漏。调用此函数就可以直接关闭管道，释放资源。

 15. int swoole_process->exit(int $status=0);
    - 退出子进程
    - $status是退出进程的状态码，如果为0表示正常结束，会继续执行PHP的shutdown_function，其他扩展的清理工作。
    - 如果$status不为0，表示异常退出，会立即终止进程。不再执行PHP的shutdown_function，其他扩展的清理工作。
    - 在父进程中，执行swoole_process::wait可以得到子进程退出的事件和状态码。

 16. bool swoole_process::kill($pid, $signo = SIGTERM);
    - 向指定pid进程发送信号
    - 默认的信号为SIGTERM，表示终止进程
    - $signo=0，可以检测进程是否存在，不会发送信号
    - 僵尸进程
        1. 子进程退出后，父进程务必要执行swoole_process::wait进行回收，否则这个子进程就会变为僵尸进程。会浪费操作系统的进程资源。
        2. 父进程可以设置监听SIGCHLD信号，收到信号后执行swoole_process::wait回收退出的子进程。

 17. array swoole_process::wait(bool $blocking = true);
    - 回收结束运行的子进程。
    - $blocking 参数可以指定是否阻塞等待，默认为阻塞
    - 操作成功会返回一个数组包含子进程的PID、退出状态码、被哪种信号KILL
        ```$result = array('code' => 0, 'pid' => 15001, 'signal' => 15);```
    - 失败返回false
    - 子进程结束必须要执行wait进行回收，否则子进程会变成僵尸进程
    - $blocking 仅在1.7.10以上版本可用
    - 使用swoole_process作为监控父进程，创建管理子process时，父类必须注册信号SIGCHLD对退出的进程执行wait，否则子process一旦被kill会引起父process exit
    - 在异步信号回调中执行wait
        ```
        swoole_process::signal(SIGCHLD, function($sig) {
          //必须为false，非阻塞模式
          while($ret =  swoole_process::wait(false)) {
              echo "PID={$ret['pid']}\n";
          }
        });
        
        // 信号发生时可能同时有多个子进程退出
        // 必须循环执行wait直到返回false
        ```

 18. swoole_process::daemon
    - 使当前进程蜕变为一个守护进程。
        ```
            //低于1.9.1的版本
            bool swoole_process::daemon(bool $nochdir = false, bool $noclose = false);
            //1.9.1或更高版本
            bool swoole_process::daemon(bool $nochdir = true, bool $noclose = true);
        ```
    - $nochdir，为true表示不要切换当前目录到根目录。
    - $noclose，为true表示不要关闭标准输入输出文件描述符。
    - 此函数在1.7.5版本后可用
    - 1.9.1或更高版本修改了默认值，现在默认nochir和noclose均为true
    - 蜕变为守护进程时，该进程的PID将发生变化，可以使用getmypid()来获取当前的PID

 19. bool swoole_process::signal(int $signo, callable $callback);
    - 设置异步信号监听。
    - 此方法基于signalfd和eventloop是异步IO，不能用于同步程序中
    - 同步阻塞的程序可以使用pcntl扩展提供的pcntl_signal
    - $callback如果为null，表示移除信号监听
    - 如果已设置了此信号的回调函数，重新设置时会覆盖历史设置
        ```
            使用举例：
            swoole_process::signal(SIGTERM, function($signo) {
                 echo "shutdown.";
            });
            swoole_server中不能设置SIGTERM和SIGALAM信号
            swoole_process::signal在swoole-1.7.9以上版本可用
            信号移除特性仅在1.7.21或更高版本可用
        ```

 20. function swoole_process::alarm(int $interval_usec, int $type = ITIMER_REAL) : bool
    - 高精度定时器，是操作系统setitimer系统调用的封装，可以设置微秒级别的定时器。定时器会触发信号，需要与swoole_process::signal或pcntl_signal配合使用。
    - $interval_usec 定时器间隔时间，单位为微秒。如果为负数表示清除定时器
    - $type 定时器类型，0 表示为真实时间,触发SIGALAM信号，1 表示用户态CPU时间，触发SIGVTALAM信号，2 表示用户态+内核态时间，触发SIGPROF信号
    - 设置成功返回true，失败返回false，可以使用swoole_errno得到错误码
    - alarm不能和Swoole\Timer同时使用
    - alarm在1.8.13或更高版本可用
        ```
            swoole_process::signal(SIGALRM, function () {
                static $i = 0;
                echo "#{$i}\talarm\n";
                $i++;
                if ($i > 20) {
                    swoole_process::alarm(-1);
                }
            });

            //100ms
            swoole_process::alarm(100 * 1000);
        ```

 21. function swoole_process::setAffinity(array $cpu_set);
    - 设置CPU亲和性，可以将进程绑定到特定的CPU核上。
    - 接受一个数组参数表示绑定哪些CPU核，如array(0,2,3)表示绑定CPU0/CPU2/CPU3
    - 成功返回true，失败返回false
    - $cpu_set内的元素不能超过CPU核数
    - CPU-ID不得超过（CPU核数 - 1）
    - 使用 swoole_cpu_num() 可以得到当前服务器的CPU核数
    - setAffinity函数在1.7.18以上版本可用
    - 此函数的作用是让进程只在某几个CPU核上运行，让出某些CPU资源执行更重要的程序。



## WebSocket: 1.7.9增加了内置的WebSocket服务器支持，通过几行PHP代码就可以写出一个异步非阻塞多进程的WebSocket服务器。
 1. 回调函数
    - WebSocket除了接收Swoole\Server和Swoole\Http\Server基类的回调函数外，额外增加了3个回调函数设置。其中：onMessage回调函数为必选, onOpen和onHandShake回调函数为可选
        1. function onHandShake(swoole_http_request $request, swoole_http_response $response);
            - WebSocket建立连接后进行握手。WebSocket服务器已经内置了handshake，如果用户希望自己进行握手处理，可以设置onHandShake事件回调函数。
            - onHandShake事件回调是可选的
            - 设置onHandShake回调函数后不会再触发onOpen事件，需要应用代码自行处理
            - onHandShake函数必须返回true表示握手成功，返回其他值表示握手失败
            - 内置的握手协议为Sec-WebSocket-Version: 13，低版本浏览器需要自行实现握手
            - 1.8.1或更高版本可以使用server->defer调用onOpen逻辑
            - 注意： 仅仅你需要自行处理handshake的时候再设置这个回调函数，如果您不需要“自定义”握手过程，那么不要设置该回调，用swoole默认的握手即可。下面是“自定义”handshake事件回调函数中必须要具备的：
            ```
                $server->on('handshake', function (\swoole_http_request $request, \swoole_http_response $response) {
                    // print_r( $request->header );
                    // if (如果不满足我某些自定义的需求条件，那么返回end输出，返回false，握手失败) {
                    //    $response->end();
                    //     return false;
                    // }

                    // websocket握手连接算法验证
                    $secWebSocketKey = $request->header['sec-websocket-key'];
                    $patten = '#^[+/0-9A-Za-z]{21}[AQgw]==$#';
                    if (0 === preg_match($patten, $secWebSocketKey) || 16 !== strlen(base64_decode($secWebSocketKey))) {
                        $response->end();
                        return false;
                    }
                    echo $request->header['sec-websocket-key'];
                    $key = base64_encode(sha1(
                        $request->header['sec-websocket-key'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11',
                        true
                    ));

                    $headers = [
                        'Upgrade' => 'websocket',
                        'Connection' => 'Upgrade',
                        'Sec-WebSocket-Accept' => $key,
                        'Sec-WebSocket-Version' => '13',
                    ];

                    // WebSocket connection to 'ws://127.0.0.1:9502/'
                    // failed: Error during WebSocket handshake:
                    // Response must not include 'Sec-WebSocket-Protocol' header if not present in request: websocket
                    if (isset($request->header['sec-websocket-protocol'])) {
                        $headers['Sec-WebSocket-Protocol'] = $request->header['sec-websocket-protocol'];
                    }

                    foreach ($headers as $key => $val) {
                        $response->header($key, $val);
                    }

                    $response->status(101);
                    $response->end();
                    echo "connected!" . PHP_EOL;
                    return true;
                });
            ```
        2. function onOpen(swoole_websocket_server $svr, swoole_http_request $req);
            - 当WebSocket客户端与服务器建立连接并完成握手后会回调此函数。
            - $req 是一个Http请求对象，包含了客户端发来的握手请求信息
            - onOpen事件函数中可以调用push向客户端发送数据或者调用close关闭连接
            - onOpen事件回调是可选的
        3. function onMessage(swoole_server $server, swoole_websocket_frame $frame)
            - 当服务器收到来自客户端的数据帧时会回调此函数。
            - $frame 是swoole_websocket_frame对象，包含了客户端发来的数据帧信息
            - onMessage回调必须被设置，未设置服务器将无法启动
            - 客户端发送的ping帧不会触发onMessage，底层会自动回复pong包
            - swoole_websocket_frame 共有4个属性，分别是: 
                1. $frame->fd，客户端的socket id，使用$server->push推送数据时需要用到
                2. $frame->data，数据内容，可以是文本内容也可以是二进制数据，可以通过opcode的值来判断
                3. $frame->opcode，WebSocket的OpCode类型，可以参考WebSocket协议标准文档
                4. $frame->finish， 表示数据帧是否完整，一个WebSocket请求可能会分成多个数据帧进行发送（底层已经实现了自动合并数据帧，现在不用担心接收到的数据帧不完整）
                5. PS注: $frame->data 如果是文本类型，编码格式必然是UTF-8，这是WebSocket协议规定的
            - OpCode与数据类型: 
                1. WEBSOCKET_OPCODE_TEXT = 0x1 ，文本数据
                2. WEBSOCKET_OPCODE_BINARY = 0x2 ，二进制数据
 2. 函数列表
    - Swoole\WebSocket\Server是Swoole\Server的子类，因此可以调用Swoole\Server的全部方法。
    - 需要注意WebSocket服务器向客户端发送数据应当使用Swoole\WebSocket\Server::push方法，此方法会进行WebSocket协议打包。而Swoole\Server::send方法是原始的TCP发送接口。 
    - Swoole\WebSocket\Server::disconnect方法可以从服务端主动关闭一个WebSocket连接，可以指定状态码(根据WebSocket协议，可使用的状态码为十进制的一个整数，取值可以是1000或4000-4999)和关闭原因(采用utf-8编码、字节长度不超过125的字符串)。在未指定情况下状态码为1000，关闭原因为空。
        1. function swoole_websocket_server->push(int $fd, string $data, int $opcode = 1, bool $finish = true);
            - 向websocket客户端连接推送数据，长度最大不得超过2M。
            - $fd 客户端连接的ID，如果指定的$fd对应的TCP连接并非websocket客户端，将会发送失败
            - $data 要发送的数据内容
            - $opcode，指定发送数据内容的格式，默认为文本。发送二进制内容$opcode参数需要设置为WEBSOCKET_OPCODE_BINARY
            - 发送成功返回true，发送失败返回false
            - swoole_websocket_server->push在swoole-1.7.11以上版本可用
        2. function swoole_websocket_server->exist(int $fd);
            - 判断WebSocket客户端是否存在，并且状态为Active状态。
            - 连接存在，并且已完成WebSocket握手，返回true
            - 连接不存在或尚未完成握手，返回false
        3. function swoole_websocket_server::pack(string $data, int $opcode = 1, bool $finish = true, bool $mask = false) : string;
            - 打包WebSocket消息。函数原型：
            - $data：消息内容
            - $opcode：WebSocket的opcode指令类型，1表示文本，2表示二进制数据，9表示心跳ping
            - $finish：帧是否完成
            - $mask：是否设置掩码
            - 返回打包好的WebSocket数据包，可通过Socket发送给对端
        4. swoole_websocket_server::unpack(string $data);
            - 解析WebSocket数据帧。函数原型：
            - 解析失败返回false，解析成功返回Swoole\WebSocket\Frame对象
        5. function swoole_websocket_server->disconnect(int $fd, int $code = 1000, string $reason = "");
            - 主动向websocket客户端发送关闭帧并关闭该连接
            - $fd 客户端连接的ID，如果指定的$fd对应的TCP连接并非websocket客户端，将会发送失败
            - $code 关闭连接的状态码，根据RFC6455，对于应用程序关闭连接状态码，取值范围为1000或4000-4999之间
            - $reason 关闭连接的原因，utf-8格式字符串，字节长度不超过125
            - 发送成功返回true，发送失败或状态码非法时返回false
            - swoole_websocket_server->disconnect在swoole-4.0.3以上版本可用
 3. 预定义常量
    - WebSocket数据帧类型
        1. WEBSOCKET_OPCODE_TEXT = 0x1，UTF-8文本字符数据
        2. WEBSOCKET_OPCODE_BINARY = 0x2，二进制数据
    - 从1.9版本起:
        1. WEBSOCKET_OPCODE_PING = 0x9，ping类型数据
    - WebSocket连接状态
        1. WEBSOCKET_STATUS_CONNECTION = 1，连接进入等待握手
        2. WEBSOCKET_STATUS_HANDSHAKE = 2，正在握手
        3. WEBSOCKET_STATUS_FRAME = 3，已握手成功等待浏览器发送数据帧
    - 未测试: 基本使用:
        1. 如何判断连接是否为WebSocket客户端
        ```
            数据帧类型是在push方法中用来设置数据帧类型用到的 连接状态，可用swoole_websocket_server->connection_info($fd) 返回的数组中有一项为 websocket_status，来判断websocket连接状态, 据此状态可以判断是否为WebSocket客户端。
            WEBSOCKET_STATUS_CONNECTION = 1，连接进入等待握手
            WEBSOCKET_STATUS_HANDSHAKE = 2，正在握手
            WEBSOCKET_STATUS_FRAME = 3，已握手成功等待浏览器发送数据帧
        ```
 4. 配置选项
    - WebSocket\Server是Server的子类，可以使用Server::set方法传入配置选项，设置某些参数。
    - websocket_subprotocol
    - 设置WebSocket子协议。设置后握手响应的Http头会增加Sec-WebSocket-Protocol: {$websocket_subprotocol}。具体使用方法请参考WebSocket协议相关RFC文档。例如:
        ```
            $server->set([
                'websocket_subprotocol' => 'chat',
            ]);
        ```

 5. 注意问题: session 与 cookie
    - 1. 单纯的 websocket 链接中并不支持 session 和 cookie
    - 2. 但是业务中确实是需要, 如何在 websocket 中设置 session, 和获取 session 其实如下:
        - 由 a.php 页面发起 ws 链接; 发起链接前, 在 a.php 中设置 cookie 和 session 其实, 在 websocket 中是可以获取 a.php 中设置的 session 和 cookie 的
        - 如果由 a.html 页面发起 ws 链接; 可以在建立 websocket 前 使用 jquery.cookie 等 设置 cookie ; 那么在 ws/websocket 后台中也是可以获取 cookie 的
    - 3. 如果要自定义 websocket 链接中的 header ; 可以自己定义和设置握手函数: onHandShake, 在这里设置 response 的 header ; 不过设置 onHandShake 就无法默认调用 onOpen, 要自定义触发; 详见[https://wiki.swoole.com/wiki/page/409.html]

## HttpServer
 1. swoole_http_server对Http协议的支持并不完整，建议仅作为应用服务器。并且在前端增加Nginx作为代理.
    - swoole-1.7.7增加了内置Http服务器的支持，通过几行代码即可写出一个异步非阻塞多进程的Http服务器。
        ```
            $http = new swoole_http_server("127.0.0.1", 9501);
            $http->on('request', function ($request, $response) {
                $response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
            });
            $http->start();

            // ab -c 200 -n 200000 -k http://127.0.0.1:9501
        ```
    - nginx+swoole配置:
        ```
            server {
                root /data/wwwroot/;
                server_name local.swoole.com;

                location / {
                    proxy_http_version 1.1;
                    proxy_set_header Connection "keep-alive";
                    proxy_set_header X-Real-IP $remote_addr;
                    if (!-e $request_filename) {
                         proxy_pass http://127.0.0.1:9501;
                    }
                }
            }
            # 在swoole中通过读取$request->header['x-real-ip']来获取客户端的真实IP
        ```
 2. 使用Http2协议
    - 需要依赖nghttp2库，下载nghttp2后编译安装, 使用Http2协议必须开启openssl
    - 需要高版本openssl必须支持TLS1.2、ALPN、NPN
        ```./configure --enable-openssl --enable-http2```
    - 设置http服务器的 open_http2_protocol 为 true
    - 例:
        ```
            $serv = new swoole_http_server("127.0.0.1", 9501, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
            $serv->set([
                'ssl_cert_file' => $ssl_dir . '/ssl.crt',
                'ssl_key_file' => $ssl_dir . '/ssl.key',
                'open_http2_protocol' => true,
            ]);
        ```
 3. swoole_http_server
    - swoole_http_server继承自swoole_server，是一个完整的http服务器实现。swoole_http_server支持同步和异步2种模式。
    - http/websocket服务器都是继承自swoole_server，所以swoole_server提供的API，如task/finish/tick等都可以使用
    - 无论是同步模式还是异步模式，swoole_http_server都可以维持大量TCP客户端连接。同步/异步仅仅体现在对请求的处理方式上。示例：
        ```
            $http = new swoole_http_server("127.0.0.1", 9501);
            $http->on('request', function ($request, $response) {
                $response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
            });
            $http->start();
        ```
    - 同步模式
        1. 这种模式等同于nginx+php-fpm/apache，它需要设置大量worker进程来完成并发请求处理。Worker进程内可以使用同步阻塞IO，编程方式与普通PHP Web程序完全一致。
        2. 与php-fpm/apache不同的是，客户端连接并不会独占进程，服务器依然可以应对大量并发连接。
    - 异步模式
        1. 这种模式下整个服务器是异步非阻塞的，服务器可以应对大规模的并发连接和并发请求。但编程方式需要完全使用异步API，如MySQL、redis、http_client、file_get_contents、sleep等阻塞IO操作必须切换为异步的方式，如异步swoole_client，swoole_event_add，swoole_timer，swoole_get_mysqli_sock等API。

 4. 事件
    - swoole_http_server->on
        1. 注册事件回调函数，与swoole_server->on相同。swoole_http_server->on的不同之处是：
            - swoole_http_server->on不接受onConnect/onReceive回调设置
            - swoole_http_server->on 额外接受1种新的事件类型onRequest
        2. onRequest事件
            - 在收到一个完整的Http请求后，会回调此函数。回调函数共有2个参数：
            - $request，Http请求信息对象，包含了header/get/post/cookie等相关信息
            - $response，Http响应对象，支持cookie/header/status等Http操作
            - 在onRequest回调函数返回时底层会销毁$request和$response对象，如果未执行$response->end()操作，底层会自动执行一次$response->end("")
            - onRequest在1.7.7后可用
            - $response/$request 对象传递给其他函数时，不要加&引用符号
            - $response/$request 对象传递给其他函数后，引用计数会增加，onRequest退出时不会销毁
            - 例:
                ```
                    $http_server->on('request', function(swoole_http_request $request, swoole_http_response $response) {
                         $response->end("<h1>hello swoole</h1>");
                    })
                ```
    - swoole_http_server->start
        1. 启动Http服务器。```swoole_http_server->start()```
        2. 启动后开始监听端口，并接收新的Http和WebSocket请求。使用on方法注册的事件回调，如onWorkerStart/onShutdown等事件回调函数依然有效。

 5. 请求与响应信息
    - swoole_http_request
        1. Http请求对象，保存了Http客户端请求的相关信息，包括GET、POST、COOKIE、Header等。
        2. Request对象销毁时会自动删除上传的临时文件
        3. 请勿使用&符号引用$request对象
        4. request 对象属性, 返回数组的key全部为小写
            - swoole_http_request->$header; // Http请求的头部信息。类型为数组，所有key均为小写。
            - swoole_http_request->$server;
                1. Http请求相关的服务器信息，相当于PHP的$_SERVER数组。包含了Http请求的方法，URL路径，客户端IP等信息。
                    ```
                        echo $request->server['request_time'];
                    ```
                2. 数组的key全部为小写，并且与PHP的$_SERVER数组保持一致
                3. request_time是在Worker设置的，在SWOOLE_PROCESS模式下存在dispatch过程，因此可能会与实际收包时间存在偏差。尤其是当请求量超过服务器处理能力时，request_time可能远滞后于实际收包时间。
                可以通过$server->getClientInfo方法获取last_time获得准确的收包时间。
            - swoole_http_request->$get;
                1. Http请求的GET参数，相当于PHP中的$_GET，格式为数组。
                2. 为防止HASH攻击，GET参数最大不允许超过 128 个
            - swoole_http_request->$post;
                1. HTTP POST参数，格式为数组。
                2. POST与Header加起来的尺寸不得超过package_max_length的设置，否则会认为是恶意请求;
                3. POST参数的个数最大不超过128个
            - swoole_http_request->$cookie
                1. HTTP请求携带的COOKIE信息，与PHP的$_COOKIE相同，格式为数组。
            - swoole_http_request->$files
                1. 文件上传信息。类型为以form名称为key的二维数组。与PHP的$_FILES相同。最大文件尺寸不得超过package_max_length设置的值。请勿使用Swoole\Http\Server处理大文件上传。
                    ```
                        Array
                        (
                            [name] => facepalm.jpg, // name 浏览器上传时传入的文件名称
                            [type] => image/jpeg,   // type MIME类型
                            [tmp_name] => /tmp/swoole.upfile.n3FmFr,    // tmp_name 上传的临时文件，文件名以/tmp/swoole.upfile开头
                            [error] => 0
                            [size] => 15476,    // size 文件尺寸
                        );
                    ```
                2. 1.9.10以上版本支持 is_uploaded_file 和 move_uploaded_file 函数
                3. 当$request对象销毁时，会自动删除上传的临时文件
            - string swoole_http_request->rawContent();
                1. 获取原始的POST包体，用于非 application/x-www-form-urlencoded 格式的Http POST请求。
                2. 返回原始POST数据，此函数等同于PHP的 fopen('php://input')
                3. 有些情况下服务器不需要解析Http POST请求参数，1.7.18以上版本增加了http_parse_post 配置，可以关闭POST数据解析。
            - function swoole_http_request->getData() : string
                1. 获取完整的原始Http请求报文。包括Http Header和Http Body
                2. 需要1.10.3/2.1.2或更高版本
        5. 例:
            ```
                // Http请求的头部信息。类型为数组，所有key均为小写。
                echo $request->header['host'];
                echo $request->header['accept-language'];
                echo $request->cookie['username'];
                // 如：index.php?hello=123
                echo $request->get['hello'];
                // 获取所有GET参数
                var_dump($request->get);
            ```
    - swoole_http_response
        1. Http响应对象，通过调用此对象的方法，实现Http响应发送。
        2. 当Response对象销毁时，如果未调用end发送Http响应，底层会自动执行end
        3. 请勿使用&符号引用$response对象
        4. response 对象属性;
            - function swoole_http_response->header(string $key, string $value, bool $ucwords = true);
                1. 设置HTTP响应的Header信息。
                2. $key，Http头的Key
                3. $value，Http头的Value
                4. $ucwords 是否需要对Key进行Http约定格式化，默认true会自动格式化
                5. 返回值; 设置失败，返回false; 设置成功，没有任何返回值
                6. 注意事项
                    - header设置必须在end方法之前
                    - $key必须完全符合Http的约定，每个单词首字母大写，不得包含中文，下划线或者其他特殊字符
                    - $value必须填写
                    - $ucwords 设为true，swoole底层会自动对$key进行约定格式化
                    - Swoole底层不允许设置相同$key的Http头
            - swoole_http_response->cookie(string $key, string $value = '', int $expire = 0 , string $path = '/', string $domain  = '', bool $secure = false , bool $httponly = false);
                1. 设置HTTP响应的cookie信息。此方法参数与PHP的setcookie完全一致。
                2. cookie设置必须在end方法之前
                3. 注意事项
                    - 底层自动会对$value进行urlencode编码，可使用rawCookie关闭对$value的编码处理
                    - 例:
                        ```
                            $response->rawcookie(
                                $cookie->getName(),
                                $cookie->getValue(),
                                $cookie->getExpiresTime(),
                                $cookie->getPath(),
                                $cookie->getDomain(),
                                $cookie->isSecure(),
                                $cookie->isHttpOnly()
                            );
                        ```
                    - 底层允许设置多个相同$key的COOKIE
            - swoole_http_response->status(int $http_status_code);
                1. 发送Http状态码。
                2. $http_status_code必须为合法的HttpCode，如200， 502， 301, 404等，否则会报错
                3. 必须在$response->end之前执行status
            - swoole_http_response->gzip(int $level = 1);
                1. 启用Http GZIP压缩。压缩可以减小HTML内容的尺寸，有效节省网络带宽，提高响应时间。必须在write/end发送内容之前执行gzip，否则会抛出错误。
                2. $level 压缩等级，范围是1-9，等级越高压缩后的尺寸越小，但CPU消耗更多。默认为1
                3. 调用gzip方法后，底层会自动添加Http编码头，PHP代码中不应当再行设置相关Http头
                4. gzip压缩在1.7.14以上版本可用
                5. jpg/png/gif格式的图片已经经过压缩，无需再次压缩
                6. gzip功能依赖zlib库，在编译swoole时底层会检测系统是否存在zlib，如果不存在，gzip方法将不可用。可以使用yum或apt-get安装zlib库：
                    ```
                        sudo apt-get install libz-dev
                    ```
            - function swoole_http_response->redirect(string $url, int $http_code = 302);
                1. 发送Http跳转。调用此方法会自动end发送并结束响应。
                2. $url：跳转的新地址，作为Location头进行发送
                3. $http_code：状态码，默认为302临时跳转，传入301表示永久跳转
                4. 需要2.2.0或更高版本
                5. 实例
                    ```
                        $http = new swoole_http_server("0.0.0.0", 9501, SWOOLE_BASE);
                        $http->on('request', function ($req, Swoole\Http\Response $resp) {
                            $resp->redirect("http://www.baidu.com/", 301);
                        });
                        $http->start();
                    ```
            - bool swoole_http_response->write(string $data);
                1. 启用Http Chunk分段向浏览器发送相应内容。关于Http Chunk可以参考Http协议标准文档。
                2. $data要发送的数据内容，最大长度不得超过2M
                3. 使用write分段发送数据后，end方法将不接受任何参数, 调用end方法后会发送一个长度为0的Chunk表示数据传输完毕
            - function swoole_http_response->sendfile(string $filename, int $offset = 0, int $length = 0);
                1. 发送文件到浏览器。
                2. $filename 要发送的文件名称，文件不存在或没有访问权限sendfile会失败
                3. $offset 上传文件的偏移量，可以指定从文件的中间部分开始传输数据。此特性可用于支持断点续传。
                4. $length 发送数据的尺寸，默认为整个文件的尺寸
                5. $length、$offset参数在1.9.11或更高版本可用
                6. 底层无法推断要发送文件的MIME格式因此需要应用代码指定Content-Type
                7. 调用sendfile前不得使用write方法发送Http-Chunk
                8. 调用sendfile后底层会自动执行end
                9. sendfile不支持gzip压缩
                10. 使用示例
                    ```
                        $response->header('Content-Type', 'image/jpeg');
                        $response->sendfile(__DIR__.$request->server['request_uri']);
                    ```
            - swoole_http_response->end(string $html);
                1. 发送Http响应体，并结束请求处理。
                2. end操作后将向客户端浏览器发送HTML内容
                3. end只能调用一次，如果需要分多次向客户端发送数据，请使用write方法
                4. 客户端开启了KeepAlive，连接将会保持，服务器会等待下一次请求
                5. 客户端未开启KeepAlive，服务器将会切断连接
            - function swoole_http_response->detach();
                1. 分离响应对象。使用此方法后，$response对象销毁时不会自动end，与swoole_http_response::create和Server::send配合使用。
                2. 客户端已完成响应，操作失败返回false，成功返回true
                3. 需要2.2.0或更高版本
                4. 跨进程响应; 某些情况下，需要在Task进程中对客户端发出响应。这时可以利用detach使$response对象独立。在Task进程可以重新构建$response，发起Http请求响应。
                5. 例:
                    ```
                        $http = new swoole_http_server("0.0.0.0", 9501);
                        $http->set(['task_worker_num' => 1, 'worker_num' => 1]);
                        $http->on('request', function ($req, Swoole\Http\Response $resp) use ($http) {
                            $resp->detach();
                            $http->task(strval($resp->fd));
                        });
                        $http->on('finish', function ()
                        {
                            echo "task finish";
                        });
                        $http->on('task', function ($serv, $task_id, $worker_id, $data)
                        {
                            var_dump($data);
                            $resp = Swoole\Http\Response::create($data);
                            $resp->end("in task");
                            echo "async task\n";
                        });
                        $http->start();
                    ```
                6. 发送任意内容; 某些特殊的场景下，需要对客户端发送特殊的响应内容。Http\Response对象自带的end方法无法满足需求，可以使用detach分离响应对象，然后自行组包并使用Server::send发送数据。例:
                    ```
                        $http = new swoole_http_server("0.0.0.0", 9501);
                        $http->on('request', function ($req, Swoole\Http\Response $resp) use ($http) {
                            $resp->detach();
                            $http->send($resp->fd, "HTTP/1.1 200 OK\r\nServer: server\r\n\r\nHello World\n");
                        });
                        $http->start();
                    ```

            - function swoole_http_response::create(int $fd) : swoole_http_response;
                1. 构造新的Http\Response对象。使用此方法前请务必调用detach方法将旧的$response对象分离，否则可能会造成对同一个请求发送两次响应内容。
                2. 参数为需要绑定的连接$fd，调用Http\Response对象的end与write方法时会向此连接发送数据
                3. 调用成功返回一个新的Http\Response对象，调用失败返回false
                4. 需要2.2.0或更高版本
                    ```
                        $http = new swoole_http_server("0.0.0.0", 9501);
                        $http->on('request', function ($req, Swoole\Http\Response $resp) use ($http) {
                            $resp->detach();
                            $resp2 = Swoole\Http\Response::create($data);
                            $resp2->end("hello world");
                        });
                        $http->start();
                    ```

    - 配置选项: Http\Server除了可以设置Server相关选项外，还可以设置一些特有的选项。
        1. upload_tmp_dir
            ```
                // 设置上传文件的临时目录。
                $serv->set(array(
                    'upload_tmp_dir' => '/data/uploadfiles/',
                ));
            ```
        2. http_parse_post
            ```
                // 设置POST消息解析开关，选项为true时自动将Content-Type为x-www-form-urlencoded的请求包体解析到POST数组。设置为false时将关闭POST解析。
                $serv->set(array(
                    'http_parse_post' => false,
                ));
            ```
        3. document_root
            ```
                // 配置静态文件根目录，与enable_static_handler配合使用。

                $server->set([
                    'document_root' => '/data/webroot/example.com',
                    'enable_static_handler' => true,
                ]);

                // 设置document_root并设置enable_static_handler为true后，底层收到Http请求会先判断document_root路径下是否存在此文件，如果存在会直接发送文件内容给客户端，不再触发onRequest回调。

                // 在1.9.17或更高版本可用
                // 使用静态文件处理特性时，应当将动态PHP代码和静态文件进行隔离，静态文件存放到特定的目录
            ```
    - 文件上传: Http\Server支持文件上传，但由于Swoole底层的限制，文件内容是存放在内存中的，因此如果并发上传大量文件可能会导致内存占用过大。
    - POST 尺寸: 默认上传2M尺寸的文件或POST 2M数据，可修改package_max_length调整最大POST尺寸限制。





## 问题
 1. sleep 问题; 不要在代码中执行sleep以及其他睡眠函数，这样会导致整个进程阻塞;
    - 如果确实要用到 sleep() 的时候怎么办 ?
 2. exit/die是危险的，会导致Worker进程退出
    - 如果要终止本次事件怎么做 ?
 3. 可通过register_shutdown_function来捕获致命错误，在进程异常退出时做一些清理工作，具体参考 /wiki/page/305.html
 4. 对于抛异常的 throw new \Exception('消息内容格式错误！'); 这种主动抛异常 造成的影响有哪些 ? 如何控制与避免 ?
    - PHP代码中如果有异常抛出，必须在回调函数中进行try/catch捕获异常，否则会导致工作进程退出
 5. 不支持set_exception_handler，必须使用try/catch方式处理异常
 6. 关于使用进程池做消费者, while(true) 的时候, mysql 和 redis 的链接释放问题, 好像mysql和redis链接状态, 并没有释放, 这样会有问题吗

## 注意
 1. Worker进程不得共用同一个Redis或MySQL等网络服务客户端，Redis/MySQL创建连接的相关代码可以放到onWorkerStart回调函数中，具体参考 /wiki/page/325.html
 2. 类/函数重复定义
    - 新手非常容易犯这个错误，由于Swoole是常驻内存的，所以加载类/函数定义的文件后不会释放。因此引入类/函数的php文件时必须要使用include_once或require_once，否会发生cannot redeclare function/class 的致命错误。
 3. 进程隔离
    - 进程隔离也是很多新手经常遇到的问题。修改了全局变量的值，为什么不生效，原因就是全局变量在不同的进程，内存空间是隔离的，所以无效。所以使用Swoole开发Server程序需要了解进程隔离问题。
    - 不同的进程中PHP变量不是共享，即使是全局变量，在A进程内修改了它的值，在B进程内是无效的
    - 如果需要在不同的Worker进程内共享数据，可以用Redis、MySQL、文件、Swoole\Table、APCu、shmget等工具实现
    - 不同进程的文件句柄是隔离的，所以在A进程创建的Socket连接或打开的文件，在B进程内是无效，即使是将它的fd发送到B进程也是不可用的
 4. 异步编程
    - 异步程序要求代码中不得包含任何同步阻塞操作
    - 异步与同步代码不能混用，一旦应用程序使用了任何同步阻塞的代码，程序即退化为同步模式


