
##全局Apache 或nginx伪静态配置
    > 1. Apache
    >   ```
    >   Options +FollowSymLinks
    >   RewriteEngine On
    >   RewriteCond %{REQUEST_FILENAME} !-d
    >   RewriteCond %{REQUEST_FILENAME} !-f
    >   RewriteRule ^ index.php [L]
    >   ```
    >
    > 2. Nginx
    >   ```
    >   location / {
    >       try_files $uri $uri/ /index.php?$query_string;
    >   }
    >   ```
    > 或 - 最好用上一种, 下面那个有bug
    >   ```
    >   location / {
    >       try_files $uri $uri/ /index.php/$query_string;
    >   }
    >   ```

##配置文件目录
    > /config

##路由配置
    > 文件: /app/Http/routes.php
    > 主要使用: Route::get/post/patch/put/delete/match/any/

##控制器
    > 目录: /app/Http/Controller
    > 继承基础框架控制器: App\Http\Controllers\Controller
    > 主要使用: 
    >   1. 返回视图 return view::();
    >   2. 输出打印 dd() . PS: 这里输出打印后会die掉程序
    >   3. view 默认会先找 *.blade.php, 然后再找 *.php

##视图
    1. view视图目录在: \resources\views 目录下
    2. 控制器中使用 return view(path.file) 或 view(file)
    3. 控制器给视图传参方式:
        ```
        return view('test.dbtest')->with('users', $users)->with('allUser', $allUser);
        // 或者
        return view('test.dbtest', ['users'=>$users, 'allUser'=>$allUser]);
        ```

##中间件
    > 中间件APP注册: /app/Http/Kernel.php
    > 在注册文件 /app/Http/Kernel.php 数组中 protected $routeMiddleware 增加 name=>path 中间件
    > 中间件文件目录: /app/Http/Middleware
    > 主要使用与注意: 
    >   1. namespace App\Http\Middleware;
    >   2. use Closure;
    >   3. 创建中间件运行方法 public function handle($request, Closure $next)
    >   4. $response = $next($request); 这里获得的是上一层中间件或者controller 中的return response 数据
    >   4. 最后一定要返回 $response 给到下一级处理
    >   5. PS注意: 中间件的 __construct 的执行顺序优先于 handle, 在中间件handle执行前, 先执行所有中间件的 __construct 
    >   6. 中间件示例: 
    >       ```
    >           Route::any('/test.any', ['as'=>'any_name', 'middleware' => ['preaction', 'nextaction'], 'uses'=>'Test\TestController@anyroute']);
    >       最外层 ob 包裹层级 preaction 在ob最外面, 其次是 nextaction 的ob, 再其次是 controller 中的ob. 
    >       返回与ob输出层级:
    >           1. controller 中 return view 作为输出到中间件的response;
    >           2. nextaction 中的ob 获取controlelr中的return到ob区 主要体现是:$response = $next($request); 因此可以中间件要执行的代码放到 $response 前, 就会在controller前执行, 代码放到 $response 后, 就会在 controller 后执行. 最后要返回 $response 对象 供外层 中间件preaction使用和执行
    >           3. preaction 中的ob 获取 nextaction 的 $response 对象到ob区 主要体现是:$response = $next($request); 因此可以中间件要执行的代码放到 $response 前, 就会在 nextaction 前执行, 代码放到 $response 后, 就会在 nextaction 后执行. 最后要返回 $response 对象 供外层 最后的系统输出与执行


##Request 请求
    1. use Illuminate\Http\Request;
    2. Illuminate\Http\Request 与 PSR-7 Requests 规范类似
    3. Controller 中方法可传入$request参数 public function getroute(Request $request)
    4. 可查看 Illuminate\Http\Request 可使用的方法
    5. 一些常用方法: $request->header(); $request->cookie(); $request->ajax(); $request->input() 等
    6. request() 全局方法 基本可以看作 Illuminate\Http\Request 的实例变量
    7. 如果要获取所有Args(路由中的GET配置参数): 即路由中自定义的所有参数, 要在controller方法中加入该参数变量, 还可以使用 $request->url() 或 $request->path() 拿到所有url路径然后自己分割获取
    先用方式如下:
    ```
    Route::put('user/{id}', 'UserController@update');

    <?php

    namespace App\Http\Controllers;

    use Illuminate\Http\Request;
    use Illuminate\Routing\Controller;

    class UserController extends Controller
    {
        public function update(Request $request, $id)
        {
            // 获取 Route 中的变量 id
            print_r($id);
        }
    }
    ```

##Response 响应
    1. use Illuminate\Http\Response
    2. Illuminate\Http\Response 继承自 Symfony\Component\HttpFoundation\Response[PS:文件路径: \vendor\symfony\http-foundation\Response.php ]
    2. 返回的都是 Response 的类实例, 或者 一个view视图
    3. response() 基本可以看作是 Illuminate\Http\Response 的实例变量
    4. 返回示例:
    ```
        // response() 在 vendor\laravel\framework\src\Illuminate\Foundation\helpers.php
        return response($content, $httpStatusCode, array-headers);

        或 结合Symfony\Component\HttpFoundation\Response基类的方法进行返回[ 最后一次setContent 会将前一次的content覆盖掉, 即本次页面只会输出"finn" ; header 可以叠加输出 ]
        return response('heheheh')->setStatusCode(200)->setContent('wowowow')->setContent('finn')->header('ax-cont', 'wowode')->header('axing-satus', 'zheges');

        与视图结合 并 自定义header
        return response()->view('hello', $data)->header('Content-Type', $type);

        直接返回JSON json() 方法在 Routing\ResponseFactory.php
        return response()->json(['name' => 'Abigail', 'state' => 'CA']);

        返回 jsonp
        return response()->jsonp('mycallbac', ['name' => 'Abigail', 'state' => 'CA']);

        直接返回视图
        return view('dirpath.file');
    ```



##Models 模型与数据库
    1. 使用 php artisan make:model Models/Activity 可生成 App\Models\Activity.php 模型文件, 文件初始格式为:
    ```
        <?php
        namespace App\Models;
        use Illuminate\Database\Eloquent\Model;
        class Activity extends Model
        {
            //
        }
    ```
    2. 也可以自己直接复制或写Model, 所有Model都继承自 Illuminate\Database\Eloquent\Model; 基类 也可以自己定义BaseModel基类继承Model 然后其他模型继承BaseModel
    3. 每个模型要固定自己设置两个类属性
        ```
        // tableName
        protected $table = 'my_table_name';
        // 主键字段
        protected $primaryKey = 'carid';
        
        // Eloquent期望created_at和updated_at已经存在于数据表中，如果你不想要这些Laravel自动管理的列，在模型类中设置$timestamps属性为false
        public $timestamps = false;
        
        // dateFormat 设置日期列存储格式 - 这个可以选择性设置或忽略
        protected $dateFormat = 'U';
        ```

    4. 多表JOIN关联
        ```

    5. 增删改查[http://laravelacademy.org/post/8834.html]
        1. 增
            ```
            DB::

            $id = DB::table('user_info')->insertGetId(
                ['name' => 'axing', 'id_card'=>time(), 'email' => 'test']
            );

    6. mysql 操作日志
        同时使用多个数据库系统
        $users = DB::connection('foo')->select(...);
        $pdo = DB::connection()->getPdo();
        DB::reconnect('foo');
        在项目最前面使用 这个方法 开启mysql log 记录功能
            DB::connection()->enableQueryLog();

        Laravel默认会为当前请求执行的的所有查询生成日志并保存在内存中( 5.1好像并没有默认开启, 因此要在项目开始前增加 DB::connection()->enableQueryLog(); 启动此功能  )。 因此， 在某些特殊的情况下， 比如一次性向数据库中插入大量数据， 就可能导致内存不足。 在这种情况下，你可以通过 disableQueryLog 方法来关闭查询日志:
            DB::connection()->disableQueryLog();
        
        调用 getQueryLog 方法可以同时获取多个查询执行后的日志:
        ```
            // 开启sql记录功能
            DB::connection()->enableQueryLog();
            ...
            select/insert/update -- 等sql语句
            ...

            // 获取所有sql
            $queries = DB::getQueryLog();
        ```



##debug调试信息
    1. (页面显示debug 与debug常用配置) 配置 \config\app.php 中
        ```
        'debug' => env('APP_DEBUG', true),
        // providers 增加 Barryvdh\Debugbar\ServiceProvider::class,
        'providers' => [
            Barryvdh\Debugbar\ServiceProvider::class,
            Illuminate\Html\HtmlServiceProvider::class,
            Elibyy\TCPDF\ServiceProvider::class,
            //Jenssegers\Agent\AgentServiceProvider::class,
            // Jenssegers\Mongodb\MongodbServiceProvider::class,
            // Elasticquent\ElasticquentServiceProvider::class,
        ],

        // aliases 增加 'Debugbar'  => Barryvdh\Debugbar\Facade::class,
        'aliases' => [
            'Debugbar'  => Barryvdh\Debugbar\Facade::class,
            'Form'      => Illuminate\Html\FormFacade::class,
            'Es' => Elasticquent\ElasticquentElasticsearchFacade::class,
        ],
        ```

    2. 获取debuger信息


    3. 添加自定义debuger信息
        ```
        use Debugbar;
        Debugbar::info('something');
        Debugbar::error('Error!');
        Debugbar::warning('Watch out…');
        Debugbar::addMessage('Another message', 'mylabel');
        ```

    PS: 详细信息见 (Laravel 调试利器 —— Laravel Debugbar 扩展包安装及使用教程)[http://laravelacademy.org/post/2774.html]



##日志









##


待检测问题: $request->input(); $request->all(); 获取的什么信息
$request 获取 get post request 等参数 获取$_SERVER信息


response callback 问题
return response()->json(['name' => 'Abigail', 'state' => 'CA'])
                 ->setCallback($request->input('callback'));
