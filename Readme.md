# openssl windows 编译安装与使用
参考链接：https://github.com/openssl/openssl/blob/master/NOTES.WIN
## 1. 编译安装
我采用的是VC编译安装，其他方式请参考上面链接。  
### 1.1 安装编译环境
下载并安装 [visual studio 2019 community](https://visualstudio.microsoft.com/)  
下载并安装 [Perl](https://www.activestate.com/products/perl/downloads/)  
安装完好后命令行执行【perl -v】就可以查看版本信息  
下载并安装 [nasm](https://www.nasm.us)  
下载 [openssl源码](https://www.openssl.org/source/)  
### 1.2 编译
这里需要根据自己的环境进行配置，64位操作系统，所以选择 `VC-WIN64A`  
从开始菜单打开 `x64 Native Tools Command Prompt`，并输入一下命令。
```shell
$ perl Configure VC-WIN64A
$ nmake
$ nmake test
```
结果报错提示说缺少Win32::Console模块。  
然后我就卸载了perl，然后在官网fork的项目中添加上这个包，重新安装。
## 2. 使用
### 0. visual studio 配置
1. 在`解决方案资源管理器`中右键点击当前项目-`属性`-`配置属性`-`C/C++`-`附加包含目录`，填上openssl的include目录的路径。
2. `链接器`-`常规`-`附加库目录` 值：openssl的lib目录路径
3. `链接器`-`输入`-`附加依赖项` 值：libeay32.lib  
编译时提示找不到某个dll：  
方法1：将dll文件拷贝到生成的.exe所在的文件夹中  
方法2：配置属性->调试->工作目录：包含dll文件的文件夹路径  
### 1. 用MD5生成一个消息（字符串）的消息摘要
```c++
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    char mess[] = "Test Message\n";
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;


    md = EVP_get_digestbyname("md5");

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, mess, strlen(mess));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    printf("Digest is: ");
    for (i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");
```
### 2. 生成RSA密钥对，并用私钥对消息摘要进行签名
```c++
    /*Generate 2048 bit RSA key */
    EVP_PKEY_CTX* pctx;
    EVP_PKEY* pkey = NULL;
    ENGINE *e = ENGINE_by_id("ACME");
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, e);
    if (!pctx)
        /* Error occurred */
        exit(-1);
    if (EVP_PKEY_keygen_init(pctx) <= 0)
        /* Error */
        exit(-1);
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0)
        /* Error */
        exit(-1);
        /* Generate key */
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
        /* Error */
        exit(-1);

    /* Sign */
    unsigned char sigret[SIG_ATOMIC_MAX];
    size_t sig_len;
    EVP_MD_CTX_set_pkey_ctx(mdctx, pctx);
    EVP_DigestSignInit(mdctx, &pctx, md, e, pkey);
    EVP_DigestSignUpdate(mdctx, md_value, md_len);
    EVP_DigestSignFinal(mdctx,sigret,&sig_len);
```

### 3. 把生成的签名转换成BASE64编码
```c++
    /* BASE64 */
    BIO* bio, * b64;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_push(b64, bio);
    BIO_write(b64, sigret, sig_len);
    BIO_flush(b64);

    BIO_free_all(b64);
```