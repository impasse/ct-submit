ct-submit

*一个用于获取Certificate Transparency时间戳的小工具*
>未在python3上测试，建议使用python2执行

## 使用

内置了几个ct服务器，请酌情增减(部分服务器可能需要你的网络**特别**)

```
python2 ct-submit pem.crt #获得的时间戳(*.sct)会保存在当前目录

---

python2 ct-submit pem.sct -z #获得的时间戳会压缩成一个zip文件储存在当前目录
```

## Certificate Transparency的配置

参考[nginx-ct](https://github.com/grahamedgecombe/nginx-ct)和[mod_ssl_ct](https://httpd.apache.org/docs/trunk/mod/mod_ssl_ct.html)