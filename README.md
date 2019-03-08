# Snell Server

对snell协议版本1.0的初步逆向

# Overview

## Encryption Schema

Schema 同 shadowsocks aead 模式，分组密码选用了 chacha20-poly1305-ietf，详见[Aead Schema](http://shadowsocks.org/en/spec/AEAD-Ciphers.html)

会话密钥生成方式为

```
crypto_pwhash(__out key, 32, psk, psk_len, salt, 3ULL, 0x2000ULL, crypto_pwhash_ALG_ARGON2ID13);
```
参数意义详见[libsodium documentation](https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function#key-derivation)

## The Snell Protocol

### C to S

```
[1-byte version][1-byte command][1-byte client_id length][variable-length client_id][1-byte host length][variable-length host][2-byte port][application data...]
```

其中

```

version:    0x01

command:
    0x00:   PING
    0x01:   CONNECT

client_id length: zero currently (maybe reserved for multi-user)
```

* 本repo给出的demo没有实现obfs功能

* host总是字符串格式的，即使是ip地址

* port为网络字节序

### S to C

```
[1-byte command][content...]
```

其中

```
command:
    0x00:   TUNNEL
    0x02:   ERROR
```

当command=0x00时，content即是应用层数据，正常建立隧道将远端数据原封不动传递

当command=0x02时，content具有如下模式

```
[1-byte error code][1-byte error msg length][variable-length error message]
```

## Obfuscating Algorithm

### HTTP

目前的http就是[simple-obfs](https://github.com/shadowsocks/simple-obfs)的http mode，不想实现demo了，但可作如下验证

```
./snell-server -c ./snell-server.conf &

obfs-server -s 0.0.0.0 -p 8787 -r 127.0.0.1:9898 --obfs=http
```

假定snell-server.conf内容如下：

```
$ cat ./snell-server.conf
[snell-server]
listen = 0.0.0.0:9898
psk = zzz
```

现在surge中添加代理```test_snell = snell, [SERVER ADDRESS], 8787, psk=zzz, obfs=http```可成功访问网络

### TLS

TLS也就是[simple-obfs](https://github.com/shadowsocks/simple-obfs)的tls mode，验证方式同上

# Build Demo

## macOS

```
brew update && brew install boost libsodium glog gflags cmake

# clone and cd into the repo

mkdir build && cd build
cmake .. && make
```

## debian

```
apt update && apt install build-essential libboost-dev libsodium-dev libgoogle-glog-dev libgflags-dev cmake

# clone and cd into the repo

mkdir build && cd build
cmake .. && make
```

