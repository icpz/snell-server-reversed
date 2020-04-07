# Snell Server

对 snell 协议版本 v2.0b 的初步逆向，1.1 版本详见 [v1](README.v1.md)

~~注意，目前（2020年3月23日） snell 2.0 仍然在快速迭代中且本人较忙，因此本项目将暂缓逆向进程，等官方发布 v2.0 release 版本后再找时间逆向。谢谢大家。~~（已更新）

# Overview

## Encryption Schema

Schema 同 shadowsocks aead 模式，分组密码选用了 chacha20-poly1305-ietf，详见[Aead Schema](http://shadowsocks.org/en/spec/AEAD-Ciphers.html)

**注意**，shadowsocks aead 模式隐含了 chunk size 大于 0 的条件，因为解密一个 chunk nounce 需要递增两次。而 snell v2 则利用了这个 chunk size 等于 0 的情况，将其作为子序列连接的分割。

会话密钥生成方式为

```
crypto_pwhash(__out key, 32, psk, psk_len, salt, 3ULL, 0x2000ULL, crypto_pwhash_ALG_ARGON2ID13);
```
参数意义详见 [libsodium documentation](https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function#key-derivation)

## The Snell Protocol

### Definitions

```

[] := <zero-length chunk>, this will result in a single [[zero length][length tag]] block after encryption

[request-header] := [1-byte version][1-byte command][1-byte client_id length][variable-length client_id][1-byte host length][variable-length host][2-byte port]

[sub-conn-request] := [request-header][application data...][]

[sub-conn-reply] := [application data...][]
```

其中

```
version:    0x01       /* why not 0x02 ? */

command:
    0x00:   PING
    0x01:   CONNECT    /* for snell v1 */
    0x05:   CONNECTv2

client_id length: length of client_id
client_id: arbitrary string including empty string
```

* CONNECT 指令则表示这是一个 snell v1 的连接，详见 [v1](README.v1.md)

* ~~本 repo 尚未给出 v2.0b 版本的 demo~~ [open-snell](https://github.com/icpz/open-snell)

* host 总是字符串格式的，即使是 ip 地址

* port 为网络字节序

### C to S

```
[sub-connection-request 0][sub-connection-request 1]....
```

### S to C

```
[1-byte command][content 0][1-byte command][content 1]....
```

其中

```
command:
    0x00:   TUNNEL
    0x02:   ERROR
```

当 command=0x00 时，表明 snell 配置正常，服务端可以进行转发，content 具有如下模式

```
[sub-connection-reply]
```


当 command=0x02 时，content 具有如下模式

```
[1-byte error code][1-byte error msg length][variable-length error message]
```

### Example Stream

```

C->S : [request-header 0][app data]          [app data][]               [request-header 1][app data]          [app data][] ...
S->C :                   [0x00]    [app data]          [app data...][]                              [0x00][app data][]           ...

```

注意，表示 `TUNNEL` 成功的 0x00 每个子链接都需要发送。子链接以 `[]` 作为分割，可将其视为子链接的半关闭，即不再写入。当双方都半关闭时子链接彻底关闭，当超时无新连接请求到来则主连接关闭。

## Obfuscating Algorithm

同 [v1](README.v1.md)

# Contact

欢迎大家交流讨论，如果有问题欢迎在 issue 区提出，或 Email [cc@icpz.dev](mailto:cc@icpz.dev)。

