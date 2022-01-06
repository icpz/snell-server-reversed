# Snell Server

对 snell 协议版本 v3.0 RC 的逆向，旧版本详见 [v2](README.v2.md)， [v1](README.v1.md)

开源实现可参考 [open-snell](https://github.com/icpz/open-snell) 和 [clash](https://github.com/Dreamacro/clash)

# Overview

## Encryption Schema

Schema 同 shadowsocks aead 模式，分组密码选用了 chacha20-poly1305-ietf，详见 [Aead Schema](http://shadowsocks.org/en/spec/AEAD-Ciphers.html)

会话密钥生成方式为

```
crypto_pwhash(__out key, 32, psk, psk_len, salt, 3ULL, 0x2000ULL, crypto_pwhash_ALG_ARGON2ID13);
```
参数意义详见 [libsodium documentation](https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function#key-derivation)

## The Snell Protocol for UDP Session

** Snell v3.0 TCP 连接协议与 v1 相同，详见 [v1](README.v1.md) **

后文主要表述 v3.0 新增的 UDP 转发模式

### Definitions

```
[udp-req-hdr] := [0x01][0x06][1-byte client_id length][variable-length client_id]

[udp-pkt] := [remote-addr][2-byte port][application data...]

[udp-resp] := [ip-addr][2-byte port][application data...]

[remote-addr] := [domain-addr] | [0x00][ip-addr]

[domain-addr] := [1-byte length][variable-length domain]

[ip-addr] := [ip4-addr] | [ip6-addr]

[ip4-addr] := [0x04][4-byte ipv4]

[ip6-addr] := [0x06][16-byte ipv6]
```

其中

```
client_id length: length of client_id
client_id: arbitrary string including empty string

remote-addr: new target address format, either [domain-addr] or [ip*-addr]

domain-addr: first byte is the length of domain (must NOT be zero)

ip4-addr: ipv4 is in network order binary data

ip6-addr: ipv6 is in network order binary data

port: network order port
```

### C to S

```
[udp-req-hdr][0x01][udp-pkt][0x01][udp-pkt][0x01][udp-pkt]...
```

### S to C

```
[1-byte command][content 0][content 1]....
```

其中

```
command:
    0x00:   READY
    0x02:   ERROR
```

当 command=0x00 时，表明服务端可以进行 UDP 转发，此时 content 具有如下模式

```
[udp-resp][udp-resp]....
```

当 command=0x02 时，content 具有如下模式

```
[1-byte error code][1-byte error msg length][variable-length error message]
```

### Example Stream

```

C->S : [udp-req-hdr]   [0x01][udp-pkt]      [0x01][udp-pkt]    [0x01][udp-pkt]                        [0x01][udp-pkt] ...
S->C :              [0x00]             [udp-resp]                               [udp-resp]           [udp-resp]          ...

```

注意，表示 `S->C` 方向中 `[udp-resp]` 中的目标地址仅支持 `[ip4-addr][port]` 或 `[ip6-addr][port]` 格式，内容为原始 target 的地址。
每个 udp packet 长度可由一次 chunk decrypt 的长度计算

## Obfuscating Algorithm

同 [v1](README.v1.md)

# Contact

欢迎大家交流讨论，如果有问题欢迎在 issue 区提出，或 Email [y@icpz.dev](mailto:y@icpz.dev)。

