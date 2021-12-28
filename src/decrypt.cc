
// g++ -o decrypt -std=c++14 decrypt.cc -I/opt/homebrew/include /opt/homebrew/lib/libsodium.a /opt/homebrew/lib/libmbedcrypto.a

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iterator>
#include <vector>
#include <algorithm>

#include <sodium.h>
#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>

template<class T>
inline void assert_eq(const T &a, const T &b) {
    if (a != b) {
        std::cerr << a << " not equal to " << b << std::endl;
        abort();
    }
}

char psk[] = "kkk";

static int aes_decrypt_chunk(
    uint8_t *m, uint64_t *mlen, uint8_t *nsec,
    const uint8_t *c, uint64_t clen,
    const uint8_t *ad, uint64_t adlen,
    const uint8_t *n, const uint8_t *k) {

    mbedtls_cipher_context_t ctx{};
    mbedtls_cipher_init(&ctx);
    assert_eq(mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM)), 0);
    assert_eq(mbedtls_cipher_setkey(&ctx, k, 16 * 8, MBEDTLS_DECRYPT), 0);
    size_t olen = 0;
    assert_eq(mbedtls_cipher_auth_decrypt_ext(&ctx, n, 12, ad, adlen, c, clen, m, clen - 16, &olen, 16), 0);
    *mlen = olen;
    mbedtls_cipher_free(&ctx);

    return 0;
}

struct crypto_context {
    uint8_t nonce[12];
    uint8_t key[32];
    int initialized;

    crypto_context() {
        std::fill(std::begin(nonce), std::end(nonce), 0);
        std::fill(std::begin(key), std::end(key), 0);
        initialized = 0;
    }

    void genkey(uint8_t *salt) {
        assert_eq(crypto_pwhash(key, 32, psk, strlen(psk), salt, 3ULL, 0x2000ULL, crypto_pwhash_ALG_ARGON2ID13), 0);
        initialized = 1;
    }

    int decrypt_chunk(const uint8_t *ctext, size_t ccapacity, uint8_t *mtext, size_t *mlen) {
        if (!initialized) { return -1; }

        uint16_t len;
        unsigned long long llen;
        int ret;
        ret = aes_decrypt_chunk((uint8_t *)&len, &llen, nullptr, ctext, 2 + 16, nullptr, 0, nonce, key);
        if (ret < 0) {
            return ret;
        }
        assert_eq(ret, 0);
        assert_eq(llen, 2ULL);
        ctext += 2 + 16;
        sodium_increment(nonce, sizeof nonce);
        len = ntohs(len);
        fprintf(stderr, "chunk size %d\n", len);
        if (len == 0) {
            *mlen = 0;
            return ret;
        }
        ret = aes_decrypt_chunk(mtext, &llen, nullptr, ctext, len + 16, nullptr, 0, nonce, key);
        if (ret < 0) {
            return ret;
        }
        assert_eq(ret, 0);
        *mlen = llen;
        sodium_increment(nonce, sizeof nonce);
        return ret;
    }
};

int main(int argc, char *argv[]) {
    assert_eq(sodium_init(), 0);
    std::ifstream ifs{argv[1], std::ios::binary};
    assert(ifs.is_open());
    std::vector<uint8_t> ctext;
    {
        std::string content{
            std::istreambuf_iterator<char>{ifs},
            std::istreambuf_iterator<char>{}
        };
        std::copy(content.begin(), content.end(), std::back_inserter(ctext));
    }
    fprintf(stderr, "%lu bytes read\n", ctext.size());

    auto *chead = ctext.data();
    auto *ctail = chead + ctext.size();

    std::vector<uint8_t> ptext;

    crypto_context ctx;
    ctx.genkey(chead);
    chead += 16;
    while (chead != ctail) {
        uint8_t buf[65536];
        size_t mlen;
        int ret = ctx.decrypt_chunk(chead, ctail - chead, buf, &mlen);
        if (ret < 0) {
            fprintf(stderr, "decrypt chunk error: %d\n", ret);
            break;
        }
        assert_eq(ret, 0);
        std::copy_n(buf, mlen, std::back_inserter(ptext));
        chead += 2 + 16 + (mlen ? mlen + 16 : 0);
    }

    fprintf(stderr, "decrypt done, total ptext %lu bytes\n", ptext.size());
    for (auto c : ptext) {
        printf("%c", c);
    }
    puts("");

    return 0;
}

