#include <sodium.h>

#include "chacha20_poly1305_ietf_cipher.hxx"

Chacha20Poly1305IetfCipher::~Chacha20Poly1305IetfCipher() {
}

int Chacha20Poly1305IetfCipher::Encrypt(
        uint8_t *c, size_t *clen, const uint8_t *ptext, size_t plen,
        const uint8_t *nonce, const uint8_t *key
    ) const {
        unsigned long long clenll;
        int ret = \
            crypto_aead_chacha20poly1305_ietf_encrypt(
                c, &clenll, ptext, plen,
                nullptr, 0, nullptr, nonce, key
            );
        if (ret == 0) {
            *clen = static_cast<size_t>(clenll);
        }
        return ret;
    }

int Chacha20Poly1305IetfCipher::Decrypt(
        uint8_t *p, size_t *plen, const uint8_t *ctext, size_t clen,
        const uint8_t *nonce, const uint8_t *key
    ) const {
        unsigned long long plenll;
        int ret = \
            crypto_aead_chacha20poly1305_ietf_decrypt(
                p, &plenll, nullptr, ctext, clen,
                nullptr, 0, nonce, key
            );
        if (ret == 0) {
            *plen = static_cast<size_t>(plenll);
        }
        return ret;
    }
