#ifndef __SNELL_CIPHER_HXX__
#define __SNELL_CIPHER_HXX__

#include <stdint.h>

class Cipher {
public:
    virtual ~Cipher() { }

    virtual int Encrypt(uint8_t *ctext, size_t *clen, const uint8_t *ptext, size_t plen, const uint8_t *nonce, const uint8_t *key) const = 0;
    virtual int Decrypt(uint8_t *ptext, size_t *plen, const uint8_t *ctext, size_t clen, const uint8_t *nonce, const uint8_t *key) const = 0;

    virtual size_t SaltSize() const { return 16U; }
    virtual size_t KeySize() const { return 32U; }
    virtual size_t NonceSize() const { return 12U; }
};

#endif // __SNELL_CIPHER_HXX__

