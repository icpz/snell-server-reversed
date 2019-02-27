#ifndef __SNELL_CHACHA20POLY1305IETF_HXX__
#define __SNELL_CHACHA20POLY1305IETF_HXX__

#include "cipher.hxx"

class Chacha20Poly1305IetfCipher : public Cipher {
public:
    virtual ~Chacha20Poly1305IetfCipher();

    int Encrypt(uint8_t *c, size_t *clen, const uint8_t *ptext, size_t plen, const uint8_t *nonce, const uint8_t *key) const;
    int Decrypt(uint8_t *p, size_t *plen, const uint8_t *ctext, size_t clen, const uint8_t *nonce, const uint8_t *key) const;
};

#endif // __SNELL_CHACHA20POLY1305IETF_HXX__

