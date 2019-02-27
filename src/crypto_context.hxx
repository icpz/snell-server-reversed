#ifndef __SNELL_CRYPTO_CONTEXT_HXX__
#define __SNELL_CRYPTO_CONTEXT_HXX__

#include <stdint.h>
#include <vector>
#include <string>
#include <memory>

#include "cipher.hxx"

class CryptoContext {
public:
    enum { OK, ERROR = -1 };
    enum { UNINITIALIZED, ENCRYPT, DECRYPT };

    CryptoContext(std::shared_ptr<Cipher> cipher, std::shared_ptr<std::string> psk);
    ~CryptoContext();

    int EncryptSome(std::vector<uint8_t> &ctext, const uint8_t *ptext, size_t plen);
    int DecryptSome(std::vector<uint8_t> &ptext, const uint8_t *ctext, size_t clen);

private:

    void DeriveKey(const uint8_t *salt);

    uint32_t state_;
    std::shared_ptr<Cipher> cipher_;
    std::shared_ptr<std::string> psk_;
    std::vector<uint8_t> key_;
    std::vector<uint8_t> nonce_;
    std::vector<uint8_t> buffer_;
};

#endif // __SNELL_CRYPTO_CONTEXT_HXX__

