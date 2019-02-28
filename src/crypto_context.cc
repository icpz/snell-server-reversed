
#include <sodium.h>
#include <glog/logging.h>
#include <arpa/inet.h>
#include <assert.h>

#include "crypto_context.hxx"

const size_t CHUNK_MAX_SIZE = 0x3FFFU;

CryptoContext::CryptoContext(std::shared_ptr<Cipher> cipher, std::shared_ptr<std::string> psk)
    : cipher_(cipher), psk_(std::move(psk)),
      key_(cipher->KeySize()), nonce_(cipher->NonceSize()) {
    state_ = 0;
}

CryptoContext::~CryptoContext() {
}

int CryptoContext::EncryptSome(std::vector<uint8_t> &ctext, const uint8_t *ptext, size_t plen) {
    if (state_ == DECRYPT) {
        return ERROR;
    }

    ctext.clear();
    if (plen == 0) {
        return OK;
    }

    if (state_ == UNINITIALIZED) {
        uint8_t salt[256];
        size_t salt_size = cipher_->SaltSize();
        randombytes_buf(salt, salt_size);
        DeriveKey(salt);
        ctext.insert(ctext.end(), salt, salt + salt_size);
        state_ = ENCRYPT;
    }

    size_t remained_size = plen;
    auto *phead = ptext;
    uint8_t buffer[65536];
    int ret = 0;
    while (remained_size) {
        size_t clen;
        auto curr_chunk_size = static_cast<uint16_t>(std::min(CHUNK_MAX_SIZE, remained_size));
        uint8_t chunk_size_buf[sizeof curr_chunk_size];
        curr_chunk_size = htons(curr_chunk_size);
        memcpy(&chunk_size_buf, &curr_chunk_size, sizeof curr_chunk_size);
        curr_chunk_size = ntohs(curr_chunk_size);

        ret = \
            cipher_->Encrypt(
                buffer, &clen, chunk_size_buf, sizeof chunk_size_buf,
                nonce_.data(), key_.data()
            );
        if (ret) {
            break;
        }
        sodium_increment(nonce_.data(), nonce_.size());
        ctext.insert(ctext.end(), buffer, buffer + clen);

        ret = \
            cipher_->Encrypt(
                buffer, &clen, phead, curr_chunk_size,
                nonce_.data(), key_.data()
            );
        if (ret) {
            break;
        }
        sodium_increment(nonce_.data(), nonce_.size());
        ctext.insert(ctext.end(), buffer, buffer + clen);
        remained_size -= curr_chunk_size;
        phead += curr_chunk_size;
    }
    return ret;
}

int CryptoContext::DecryptSome(std::vector<uint8_t> &ptext, const uint8_t *ctext, size_t clen) {
    if (state_ == ENCRYPT) {
        LOG(FATAL) << "invalid state";
        return ERROR;
    }

    ptext.clear();
    if (clen == 0) {
        return OK;
    }

    buffer_.insert(buffer_.end(), ctext, ctext + clen);

    if (state_ == UNINITIALIZED) {
        size_t salt_size = cipher_->SaltSize();
        if (buffer_.size() < salt_size) {
            return OK; // need more data
        }
        const uint8_t *salt = buffer_.data();
        DeriveKey(salt);
        buffer_.erase(buffer_.begin(), buffer_.begin() + salt_size);
        state_ = DECRYPT;
    }

    size_t remained_size = buffer_.size();
    auto *chead = buffer_.data();
    uint8_t buffer[65536];
    int ret = 0;
    while (remained_size) {
        uint16_t curr_chunk_size;
        size_t mlen;
        size_t excepted_size = sizeof curr_chunk_size + 16 + 16;
        if (remained_size < excepted_size) {
            break; // need more data
        }

        ret = \
            cipher_->Decrypt(
                reinterpret_cast<uint8_t *>(&curr_chunk_size), &mlen,
                chead, sizeof curr_chunk_size + 16,
                nonce_.data(), key_.data()
            );
        if (ret) {
            break;
        }
        curr_chunk_size = ntohs(curr_chunk_size);
        excepted_size += curr_chunk_size;
        if (remained_size < excepted_size) {
            break; // need more data
        }
        chead += sizeof curr_chunk_size + 16;
        sodium_increment(nonce_.data(), nonce_.size());

        ret = \
            cipher_->Decrypt(
                buffer, &mlen, chead, curr_chunk_size + 16,
                nonce_.data(), key_.data()
            );
        if (ret) {
            break;
        }
        chead += curr_chunk_size + 16;
        sodium_increment(nonce_.data(), nonce_.size());
        ptext.insert(ptext.end(), buffer, buffer + mlen);
        remained_size -= excepted_size;
    }
    buffer_.erase(buffer_.begin(), buffer_.end() - remained_size);
    return ret;
}

void CryptoContext::DeriveKey(const uint8_t *salt) {
    int ret = \
        crypto_pwhash(
            key_.data(), key_.size(), psk_->data(), psk_->size(),
            salt, 3ULL, 0x2000ULL, crypto_pwhash_ALG_ARGON2ID13
        );
    assert(ret == 0);
}

