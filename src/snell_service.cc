
#include <glog/logging.h>

#include "snell_service.hxx"
#include "chacha20_poly1305_ietf_cipher.hxx"

namespace bsys = boost::system;
using tcp = boost::asio::ip::tcp;

SnellService::SnellService(
    boost::asio::io_context &ctx,
    tcp::endpoint bind_ep,
    const std::string &psk
) : acceptor_(ctx, bind_ep) {

    psk_ = std::make_shared<std::string>(psk);
    cipher_ = std::make_shared<Chacha20Poly1305IetfCipher>();

    LOG(INFO) << "listening on " << bind_ep;
    running_ = true;
    DoAccept();
}

SnellService::~SnellService() {
}

void SnellService::Stop() {
    if (!running_) { return; }
    running_ = false;
    acceptor_.cancel();
}

class Session : public std::enable_shared_from_this<Session> {
    struct Peer {
        Peer(tcp::socket socket)
            : socket(std::move(socket)) {
        }

        Peer(boost::asio::io_context &ctx)
            : socket(ctx) {
        }

        void CancelAll() {
            socket.cancel();
        }

        tcp::socket socket;
        std::vector<uint8_t> buffer;
    };

    enum { READ_BUF_SIZE = 8192 };

public:
    Session(tcp::socket socket, std::shared_ptr<Cipher> cipher, std::shared_ptr<std::string> psk)
        : context_(socket.get_executor().context()),
          client_(std::move(socket)), target_(context_),
          resolver_(context_) {
              decrypt_ctx_ = std::make_shared<CryptoContext>(cipher, psk);
              encrypt_ctx_ = std::make_shared<CryptoContext>(cipher, psk);
        }

    ~Session() {
        LOG(INFO) << "session end";
    }

    void Start() {
        LOG(INFO) << "session start";
        auto read_buffer = std::make_shared<std::array<uint8_t, READ_BUF_SIZE>>();
        DoReadSnellHeader(read_buffer);
    }

private:

    void DoReadSnellHeader(std::shared_ptr<std::array<uint8_t, READ_BUF_SIZE>> read_buffer) {
        auto self{shared_from_this()};
        client_.socket.async_read_some(
            boost::asio::buffer(*read_buffer),
            [self, this, read_buffer](bsys::error_code ec, size_t length) {
                if (ec) {
                    return;
                }

                int ret = 0;
                uint8_t *header = nullptr;
                size_t remained_size = 0;
                size_t uid_len;
                uint8_t uid[256];
                size_t a_len;
                char address[256] = { 0 };
                uint16_t port;

                {
                    std::vector<uint8_t> delta;
                    ret = decrypt_ctx_->DecryptSome(delta, read_buffer->data(), length);
                    if (ret) {
                        LOG(WARNING) << "decrypt failed";
                        return;
                    }
                    if (delta.empty()) {
                        goto __snell_read_head_need_more;
                    }
                    std::copy(delta.begin(), delta.end(), std::back_inserter(client_.buffer));
                }

                header = client_.buffer.data();
                remained_size = client_.buffer.size();
                if (client_.buffer.size() < 4) {
                    goto __snell_read_head_need_more;
                }

                if (header[0] != 0x01) {
                    LOG(WARNING) << "unsupported version";
                    return;
                }

                if (header[1] == 0x00) { // ping COMMAND
                    /* not implemented */
                    LOG(WARNING) << "unimplemented command: " << (uint32_t)header[1];
                    return;
                } else if (header[1] == 0x01) {

                } else {
                    LOG(WARNING) << "unsupported command: " << (uint32_t)header[1];
                    /* unsupported command */
                    return;
                }

                uid_len = header[2];
                remained_size -= 3;
                header += 3;
                if (remained_size < uid_len) {
                    goto __snell_read_head_need_more;
                }
                if (uid_len != 0) { // might be reserved for multi user
                    memcpy(uid, header, uid_len);
                }
                remained_size -= uid_len;
                header += uid_len;

                if (remained_size < 1) {
                    goto __snell_read_head_need_more;
                }

                /* now it's address */
                a_len = header[0];
                remained_size -= 1;
                header += 1;
                if (a_len == 0) {
                    return;
                }
                if (remained_size < a_len + 2) {
                    goto __snell_read_head_need_more;
                }
                memcpy(address, header, a_len);
                header += a_len;
                remained_size -= a_len;

                memcpy(&port, header, 2);
                port = ntohs(port);
                header += 2;
                remained_size -= 2;

                {
                    auto beg = client_.buffer.begin();
                    size_t delete_size = client_.buffer.size() - remained_size;
                    client_.buffer.erase(beg, beg + delete_size);
                }

                target_.buffer.push_back(0x00); // don't know yet

                DoResolveTarget(address, std::to_string(port));
                return;

__snell_read_head_need_more:
                DoReadSnellHeader(read_buffer);
                return;
            }
        );
    }

    void DoResolveTarget(const std::string &host, const std::string &port) {
        auto self{shared_from_this()};
        LOG(INFO) << "resolving to " << host << ":" << port;
        resolver_.async_resolve(
            host, port,
            [self, this](bsys::error_code ec, tcp::resolver::results_type results) {
                if (ec) {
                    return;
                }
                DoConnectTarget(std::move(results));
            }
        );
    }

    void DoConnectTarget(tcp::resolver::results_type results) {
        auto self{shared_from_this()};
        boost::asio::async_connect(
            target_.socket, results,
            [self, this](bsys::error_code ec, tcp::endpoint ep) {
                if (ec) {
                    return;
                }
                if (!client_.buffer.empty()) {
                    DoWriteToTarget();
                } else {
                    StartStream();
                }
            }
        );
    }

    void DoWriteToTarget() {
        auto self{shared_from_this()};
        boost::asio::async_write(
            target_.socket, boost::asio::buffer(client_.buffer),
            [self, this](bsys::error_code ec, size_t len) {
                if (!ec) {
                    StartStream();
                }
            }
        );
    }

    void StartStream() {
        DoRelayStream(
            client_, target_,
            std::bind(
                &CryptoContext::DecryptSome,
                decrypt_ctx_,
                std::placeholders::_1,
                std::placeholders::_2,
                std::placeholders::_3
            )
        );
        DoRelayStream(
            target_, client_,
            std::bind(
                &CryptoContext::EncryptSome,
                encrypt_ctx_,
                std::placeholders::_1,
                std::placeholders::_2,
                std::placeholders::_3
            )
        );
    }

    template<class _Processor>
    void DoRelayStream(Peer &src, Peer &dst, _Processor proc) {
        auto self{shared_from_this()};
        auto read_buffer = std::make_shared<std::array<uint8_t, READ_BUF_SIZE>>();
        src.socket.async_read_some(
            boost::asio::buffer(*read_buffer),
            [self, this, read_buffer, &src, &dst, proc](bsys::error_code ec, size_t length) {
                if (ec) {
                    return;
                }
                int ret = 0;
                {
                    std::vector<uint8_t> delta{src.buffer.begin(), src.buffer.end()};
                    delta.insert(delta.end(), read_buffer->begin(), read_buffer->begin() + length);
                    ret = proc(src.buffer, delta.data(), delta.size());
                }
                if (ret) {
                    return;
                }
                if (src.buffer.empty()) { // need more
                    DoRelayStream(src, dst, proc);
                    return;
                }
                boost::asio::async_write(
                    dst.socket, boost::asio::buffer(src.buffer),
                    [self, this, &src, &dst, proc](bsys::error_code ec, size_t length) {
                        if (ec) {
                            return;
                        }
                        src.buffer.clear();
                        DoRelayStream(src, dst, proc);
                    } // write callback end
                );
            } // read callback end
        );
    }

    boost::asio::io_context &context_;
    Peer client_;
    Peer target_;
    tcp::resolver resolver_;
    std::shared_ptr<CryptoContext> encrypt_ctx_;
    std::shared_ptr<CryptoContext> decrypt_ctx_;
};

void SnellService::DoAccept() {
    acceptor_.async_accept(
        [this](bsys::error_code ec, tcp::socket socket) {
            if (ec) {
                return;
            }
            auto session = \
                std::make_shared<Session>(
                    std::move(socket),
                    cipher_,
                    psk_
                );
            session->Start();
            if (running_) {
                DoAccept();
            }
        }
    );
}

