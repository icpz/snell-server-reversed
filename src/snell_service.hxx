#ifndef __SNELL_SERVER_HXX__
#define __SNELL_SERVER_HXX__

#include <string>
#include <memory>

#include <boost/asio.hpp>

#include "crypto_context.hxx"

class SnellService {
public:
    SnellService(
        boost::asio::io_context &ctx,
        boost::asio::ip::tcp::endpoint bind_ep,
        const std::string &psk
    );
    ~SnellService();

    void Stop();

private:
    void DoAccept();

    bool running_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<std::string> psk_;
    std::shared_ptr<Cipher> cipher_;
};

#endif // __SNELL_SERVER_HXX__

