#include <gflags/gflags.h>
#include <glog/logging.h>
#include <boost/asio.hpp>

#include "snell_service.hxx"

DEFINE_uint32(port, 8889, "listening port");
DEFINE_string(psk, "hellosnell", "pre-shared key");

int main(int argc, char *argv[]) {
    google::ParseCommandLineFlags(&argc, &argv, true);
    FLAGS_logtostderr = 1; // dirty work
    google::InitGoogleLogging(argv[0]);

    auto bind_ep = \
        boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), FLAGS_port);

    boost::asio::io_context context;

    SnellService server{context, bind_ep, FLAGS_psk};

    context.run();

    google::ShutdownGoogleLogging();
    google::ShutDownCommandLineFlags();
    return 0;
}

