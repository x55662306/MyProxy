#include <boost/asio.hpp>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>

using boost::asio::io_service;
using boost::asio::ip::tcp;

io_service global_io_service;

auto printenv = []() {
  std::cout << "EXEC_FILE: " << getenv("EXEC_FILE") << std::endl;
  std::cout << "REQUEST_METHOD: " << getenv("REQUEST_METHOD") << std::endl;
  std::cout << "REQUEST_URI: " << getenv("REQUEST_URI") << std::endl;
  std::cout << "QUERY_STRING: " << getenv("QUERY_STRING") << std::endl;
  std::cout << "SERVER_PROTOCOL: " << getenv("SERVER_PROTOCOL") << std::endl;
  std::cout << "HTTP_HOST: " << getenv("HTTP_HOST") << std::endl;
  std::cout << "SERVER_ADDR: " << getenv("SERVER_ADDR") << std::endl;
  std::cout << "SERVER_PORT: " << getenv("SERVER_PORT") << std::endl;
  std::cout << "REMOTE_ADDR: " << getenv("REMOTE_ADDR") << std::endl;
  std::cout << "REMOTE_PORT: " << getenv("REMOTE_PORT") << std::endl;
};

class Session : public std::enable_shared_from_this<Session> {
public:
  Session(tcp::socket socket) : socket_(std::move(socket)) {}

  void start() { do_read(); }

private:
  void do_read() {
    auto self(shared_from_this());
    socket_.async_read_some(
        boost::asio::buffer(data_, max_length),
        [this, self](boost::system::error_code ec, std::size_t length) {
          sscanf(data_, "%s %s %s %s %s", REQUEST_METHOD, REQUEST_URI,
                 SERVER_PROTOCOL, blackhole, HTTP_HOST);

          if (!ec) {
            do_write(length);
          }
        });
  }

  void do_write(std::size_t length) {
    auto self(shared_from_this());
    boost::asio::async_write(
        socket_, boost::asio::buffer(status_str, strlen(status_str)),
        [this, self](boost::system::error_code ec, std::size_t /*length*/) {
          if (!ec) {

            strcpy(SERVER_ADDR,
                   socket_.local_endpoint().address().to_string().c_str());
            sprintf(SERVER_PORT, "%u", socket_.local_endpoint().port());
            strcpy(REMOTE_ADDR,
                   socket_.remote_endpoint().address().to_string().c_str());
            sprintf(REMOTE_PORT, "%u", socket_.remote_endpoint().port());

            bool flag = false;
            int j = 0;
            for (int i = 0; i < 1000; i++) {
              if (REQUEST_URI[i] == '\0') {
                break;
              } else if (REQUEST_URI[i] == '?') {
                flag = true;
                continue;
              }
              if (flag) {
                QUERY_STRING[j++] = REQUEST_URI[i];
              }
            }

            for (int i = 1; i < 100; i++) {
              if (REQUEST_URI[i] == '\0' || REQUEST_URI[i] == '?') {
                break;
              }
              EXEC_FILE[i + 1] = REQUEST_URI[i];
            }

            setenv("REQUEST_METHOD", REQUEST_METHOD, 1);
            setenv("REQUEST_URI", REQUEST_URI, 1);
            setenv("QUERY_STRING", QUERY_STRING, 1);
            setenv("SERVER_PROTOCOL", SERVER_PROTOCOL, 1);
            setenv("HTTP_HOST", HTTP_HOST, 1);
            setenv("SERVER_ADDR", SERVER_ADDR, 1);
            setenv("SERVER_PORT", SERVER_PORT, 1);
            setenv("REMOTE_ADDR", REMOTE_ADDR, 1);
            setenv("REMOTE_PORT", REMOTE_PORT, 1);
            setenv("EXEC_FILE", EXEC_FILE, 1);

            printenv();

            global_io_service.notify_fork(io_service::fork_prepare);
            if (fork() != 0) {
              global_io_service.notify_fork(io_service::fork_parent);
              socket_.close();
            } else {
              global_io_service.notify_fork(io_service::fork_child);
              int sock = socket_.native_handle();
              dup2(sock, STDERR_FILENO);
              dup2(sock, STDIN_FILENO);
              dup2(sock, STDOUT_FILENO);
              socket_.close();

              if (execlp(EXEC_FILE, EXEC_FILE, NULL) < 0) {
                std::cout << "Content-type:text/html\r\n\r\n<h1>FAIL</h1>";
              }
            }

            do_read();
          }
        });
  }

  tcp::socket socket_;
  enum { max_length = 1024 };
  char data_[max_length];
  char status_str[200] = "HTTP/1.1 200 OK\n";
  char REQUEST_METHOD[20];
  char REQUEST_URI[1000];
  char QUERY_STRING[1000];
  char SERVER_PROTOCOL[100];
  char HTTP_HOST[100];
  char SERVER_ADDR[100];
  char SERVER_PORT[10];
  char REMOTE_ADDR[100];
  char REMOTE_PORT[10];
  char EXEC_FILE[100] = "./";
  char blackhole[100];
};

class Server {
public:
  Server(short port)
      : acceptor_(global_io_service, tcp::endpoint(tcp::v4(), port)),
        socket_(global_io_service) {
    do_accept();
  }

private:
  void do_accept() {
    acceptor_.async_accept(socket_, [this](boost::system::error_code ec) {
      if (!ec) {
        std::make_shared<Session>(std::move(socket_))->start();
      }

      do_accept();
    });
  }

  tcp::acceptor acceptor_;
  tcp::socket socket_;
};

int main(int argc, char *argv[]) {
  try {
    if (argc != 2) {
      std::cerr << "Usage: async_tcp_echo_Server <port>\n";
      return 1;
    }

    Server s(std::atoi(argv[1]));

    global_io_service.run();
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}
