#include <boost/asio.hpp>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>


using boost::asio::ip::tcp;

boost::asio::io_context global_io_context;

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

class Session : public std::enable_shared_from_this<Session> 
{
public:
  Session(tcp::socket socket) : socket_client(std::move(socket)), socket_server(global_io_context), resolver(global_io_context), acceptor_(global_io_context, tcp::endpoint(tcp::v4(), INADDR_ANY)) {}

  void start() { get_socks4(); }

private:
  void get_socks4() 
  {
    auto self(shared_from_this());
    socket_client.async_read_some(
        boost::asio::buffer(data_, max_length),
        [this, self](boost::system::error_code ec, std::size_t length) 
        {
          std::cout << data_ << std::endl;
          vn = (int)(unsigned char)data_[0];
          cd = (int)(unsigned char)data_[1];
          dstport = ((int)(unsigned char)data_[2])*256 + ((int)(unsigned char)data_[3]);
          dstip = std::to_string((int)(unsigned char)data_[4]) + "." + std::to_string((int)(unsigned char)data_[5]) + "." + std::to_string((int)(unsigned char)data_[6]) + "." + std::to_string((int)(unsigned char)data_[7]);
          
          if (!ec)
            parse_cmd();
        });
  }

  void parse_cmd()
  {
    std::cout << vn << std::endl;
    std::cout << cd << std::endl;
    std::cout << dstport << std::endl;
    std::cout << dstip << std::endl;
    std::cout << "---------------------------------------------------" << std::endl;
    if(cd == 1)
    {
    	connect_reply();
    }
    else if(cd == 2)
    {
      listen_server();
    }
  }

  void connect_reply()
  {
  	auto self(shared_from_this());
  	char str_reply[8];
  	memset(str_reply, 0, strlen(str_reply));
  	//memcpy(str_reply, data_, 8);
  	str_reply[0] = 0x0;
  	str_reply[1] = 0x5a;

  	boost::asio::async_write(socket_client, boost::asio::buffer(str_reply, 8), 
  		[this, self](boost::system::error_code ec, std::size_t length) 
        {
        	if(!ec)
        		connect_server();
        	else
        		std::cout << "Reply fail: " << ec.value() << std::endl;
        });
  }

  void connect_server()
  {
    if(dstip == "0.0.0.1")
    {
      domain_name = "";
      int cnt = 8;
      while(data_[cnt] != 0)cnt++;
      std::cout << cnt << std::endl;
      for(int i=cnt+1; data_[i]!=0; i++)
      {
        domain_name += data_[i];
      }
      std::cout << domain_name << std::endl;

      boost::asio::ip::tcp::resolver::query addr(domain_name, std::to_string(dstport));
      boost::asio::ip::tcp::resolver::iterator iter = resolver.resolve(addr);

      endpoint = std::move(iter->endpoint());
    }
    else
    {
    	boost::asio::ip::tcp::endpoint e(boost::asio::ip::address::from_string(dstip), dstport);
      endpoint = std::move(e);
    }
    boost::system::error_code ec;
    socket_server.connect(endpoint, ec);
    if (!ec)
    {
      read_client();
      read_server();
    } 
    else
    {
      std::cout << "Connect to server fail: " << ec.value() << std::endl;
    }
  }

  void read_client() 
  {
    auto self(shared_from_this());
    socket_client.async_read_some(
        boost::asio::buffer(data_from_client, max_length),
        [this, self](boost::system::error_code ec, std::size_t length) 
        {
          	if (!ec)
            {
              write_server(length);
            }
            else
        		  std::cout << "Read client fail: " << ec.value() << std::endl;

        });
  }

  void write_server(std::size_t len) 
  {
    auto self(shared_from_this());
    boost::asio::async_write(socket_server, boost::asio::buffer(data_from_client, len), 
      [this, self](boost::system::error_code ec, std::size_t length) 
        {
            if (!ec)
            {
              memset(data_from_client, 0, max_length);
              read_client();
            }
            else
              std::cout << "Write server fail: " << ec.value() << std::endl;

        });
  }

  void read_server() 
  {
    auto self(shared_from_this());
    socket_server.async_read_some(
        boost::asio::buffer(data_from_server, max_length),
        [this, self](boost::system::error_code ec, std::size_t length) 
        {
            if (!ec)
            {
              write_client(length);
            }
            else
              std::cout << "Read server fail: " << ec.value() << std::endl;

        });
  }

  void write_client(std::size_t len) 
  {
    auto self(shared_from_this());
    boost::asio::async_write(socket_client, boost::asio::buffer(data_from_server, len), 
      [this, self](boost::system::error_code ec, std::size_t length) 
        {
            if (!ec)
            {
              memset(data_from_server, 0, max_length);
              read_server();
            }
            else
              std::cout << "Write client fail: " << ec.value() << std::endl;

        });
  }

  void listen_server()
  {
    auto self(shared_from_this());
    acceptor_.listen();
    int port = acceptor_.local_endpoint().port();
    std::cout << port << std::endl;
    char str_reply[8];
    memset(str_reply, 0, strlen(str_reply));
    str_reply[0] = 0x0;
    str_reply[1] = 0x5a;
    str_reply[2] = port/256;
    str_reply[3] = port%256;

    boost::asio::async_write(socket_client, boost::asio::buffer(str_reply, 8), 
      [this, self, str_reply](boost::system::error_code ec, std::size_t length) 
        {
          if(!ec)
            bind_accept(str_reply);
          else
            std::cout << "Bind reply fail 1: " << ec.value() << std::endl;
        });
  }

  void bind_accept(const char *str_reply)
  {
    auto self(shared_from_this());
    boost::system::error_code ec;
    std::cout << "start accept" << std::endl;
    boost::asio::ip::tcp::socket sc(acceptor_.accept(ec));
    if (ec)
    {
      std::cout << sc.remote_endpoint().address() << std::endl;
      boost::asio::async_write(socket_client, boost::asio::buffer(str_reply, 8), 
      [this, self](boost::system::error_code ec, std::size_t length) 
        {
          if(!ec)
            std::cout << "good good" << std::endl;
          else
            std::cout << "Bind reply fail 2: " << ec.value() << std::endl;
        });
    }
    else
    {
      std::cout << "Bind accept fail: " << ec.value() << std::endl;
    }
  }


  tcp::socket socket_client;
  tcp::socket socket_server;
  tcp::endpoint endpoint;
  tcp::resolver resolver;
  tcp::acceptor acceptor_;
  enum { max_length = 1024 };
  char data_[max_length];
  char data_from_server[max_length];
  char data_from_client[max_length];
  int vn;
  int cd;
  int dstport;
  std::string dstip;
  std::string domain_name;

};

class Server 
{
public:
  Server(short port) : acceptor_(global_io_context, tcp::endpoint(tcp::v4(), port)), socket_(global_io_context) 
  {
    do_accept();
  }

private:
  void do_accept() 
  {
    acceptor_.async_accept(socket_, [this](boost::system::error_code ec) 
    {
      if (!ec)
        std::make_shared<Session>(std::move(socket_))->start();

      do_accept();
    });
  }

  tcp::acceptor acceptor_;
  tcp::socket socket_;
};

int main(int argc, char *argv[]) 
{
  try 
  {
    if (argc != 2) 
    {
      std::cerr << "Usage: async_tcp_echo_Server <port>\n";
      return 1;
    }

    Server s(std::atoi(argv[1]));

    global_io_context.run();
  } 
  catch (std::exception &e) 
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}