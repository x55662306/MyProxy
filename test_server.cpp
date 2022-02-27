#include <boost/asio.hpp>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>

using boost::asio::ip::tcp;

boost::asio::io_context global_io_context;

class mc
{
public:
  mc() : socket_server(global_io_context){}
  void start()
  { 
    boost::asio::ip::tcp::endpoint e(boost::asio::ip::address::from_string("140.113.235.234"), 8080);
    endpoint = std::move(e);
    
    boost::system::error_code ec;
    socket_server.connect(endpoint, ec);
    if (!ec)
    {
      std::cout << "sucess" << std::endl;
    } 
    else
    {
      std::cout << ec.value() << std::endl;
    }


    /*
    socket_server.async_connect(e,
      [](const boost::system::error_code& error)
      {
        if (!error)
        {
          std::cout << "sucess" << std::endl;
          //do_read();
        }
        else
        {
          std::cout << error.value() << std::endl;
        }
      });
    */
  }
  tcp::socket socket_server;
  boost::asio::ip::tcp::endpoint endpoint;
};

class Server 
{
public:
  Server() : acceptor_(global_io_context, tcp::endpoint(tcp::v4(), 1234)), socket_(global_io_context) 
  {
    do_accept();
  }

private:
  void do_accept() 
  {
    acceptor_.async_accept(socket_, [this](boost::system::error_code ec) 
    {
      if (!ec)
        {
          get_socks4();
        }
    });
  }

  void get_socks4() 
  {
    socket_.async_read_some(
        boost::asio::buffer(data_, max_length),
        [this](boost::system::error_code ec, std::size_t length) 
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
      reply();
    }
  }

  void reply()
  {
    char str_reply[8];
    memset(str_reply, 0, strlen(str_reply));
    //for(int i=2;i<8;++i) str_reply[i] = data_[i];
    str_reply[0] = 0x0;
    unsigned char uc = 0x5a;
    str_reply[1] = (char)uc;
    std::cout << strlen(str_reply) << std::endl;
    boost::asio::async_write(socket_, boost::asio::buffer(str_reply, 8), 
      [this](boost::system::error_code ec, std::size_t length) 
        {
          if(!ec)
            do_read();
          else
            std::cout << "Reply fail: " << ec.value() << std::endl;
        });
  }

  void do_read() 
  {
    socket_.async_read_some(
        boost::asio::buffer(data_, max_length),
        [this](boost::system::error_code ec, std::size_t length) 
        {
            if (!ec)
              std::cout << data_ << std::endl;
            else
              std::cout << "Read fail: " << ec.value() << std::endl;

        });
  }

  enum { max_length = 1024 };
  char data_[max_length];
  int vn;
  int cd;
  int dstport;
  std::string dstip;
  tcp::acceptor acceptor_;
  tcp::socket socket_;
};

int main(int argc, char *argv[]) 
{
  try 
  { 
    Server s;


    //std::make_shared<mc>()->start();

    //mc my_mc;

    //my_mc.start();

    tcp::socket socket_server(global_io_context);
    boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string("140.113.235.234"), 8080);
    
    socket_server.async_connect(endpoint,
      [](const boost::system::error_code& error)
      {
        if (!error)
        {
          std::cout << "aaaaa:"  << "sucess" << std::endl;
          //do_read();
        }
        else
        {
          std::cout << "aaaaa: "  << error.value() << std::endl;
        }
      });

    global_io_context.run();
  } 
  catch (std::exception &e) 
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}