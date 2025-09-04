#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>

using namespace boost::asio;

#define CONNECT_SUCCESS "HTTP/1.1 200 Connection Established\r\n\r\n"

#define HTTP_RSP_DEMO "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n01234567890123456789"

io_context _io_context;
ssl::context ssl_context(ssl::context::tls_server);
ip::tcp::acceptor acceptor(_io_context, ip::tcp::endpoint(ip::tcp::v4(), 8888));

bool copy_to_clipboard(std::string& content) {
	if (!OpenClipboard(NULL)) {
		return false;
	}
	EmptyClipboard();
	// 计算需要的缓冲区大小（包括null终止符
	size_t bufferSize = content.size() + 1;

	// 分配全局内存
	HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bufferSize);
	if (!hMem) {
		CloseClipboard();
		return false;
	}

	// 锁定内存并复制数据
	char* pMem = (char*)GlobalLock(hMem);
	if (!pMem) {
		GlobalFree(hMem);
		CloseClipboard();
		return false;
	}
	strcpy_s(pMem, bufferSize, content.c_str());
	GlobalUnlock(hMem);

	// 设置剪切板数据
	SetClipboardData(CF_TEXT, hMem);

	// 关闭剪切板
	CloseClipboard();
	return true;
}

std::string copy_from_clipboard() {
	std::string content;
	if (!OpenClipboard(NULL)) {
		return content;
	}

	HANDLE hData = GetClipboardData(CF_TEXT);
	if (hData != NULL) {
		char* text = static_cast<char*>(GlobalLock(hData));
		if (text != NULL) {
			content = text;
			GlobalUnlock(hData);
		}
	}

	// 关闭剪切板
	CloseClipboard();
	return content;
}

std::vector<uint8_t> base64_to_bytes(std::string base64_str) {
	using namespace boost::archive::iterators;
	using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

	size_t padding = 0;
	if (base64_str.size() >= 2) {
		if (base64_str[base64_str.size() - 1] == '=') {
			padding++;
		}
		if (base64_str[base64_str.size() - 2] == '=') {
			padding++;
		}
	}

	// 解码
	std::vector<uint8_t> bytes(It(base64_str.begin()), It(base64_str.end() - padding));
	return bytes;
}

void async_handle(const boost::system::error_code& error, boost::asio::ip::tcp::socket sock) {
	try
	{
		streambuf connect_header_buf;
		read_until(sock, connect_header_buf, "\r\n\r\n");
		std::cout << std::string(reinterpret_cast<const char*>(connect_header_buf.data().data()), connect_header_buf.data().size());

		auto sock_ptr = std::make_shared<ip::tcp::socket>(std::move(sock));
		async_write(*sock_ptr, buffer(CONNECT_SUCCESS, strlen(CONNECT_SUCCESS)), [sock_ptr](const boost::system::error_code& error, std::size_t bytes_transferred) {
			auto ssl_stream = std::make_shared<ssl::stream<ip::tcp::socket>>(std::move(*sock_ptr), ssl_context);
			ssl_stream->async_handshake(ssl::stream_base::server, [ssl_stream](const boost::system::error_code& ec) {
				streambuf req_header_buf;
				boost::system::error_code read_until_ec;
				read_until(*ssl_stream, req_header_buf, "\r\n\r\n", read_until_ec);
				if (read_until_ec.failed()) {
					std::cerr << read_until_ec.what() << std::endl;
					return;
				}

				std::string req_header(reinterpret_cast<const char*>(req_header_buf.data().data()), req_header_buf.data().size());
				std::cout << req_header;

				if (req_header.substr(0, 4) != "GET ") {
					return;
				}

				size_t offset_l = 0, offset_r = 0;
				offset_l = req_header.find(' ') + 1;
				offset_r = req_header.find(' ', offset_l);
				std::string path = req_header.substr(offset_l, offset_r - offset_l);
				offset_l = req_header.find("Host: ", offset_r) + 6;
				offset_r = req_header.find("\r\n", offset_l);
				std::string host = req_header.substr(offset_l, offset_r - offset_l);

				std::string req_clipboard = "~@#> " + host + path;
				std::cout << req_clipboard << std::endl;
				if (!copy_to_clipboard(req_clipboard))
					return;

				std::string rsp, rsp_prefix = "~@#< " + host + path + "\r\n";
				for (size_t i = 0; i < 10000; i++)
				{
					rsp = copy_from_clipboard();
					if (rsp.starts_with(rsp_prefix))
						break;
					rsp = "";
					steady_timer(_io_context, boost::asio::chrono::milliseconds(10)).wait();
				}
				if (rsp.empty())
					return;
				std::cout << rsp_prefix << rsp.size() << std::endl;

				//async_write(*ssl_stream, buffer(HTTP_RSP_DEMO, strlen(HTTP_RSP_DEMO)), [ssl_stream](const boost::system::error_code& ec, std::size_t bytes_transferred) {
				//	steady_timer(_io_context, boost::asio::chrono::seconds(1)).wait();
				//	});
				std::vector<uint8_t> bytes = base64_to_bytes(std::string(rsp.data() + rsp_prefix.size(), rsp.size() - rsp_prefix.size()));
				write(*ssl_stream, buffer(bytes.data(), bytes.size()));
				steady_timer(_io_context, boost::asio::chrono::seconds(1)).wait();
				});
			});
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}
	acceptor.async_accept(async_handle);
}

int main()
{
	ssl_context.use_certificate_file(R"(D:\program\openssl\ssl\certs\cert.pem)", ssl::context::pem);
	ssl_context.use_private_key_file(R"(D:\program\openssl\ssl\certs\key.pem)", ssl::context::pem);
	acceptor.async_accept(async_handle);
	_io_context.run();
}
