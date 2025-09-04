#include <string>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>

using namespace boost::asio;

io_context _io_context;
ssl::context ssl_context(ssl::context::sslv23);

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

std::string to_base64(streambuf& response_buf) {
	// 使用 Boost 的 Base64 编码器
	using namespace boost::archive::iterators;
	using It = base64_from_binary<transform_width<const char*, 6, 8>>;

	std::string encoded(It((char*)response_buf.data().data()), It((char*)response_buf.data().data() + response_buf.data().size()));

	// 添加必要的填充字符
	size_t padding = (3 - response_buf.data().size() % 3) % 3;
	encoded.append(padding, '=');
	return encoded;
}

int main()
{
	ssl_context.set_default_verify_paths();
	ip::tcp::resolver resolver(_io_context);

	while (true)
	{
		std::string req_clipboard = copy_from_clipboard();
		if (!req_clipboard.starts_with("~@#> "))
		{
			Sleep(10);
			continue;
		}
		std::cout << req_clipboard << std::endl;
		try
		{
			size_t offset = req_clipboard.find("/");
			std::string host = req_clipboard.substr(5, offset - 5);
			std::string path = req_clipboard.substr(offset);

			//ip::tcp::socket()
			ssl::stream<ip::tcp::socket> ssl_stream(_io_context, ssl_context);
			auto endpoints = resolver.resolve(host, "https");
			for (const auto& endpoint : endpoints) {
				// 获取 IP 地址
				std::string ip_address = endpoint.endpoint().address().to_string();

				// 获取端口号
				unsigned short port = endpoint.endpoint().port();

				//std::cout << "IP: " << ip_address
				//	<< ", Port: " << port
				//	<< ", Protocol: " << endpoint.endpoint().protocol().protocol()
				//	<< std::endl;
			}

			connect(ssl_stream.lowest_layer(), endpoints);
			ssl_stream.lowest_layer().set_option(ip::tcp::no_delay(true));
			ssl_stream.set_verify_mode(ssl::verify_none);
			SSL_set_tlsext_host_name(ssl_stream.native_handle(), host.c_str());
			ssl_stream.handshake(ssl::stream_base::client);

			std::string request =
				"GET " + path + " HTTP/1.1\r\n"
				"Host: " + host + "\r\n"
				"Connection: close\r\n"
				"\r\n";

			write(ssl_stream, buffer(request));

			// 读取响应
			streambuf response_buf;
			boost::system::error_code ec;
			read(ssl_stream, response_buf, transfer_all(), ec);

			// 转换为字符串
			//std::string response((char*)response_buf.data().data(), response_buf.data().size());
			//std::cout << response << std::endl;

			std::string rsp_clipboard = "~@#< " + host + path + "\r\n";
			//rsp_clipboard.append((char*)response_buf.data().data(), response_buf.data().size());
			std::cout << rsp_clipboard << std::endl;
			rsp_clipboard.append(to_base64(response_buf));
			copy_to_clipboard(rsp_clipboard);
		}
		catch (const std::exception& e)
		{
			std::cerr << e.what() << std::endl;
		}
	}
}

