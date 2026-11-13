// Linux / C++17 / OpenSSL 3.x. Use OpenSSL >=3.5 for X25519MLKEM768.
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

using Context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using Session = std::unique_ptr<SSL, decltype(&SSL_free)>;
struct FileCloser {
    void operator()(FILE* f) const {
        if (f)
            std::fclose(f);
    }
};
std::unique_ptr<FILE, FileCloser> keylog_file;
void keylog_line(const SSL*, const char* line) {
    if (keylog_file) {
        std::fprintf(keylog_file.get(), "%s\n", line);
        std::fflush(keylog_file.get());
    }
}
struct Fd {
    int n;
    explicit Fd(int value) : n(value) {
        if (n < 0)
            throw std::runtime_error(std::strerror(errno));
    }
    ~Fd() {
        close(n);
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};
struct Timeout : std::runtime_error {
    Timeout() : std::runtime_error("operation deadline exceeded") {}
};
int64_t clock_ns(clockid_t clock = CLOCK_MONOTONIC) {
    timespec t{};
    if (clock_gettime(clock, &t))
        throw std::runtime_error("clock_gettime failed");
    return int64_t(t.tv_sec) * 1000000000LL + t.tv_nsec;
}
std::string errors(const std::string& where) {
    std::string out = where;
    for (unsigned long e; (e = ERR_get_error()) != 0;) {
        char b[256];
        ERR_error_string_n(e, b, sizeof b);
        out += ": ";
        out += b;
    }
    return out;
}
void require(bool ok, const std::string& where) {
    if (!ok)
        throw std::runtime_error(errors(where));
}
std::string quote(const std::string& s) {
    std::ostringstream o;
    o << '"';
    for (unsigned char c : s) {
        if (c == '"' || c == '\\')
            o << '\\' << c;
        else if (c < 32)
            o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << int(c);
        else
            o << c;
    }
    return o.str() + '"';
}
std::string lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
void wait_fd(int fd, short events, int64_t deadline) {
    for (;;) {
        auto left = deadline - clock_ns();
        if (left <= 0)
            throw Timeout();
        pollfd p{fd, events, 0};
        int ms = static_cast<int>(
            std::min<int64_t>((left + 999999) / 1000000, INT_MAX));
        int r = poll(&p, 1, ms);
        if (r > 0)
            return; // the next socket/SSL call diagnoses hangup or error
        if (r < 0 && errno != EINTR)
            throw std::runtime_error(std::strerror(errno));
    }
}
void configure_socket(int fd) {
    int one = 1;
    require(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) == 0,
            "TCP_NODELAY");
    int flags = fcntl(fd, F_GETFL, 0);
    require(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
            "nonblocking socket");
}
sockaddr_in address(const char* ip, int port) {
    if (port < 1 || port > 65535)
        throw std::runtime_error("invalid port");
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port));
    require(inet_pton(AF_INET, ip, &a.sin_addr) == 1, "IPv4 address required");
    return a;
}
// Call SSL_get_error immediately after the SSL operation, on the same thread.
template <class Function>
void ssl_operation(SSL* ssl, int64_t deadline, Function f) {
    for (;;) {
        if (clock_ns() >= deadline)
            throw Timeout();
        ERR_clear_error();
        errno = 0;
        int r = f();
        if (r == 1)
            return;
        int e = SSL_get_error(ssl, r);
        int saved_errno = errno;
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            wait_fd(SSL_get_fd(ssl),
                    e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
        } else {
            throw std::runtime_error(errors("TLS error " + std::to_string(e) +
                                            " errno " +
                                            std::to_string(saved_errno)));
        }
    }
}
struct Trace {
    int hrr = 0, client_finished = 0, server_finished = 0;
};
void message(int write, int, int type, const void* buffer, size_t n, SSL*,
             void* arg) {
    auto& t = *static_cast<Trace*>(arg);
    auto* p = static_cast<const unsigned char*>(buffer);
    static const unsigned char retry_random[32] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
        0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
        0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    if (type != SSL3_RT_HANDSHAKE || n < 4)
        return;
    if (!write && p[0] == SSL3_MT_SERVER_HELLO && n >= 38 &&
        !std::memcmp(p + 6, retry_random, 32))
        ++t.hrr;
    if (p[0] == SSL3_MT_FINISHED) {
        if (write)
            ++t.client_finished;
        else
            ++t.server_finished;
    }
}
Context context(bool server, const char* cert, const char* key = nullptr) {
    Context c(SSL_CTX_new(server ? TLS_server_method() : TLS_client_method()),
              SSL_CTX_free);
    require(bool(c), "SSL_CTX_new");
    require(SSL_CTX_set_min_proto_version(c.get(), TLS1_3_VERSION) == 1,
            "min TLS");
    require(SSL_CTX_set_max_proto_version(c.get(), TLS1_3_VERSION) == 1,
            "max TLS");
    require(SSL_CTX_set_ciphersuites(c.get(), "TLS_AES_128_GCM_SHA256") == 1,
            "cipher");
    require(SSL_CTX_set1_sigalgs_list(c.get(), "rsa_pss_rsae_sha256") == 1,
            "signature algorithm");
    SSL_CTX_set_session_cache_mode(c.get(), SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(c.get(), SSL_OP_NO_TICKET);
    require(SSL_CTX_set_max_early_data(c.get(), 0) == 1, "early data");
    if (server) {
        require(SSL_CTX_set_num_tickets(c.get(), 0) == 1, "ticket count");
        require(SSL_CTX_use_certificate_chain_file(c.get(), cert) == 1,
                "server certificate");
        require(SSL_CTX_use_PrivateKey_file(c.get(), key, SSL_FILETYPE_PEM) ==
                    1,
                "server key");
        require(SSL_CTX_check_private_key(c.get()) == 1,
                "key matches certificate");
    } else {
        SSL_CTX_set_verify(c.get(), SSL_VERIFY_PEER, nullptr);
        require(SSL_CTX_load_verify_locations(c.get(), cert, nullptr) == 1,
                "trust anchor");
        // Only capture runs set this. Main runs explicitly remove it.
        if (const char* path = std::getenv("TLSBENCH_KEYLOG")) {
            keylog_file.reset(std::fopen(path, "a"));
            require(bool(keylog_file), "keylog open");
            SSL_CTX_set_keylog_callback(c.get(), keylog_line);
        }
    }
    return c;
}
struct Result {
    std::string status = "error", error, phase = "setup", group, negotiated,
                tls, cipher;
    int reused = -1;
    long verify = -1;
    Trace trace;
    int64_t tcp = -1, handshake = -1, cpu = -1, response = -1;
    uint64_t sent = 0, received = 0;
    int local_port = 0;
};
void emit(const Result& r) {
    std::cout << "{\"status\":" << quote(r.status)
              << ",\"error\":" << quote(r.error)
              << ",\"phase\":" << quote(r.phase)
              << ",\"offered_group\":" << quote(r.group)
              << ",\"negotiated_group\":" << quote(r.negotiated)
              << ",\"tls\":" << quote(r.tls)
              << ",\"cipher\":" << quote(r.cipher) << ",\"reused\":" << r.reused
              << ",\"verify_result\":" << r.verify << ",\"hrr\":" << r.trace.hrr
              << ",\"client_finished\":" << r.trace.client_finished
              << ",\"server_finished\":" << r.trace.server_finished
              << ",\"tcp_ns\":" << r.tcp << ",\"tls_ns\":" << r.handshake
              << ",\"client_cpu_ns\":" << r.cpu
              << ",\"response_ns\":" << r.response
              << ",\"tls_sent_bytes\":" << r.sent
              << ",\"tls_received_bytes\":" << r.received
              << ",\"local_port\":" << r.local_port << "}\n"
              << std::flush;
}
Result trial(SSL_CTX* ctx, const sockaddr_in& addr, const std::string& group,
             int timeout_ms) {
    Result r;
    r.group = group;
    try {
        Fd fd(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
        configure_socket(fd.n);
        Session ssl(SSL_new(ctx), SSL_free);
        require(bool(ssl), "SSL_new");
        require(SSL_set1_groups_list(ssl.get(), group.c_str()) == 1,
                "group unavailable");
        require(SSL_set_tlsext_host_name(ssl.get(), "bench.test") == 1, "SNI");
        require(SSL_set1_host(ssl.get(), "bench.test") == 1,
                "hostname validation");
        require(SSL_set_fd(ssl.get(), fd.n) == 1, "SSL_set_fd");
        SSL_set_msg_callback(ssl.get(), message);
        SSL_set_msg_callback_arg(ssl.get(), &r.trace);
        r.phase = "tcp";
        const auto start = clock_ns();
        const auto deadline = start + int64_t(timeout_ms) * 1000000;
        if (connect(fd.n, reinterpret_cast<const sockaddr*>(&addr),
                    sizeof addr) != 0) {
            if (errno != EINPROGRESS)
                throw std::runtime_error(std::strerror(errno));
            wait_fd(fd.n, POLLOUT, deadline);
            int err = 0;
            socklen_t len = sizeof err;
            require(getsockopt(fd.n, SOL_SOCKET, SO_ERROR, &err, &len) == 0,
                    "SO_ERROR");
            if (err)
                throw std::runtime_error(std::strerror(err));
        }
        r.tcp = clock_ns() - start;
        r.phase = "tls";
        const auto cpu_start = clock_ns(CLOCK_THREAD_CPUTIME_ID);
        const auto tls_start = clock_ns();
        ssl_operation(ssl.get(), deadline,
                      [&] { return SSL_connect(ssl.get()); });
        const auto tls_end = clock_ns();
        const auto cpu_end = clock_ns(CLOCK_THREAD_CPUTIME_ID);
        r.handshake = tls_end - tls_start;
        r.cpu = cpu_end - cpu_start;
        r.sent = BIO_number_written(SSL_get_wbio(ssl.get()));
        r.received = BIO_number_read(SSL_get_rbio(ssl.get()));
        // Send/read a fixed one-byte application exchange immediately;
        // validation and formatting follow this timing boundary, so they do not
        // inflate response time.
        r.phase = "application";
        size_t done = 0;
        const char request = 'Q';
        char response = 0;
        ssl_operation(ssl.get(), deadline, [&] {
            return SSL_write_ex(ssl.get(), &request, 1, &done);
        });
        require(done == 1, "short request");
        ssl_operation(ssl.get(), deadline, [&] {
            return SSL_read_ex(ssl.get(), &response, 1, &done);
        });
        r.response = clock_ns() - start;
        require(done == 1 && response == 'A', "incorrect response");
        r.phase = "validation";
        const char* name =
            SSL_group_to_name(ssl.get(), SSL_get_negotiated_group(ssl.get()));
        r.negotiated = name ? name : "";
        r.tls = SSL_get_version(ssl.get());
        r.cipher = SSL_get_cipher_name(ssl.get());
        r.reused = SSL_session_reused(ssl.get());
        r.verify = SSL_get_verify_result(ssl.get());
        sockaddr_in local{};
        socklen_t len = sizeof local;
        require(getsockname(fd.n, reinterpret_cast<sockaddr*>(&local), &len) ==
                    0,
                "getsockname");
        r.local_port = ntohs(local.sin_port);
        require(lower(r.negotiated) == lower(group),
                "negotiated group mismatch");
        require(r.tls == "TLSv1.3" && r.cipher == "TLS_AES_128_GCM_SHA256",
                "TLS/cipher mismatch");
        require(!r.reused && r.verify == X509_V_OK,
                "resumption or verification failure");
        require(r.trace.hrr == 0 && r.trace.client_finished == 1 &&
                    r.trace.server_finished == 1,
                "unexpected handshake path");
        // Complete bidirectional close_notify outside measurement. Prevent
        // unread TLS records from causing RST and contaminating the next serial
        // trial.
        r.phase = "shutdown";
        ssl_operation(ssl.get(), clock_ns() + int64_t(timeout_ms) * 1000000,
                      [&] {
                          int v = SSL_shutdown(ssl.get());
                          return v == 0 ? SSL_shutdown(ssl.get()) : v;
                      });
        r.status = "ok";
        r.phase = "done";
    } catch (const Timeout& e) {
        r.status = "timeout";
        r.error = e.what();
    } catch (const std::exception& e) {
        r.error = e.what();
    }
    return r;
}
void server(const char* ip, int port, const char* cert, const char* key,
            const char* groups) {
    auto ctx = context(true, cert, key);
    require(SSL_CTX_set1_groups_list(ctx.get(), groups) == 1, "server groups");
    Fd listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    int one = 1;
    require(
        setsockopt(listener.n, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0,
        "SO_REUSEADDR");
    auto addr = address(ip, port);
    require(bind(listener.n, reinterpret_cast<sockaddr*>(&addr), sizeof addr) ==
                0,
            "bind");
    require(listen(listener.n, 32) == 0, "listen");
    std::cout << "READY " << OpenSSL_version(OPENSSL_VERSION) << '\n'
              << std::flush;
    for (;;) {
        int accepted = accept4(listener.n, nullptr, nullptr, SOCK_CLOEXEC);
        if (accepted < 0) {
            if (errno == EINTR)
                continue;
            throw std::runtime_error("accept failed");
        }
        try {
            Fd fd(accepted);
            configure_socket(fd.n);
            Session ssl(SSL_new(ctx.get()), SSL_free);
            require(bool(ssl), "SSL_new");
            require(SSL_set_fd(ssl.get(), fd.n) == 1, "SSL_set_fd");
            auto deadline = clock_ns() + 10000000000LL;
            ssl_operation(ssl.get(), deadline,
                          [&] { return SSL_accept(ssl.get()); });
            char q = 0;
            size_t n = 0;
            ssl_operation(ssl.get(), deadline,
                          [&] { return SSL_read_ex(ssl.get(), &q, 1, &n); });
            require(n == 1 && q == 'Q', "bad request");
            const char answer = 'A';
            ssl_operation(ssl.get(), deadline, [&] {
                return SSL_write_ex(ssl.get(), &answer, 1, &n);
            });
            require(n == 1, "short response");
            ssl_operation(ssl.get(), deadline, [&] {
                int v = SSL_shutdown(ssl.get());
                return v == 0 ? SSL_shutdown(ssl.get()) : v;
            });
        } catch (const std::exception& e) {
            std::cerr << "connection: " << e.what() << '\n';
        }
    }
}
int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    try {
        if (argc == 2 && std::string(argv[1]) == "version") {
            std::cout << "headers=" << OPENSSL_VERSION_TEXT
                      << "\nruntime=" << OpenSSL_version(OPENSSL_VERSION)
                      << '\n';
            return 0;
        }
        if (argc == 7 && std::string(argv[1]) == "server") {
            server(argv[2], std::stoi(argv[3]), argv[4], argv[5], argv[6]);
            return 0;
        }
        if (argc == 6 && std::string(argv[1]) == "client") {
            auto ctx = context(false, argv[4]);
            auto addr = address(argv[2], std::stoi(argv[3]));
            int timeout = std::stoi(argv[5]);
            require(timeout > 0 && timeout <= 60000, "timeout range");
            std::cout << "READY " << OpenSSL_version(OPENSSL_VERSION) << '\n'
                      << std::flush;
            std::string group;
            while (std::getline(std::cin, group)) {
                if (group == "QUIT")
                    break;
                emit(trial(ctx.get(), addr, group, timeout));
            }
            return 0;
        }
        std::cerr << "Usage:\n  tlsbench version\n  tlsbench server IP PORT "
                     "CERT KEY GROUPS\n"
                     "  tlsbench client IP PORT CA TIMEOUT_MS  # one group per "
                     "stdin line\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 2;
    }
}
