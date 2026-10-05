// test_secure_channel.cpp
//
// The encrypted channel must (1) deliver messages in order, (2) reject any
// frame that is replayed, reordered, dropped-before, modified, or reflected,
// and (3) refuse to send something the peer would refuse to read.
//
// Build: g++ -std=c++17 -O2 -pthread test_secure_channel.cpp -lcrypto -o test_secure_channel
#include "handshake.hpp"
#include "test_util.hpp"

#include <thread>
using namespace secure;
using tu::check;

static std::array<uint8_t, 32> make_key(int seed) {
    std::array<uint8_t, 32> k{};
    for (int i = 0; i < 32; ++i) k[i] = static_cast<uint8_t>(seed + i * 7);
    return k;
}
static std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }
static std::string str(const std::vector<uint8_t>& v) { return {v.begin(), v.end()}; }

// Pulls one complete wire frame ([len][nonce][ct][tag]) off a socket.
static std::vector<uint8_t> grab_frame(int fd) {
    uint8_t lb[4];
    if (!read_exact(fd, lb, 4)) return {};
    uint32_t be; std::memcpy(&be, lb, 4);
    const uint32_t n = ntohl(be);
    std::vector<uint8_t> f(4 + n);
    std::memcpy(f.data(), lb, 4);
    if (!read_exact(fd, f.data() + 4, n)) return {};
    return f;
}
static void inject(int fd, const std::vector<uint8_t>& f) { write_exact(fd, f.data(), f.size()); }

// A "wire" the test controls: client sends into tap_rd; whatever the test
// injects into inj_wr is what the server actually receives.
struct Tapped {
    int tap_wr, tap_rd, inj_wr, inj_rd;
    std::array<uint8_t, 32> ck = make_key(1), sk = make_key(100);
    Tapped() {
        int a[2], b[2];
        ::socketpair(AF_UNIX, SOCK_STREAM, 0, a);
        ::socketpair(AF_UNIX, SOCK_STREAM, 0, b);
        tap_wr = a[0]; tap_rd = a[1]; inj_wr = b[0]; inj_rd = b[1];
    }
    ~Tapped() { ::close(tap_wr); ::close(tap_rd); ::close(inj_wr); ::close(inj_rd); }
    SecureChannel client() { return SecureChannel(tap_wr, Role::Client, ck, sk); }
    SecureChannel server() { return SecureChannel(inj_rd, Role::Server, ck, sk); }
};

static void test_in_order_and_handshake() {
    std::cout << "=== Real handshake, in-order delivery both directions ===\n";
    int sp[2];
    ::socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    std::optional<SecureChannel> srv, cli;
    std::thread t([&] { srv = server_handshake(sp[0]); });
    cli = client_handshake(sp[1]);
    t.join();
    check("handshake completes on both sides", srv && cli);
    if (!(srv && cli)) return;
    bool ok = true;
    for (int i = 0; i < 50; ++i) {
        ok &= cli->send(bytes("c2s-" + std::to_string(i)));
        auto r = srv->receive();
        ok &= r && str(*r) == "c2s-" + std::to_string(i);
        ok &= srv->send(bytes("s2c-" + std::to_string(i)));
        auto r2 = cli->receive();
        ok &= r2 && str(*r2) == "s2c-" + std::to_string(i);
    }
    check("50 round trips in both directions", ok);
    ok = cli->send({}) ; auto e = srv->receive();
    check("empty message round-trips", ok && e && e->empty());
    ::close(sp[0]); ::close(sp[1]);
}

static void test_replay() {
    std::cout << "\n=== Replay: a frame that was already delivered ===\n";
    Tapped w; auto cli = w.client(); auto srv = w.server();
    cli.send(bytes("PUT 1")); cli.send(bytes("DEL 1"));
    auto f0 = grab_frame(w.tap_rd), f1 = grab_frame(w.tap_rd);
    inject(w.inj_wr, f0);
    auto a = srv.receive();
    check("original frame 0 accepted", a && str(*a) == "PUT 1");
    inject(w.inj_wr, f0);
    check("replayed frame 0 rejected", !srv.receive().has_value());
    inject(w.inj_wr, f1);
    check("channel is dead after a rejected frame (fail closed)", !srv.receive().has_value());
}

static void test_reorder_and_drop() {
    std::cout << "\n=== Reorder / drop ===\n";
    {
        Tapped w; auto cli = w.client(); auto srv = w.server();
        cli.send(bytes("first")); cli.send(bytes("second"));
        auto f0 = grab_frame(w.tap_rd), f1 = grab_frame(w.tap_rd);
        inject(w.inj_wr, f1); inject(w.inj_wr, f0);
        check("frame 1 delivered before frame 0 is rejected", !srv.receive().has_value());
    }
    {
        Tapped w; auto cli = w.client(); auto srv = w.server();
        cli.send(bytes("dropped")); cli.send(bytes("after-the-drop"));
        grab_frame(w.tap_rd);                       // attacker swallows frame 0
        auto f1 = grab_frame(w.tap_rd);
        inject(w.inj_wr, f1);
        check("a gap in the sequence (frame dropped) is detected", !srv.receive().has_value());
    }
}

static void test_tamper_every_byte() {
    std::cout << "\n=== Flip every bit of a frame (after the length prefix) ===\n";
    Tapped w; auto cli = w.client();
    cli.send(bytes("sensitive payload"));
    const auto good = grab_frame(w.tap_rd);
    bool all_rejected = true; size_t tried = 0;
    for (size_t i = 4; i < good.size(); ++i) {
        for (int bit = 0; bit < 8; ++bit) {
            Tapped t2; auto srv = t2.server();
            auto bad = good; bad[i] ^= static_cast<uint8_t>(1u << bit);
            inject(t2.inj_wr, bad);
            ++tried;
            if (srv.receive().has_value()) all_rejected = false;
        }
    }
    check("all " + std::to_string(tried) + " single-bit modifications rejected (nonce, ciphertext, tag)", all_rejected);
    Tapped t3; auto srv3 = t3.server();
    inject(t3.inj_wr, good);
    auto r = srv3.receive();
    check("the unmodified frame is still accepted", r && str(*r) == "sensitive payload");
}

static void test_reflection() {
    std::cout << "\n=== Reflection: feed a side its own direction's traffic ===\n";
    Tapped w; auto cli = w.client();
    cli.send(bytes("hello"));
    const auto f = grab_frame(w.tap_rd);
    int sp[2]; ::socketpair(AF_UNIX, SOCK_STREAM, 0, sp);
    SecureChannel cli2(sp[1], Role::Client, w.ck, w.sk);
    inject(sp[0], f);
    check("client frame replayed back at a client is rejected", !cli2.receive().has_value());
    ::close(sp[0]); ::close(sp[1]);
}

static void test_oversize_send() {
    std::cout << "\n=== send() refuses what receive() would refuse ===\n";
    Tapped w; auto cli = w.client(); auto srv = w.server();
    std::vector<uint8_t> huge(17u * 1024 * 1024, 'x');
    check("17 MB message refused at the sender", !cli.send(huge));
    check("a refused send does not consume a nonce (next message still in sequence)", cli.send(bytes("ok")));
    inject(w.inj_wr, grab_frame(w.tap_rd));
    auto r = srv.receive();
    check("next message arrives in order", r && str(*r) == "ok");
}

int main() {
    test_in_order_and_handshake();
    test_replay();
    test_reorder_and_drop();
    test_tamper_every_byte();
    test_reflection();
    test_oversize_send();
    return tu::summary();
}
