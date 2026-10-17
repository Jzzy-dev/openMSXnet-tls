#include "UnapiNetTls.hh"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#ifdef interface
#undef interface
#endif
#else
#include <cerrno>
#include <sys/socket.h>
#endif

#include <cstdlib>
#include <cstring>

namespace openmsx {

// --- global state (only touched while globalMutex() is held) ----------------

static bool psaReady = false;
static bool caLoaded = false;
static mbedtls_x509_crt caChain;
static std::string caSource = "none";
static int caCount = 0;

std::mutex& UnapiNetTls::globalMutex()
{
	static std::mutex m;
	return m;
}

static int countCerts(const mbedtls_x509_crt& chain)
{
	int n = 0;
	for (const auto* c = &chain; c && c->raw.len != 0; c = c->next) ++n;
	return n;
}

// Load the root certificates once. Order -
//  1. environment variable UNAPINET_CA_FILE (PEM file or directory)
//  2. Windows - the system "ROOT" certificate store
//     other     - the usual system bundle files, then /etc/ssl/certs
static void loadCaChain()
{
	if (caLoaded) return;
	caLoaded = true;
	mbedtls_x509_crt_init(&caChain);

	if (const char* env = std::getenv("UNAPINET_CA_FILE"); env && *env) {
		if (mbedtls_x509_crt_parse_file(&caChain, env) >= 0 ||
		    mbedtls_x509_crt_parse_path(&caChain, env) >= 0) {
			if ((caCount = countCerts(caChain)) > 0) {
				caSource = env;
				return;
			}
		}
	}
#ifdef _WIN32
	if (HCERTSTORE store = CertOpenSystemStoreA(0, "ROOT")) {
		PCCERT_CONTEXT ctx = nullptr;
		while ((ctx = CertEnumCertificatesInStore(store, ctx)) != nullptr) {
			if (ctx->dwCertEncodingType & X509_ASN_ENCODING) {
				// a few odd certificates in the store may not parse, ignore those
				(void)mbedtls_x509_crt_parse_der(
					&caChain, ctx->pbCertEncoded, ctx->cbCertEncoded);
			}
		}
		CertCloseStore(store, 0);
		caSource = "Windows certificate store";
	}
#else
	static const char* const files[] = {
		"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Arch
		"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
		"/etc/ssl/ca-bundle.pem",             // openSUSE
		"/etc/ssl/cert.pem",                  // macOS, Alpine, BSD
		"/usr/local/etc/openssl/cert.pem",    // Homebrew
	};
	for (const char* f : files) {
		if (mbedtls_x509_crt_parse_file(&caChain, f) >= 0 && countCerts(caChain) > 0) {
			caSource = f;
			break;
		}
	}
	if (countCerts(caChain) == 0 &&
	    mbedtls_x509_crt_parse_path(&caChain, "/etc/ssl/certs") >= 0) {
		caSource = "/etc/ssl/certs";
	}
#endif
	caCount = countCerts(caChain);
}

std::string UnapiNetTls::caInfo()
{
	return caSource + " (" + std::to_string(caCount) + " certificates)";
}

// --- socket callbacks for mbedTLS (non-blocking) ----------------------------

static bool wouldBlock()
{
#ifdef _WIN32
	int e = WSAGetLastError();
	return e == WSAEWOULDBLOCK || e == WSAEINTR;
#else
	return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

static int bioSend(void* ctx, const unsigned char* buf, size_t len)
{
	SOCKET s = *static_cast<SOCKET*>(ctx);
#if defined(MSG_NOSIGNAL)
	int flags = MSG_NOSIGNAL;
#else
	int flags = 0;
#endif
	auto n = ::send(s, reinterpret_cast<const char*>(buf), static_cast<int>(len), flags);
	if (n >= 0) return static_cast<int>(n);
	return wouldBlock() ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_SEND_FAILED;
}

static int bioRecv(void* ctx, unsigned char* buf, size_t len)
{
	SOCKET s = *static_cast<SOCKET*>(ctx);
	auto n = ::recv(s, reinterpret_cast<char*>(buf), static_cast<int>(len), 0);
	if (n >= 0) return static_cast<int>(n); // 0 = EOF
	return wouldBlock() ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_RECV_FAILED;
}

// --- per connection ----------------------------------------------------------

struct UnapiNetTls::Impl {
	SOCKET sock = OPENMSX_INVALID_SOCKET;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	mbedtls_ssl_config conf;
	mbedtls_ssl_context ssl;

	Impl() {
		mbedtls_entropy_init(&entropy);
		mbedtls_ctr_drbg_init(&drbg);
		mbedtls_ssl_config_init(&conf);
		mbedtls_ssl_init(&ssl);
	}
	~Impl() {
		mbedtls_ssl_free(&ssl);
		mbedtls_ssl_config_free(&conf);
		mbedtls_ctr_drbg_free(&drbg);
		mbedtls_entropy_free(&entropy);
	}
	Impl(const Impl&) = delete;
	Impl& operator=(const Impl&) = delete;
};

UnapiNetTls::UnapiNetTls() : impl(std::make_unique<Impl>()) {}
UnapiNetTls::~UnapiNetTls() = default;

void UnapiNetTls::setError(const char* what, int ret)
{
	char buf[160];
	mbedtls_strerror(ret, buf, sizeof(buf));
	errorText = std::string(what) + " - " + buf;
	if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
		uint32_t flags = mbedtls_ssl_get_verify_result(&impl->ssl);
		char info[256];
		if (mbedtls_x509_crt_verify_info(info, sizeof(info), "", flags) > 0) {
			// keep it on one line
			for (char* p = info; *p; ++p) if (*p == '\n') *p = ' ';
			errorText += " (";
			errorText += info;
			errorText += ")";
		}
	}
}

std::unique_ptr<UnapiNetTls> UnapiNetTls::create(
	SOCKET sock, const std::string& hostName, bool verify, std::string& error)
{
	if (!psaReady) {
		if (psa_crypto_init() != PSA_SUCCESS) {
			error = "psa_crypto_init failed";
			return nullptr;
		}
		psaReady = true;
	}
	if (verify) loadCaChain();

	std::unique_ptr<UnapiNetTls> t(new UnapiNetTls());
	auto& d = *t->impl;
	d.sock = sock;

	static const char pers[] = "openMSXnet UnapiNet";
	int ret = mbedtls_ctr_drbg_seed(&d.drbg, mbedtls_entropy_func, &d.entropy,
	                                reinterpret_cast<const unsigned char*>(pers), sizeof(pers) - 1);
	if (ret == 0) {
		ret = mbedtls_ssl_config_defaults(&d.conf, MBEDTLS_SSL_IS_CLIENT,
		                                  MBEDTLS_SSL_TRANSPORT_STREAM,
		                                  MBEDTLS_SSL_PRESET_DEFAULT);
	}
	if (ret != 0) {
		t->setError("TLS setup", ret);
		error = t->errorText;
		return nullptr;
	}
	mbedtls_ssl_conf_rng(&d.conf, mbedtls_ctr_drbg_random, &d.drbg);
	if (verify) {
		if (caCount == 0) {
			error = "no root certificates found (set UNAPINET_CA_FILE)";
			return nullptr;
		}
		mbedtls_ssl_conf_authmode(&d.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_ca_chain(&d.conf, &caChain, nullptr);
	} else {
		mbedtls_ssl_conf_authmode(&d.conf, MBEDTLS_SSL_VERIFY_NONE);
	}
	ret = mbedtls_ssl_setup(&d.ssl, &d.conf);
	if (ret == 0 && !hostName.empty()) {
		// SNI, and the name the certificate is checked against
		ret = mbedtls_ssl_set_hostname(&d.ssl, hostName.c_str());
	}
	if (ret != 0) {
		t->setError("TLS setup", ret);
		error = t->errorText;
		return nullptr;
	}
	mbedtls_ssl_set_bio(&d.ssl, &d.sock, bioSend, bioRecv, nullptr);
	return t;
}

UnapiNetTls::Status UnapiNetTls::handshake()
{
	int ret = mbedtls_ssl_handshake(&impl->ssl);
	if (ret == 0) return Status::Done;
	if (ret == MBEDTLS_ERR_SSL_WANT_READ)  { lastWantWrite = false; return Status::WantRead; }
	if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) { lastWantWrite = true;  return Status::WantWrite; }
	setError("TLS handshake", ret);
	return Status::Error;
}

ptrdiff_t UnapiNetTls::read(uint8_t* buf, size_t len)
{
	while (true) {
		int ret = mbedtls_ssl_read(&impl->ssl, buf, len);
		if (ret > 0) return ret;
		switch (ret) {
		case MBEDTLS_ERR_SSL_WANT_READ:
			lastWantWrite = false;
			return 0;
		case MBEDTLS_ERR_SSL_WANT_WRITE:
			lastWantWrite = true;
			return 0;
#ifdef MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
		case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
			continue; // TLS 1.3 ticket after the handshake, not data
#endif
		case 0:
		case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		case MBEDTLS_ERR_SSL_CONN_EOF:
			return -1;
		default:
			setError("TLS read", ret);
			return -2;
		}
	}
}

ptrdiff_t UnapiNetTls::write(const uint8_t* buf, size_t len)
{
	int ret = mbedtls_ssl_write(&impl->ssl, buf, len);
	if (ret >= 0) return ret;
	if (ret == MBEDTLS_ERR_SSL_WANT_READ)  { lastWantWrite = false; return 0; }
	if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) { lastWantWrite = true;  return 0; }
	setError("TLS write", ret);
	return -1;
}

std::string UnapiNetTls::info() const
{
	return std::string(mbedtls_ssl_get_version(&impl->ssl)) + " " +
	       mbedtls_ssl_get_ciphersuite(&impl->ssl);
}

size_t UnapiNetTls::pending() const
{
	return mbedtls_ssl_get_bytes_avail(&impl->ssl);
}

void UnapiNetTls::closeNotify()
{
	(void)mbedtls_ssl_close_notify(&impl->ssl);
}

} // namespace openmsx
