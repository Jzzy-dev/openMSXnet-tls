#ifndef UNAPINETTLS_HH
#define UNAPINETTLS_HH

#include "Socket.hh"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

// UnapiNetTls - client side TLS for one UnapiNet TCP connection (mbedTLS).
//
// The MSX side never sees TLS: it opens a TCP connection with flag bit 2
// (TLS) and optionally bit 3 (verify the server certificate) and a host name
// for SNI / name check, then sends and receives plain data. Encryption happens
// here, on the host.
//
// Threading: mbedTLS is built without MBEDTLS_THREADING_C, and TLS 1.3 uses
// the global PSA crypto state. So EVERY call into any UnapiNetTls object (and
// creating / destroying one) must hold globalMutex(). The calls themselves are
// non-blocking, so the lock is only ever held for a short time.

namespace openmsx {

class UnapiNetTls
{
public:
	enum class Status { Done, WantRead, WantWrite, Error };

	// Lock this around every use of any UnapiNetTls object.
	[[nodiscard]] static std::mutex& globalMutex();

	// Set up a TLS client on an already connected, non-blocking socket.
	// Returns nullptr on failure (reason in 'error').
	[[nodiscard]] static std::unique_ptr<UnapiNetTls> create(
		SOCKET sock, const std::string& hostName, bool verify, std::string& error);

	~UnapiNetTls();
	UnapiNetTls(const UnapiNetTls&) = delete;
	UnapiNetTls& operator=(const UnapiNetTls&) = delete;

	// One non-blocking handshake step.
	[[nodiscard]] Status handshake();

	// Read decrypted data.
	//  >0 : number of bytes
	//   0 : nothing available right now (see wantWrite())
	//  -1 : peer closed the connection (close_notify or EOF)
	//  -2 : error
	[[nodiscard]] ptrdiff_t read(uint8_t* buf, size_t len);

	// Write plain data.
	//  >0 : number of bytes taken (may be less than len)
	//   0 : would block, retry later with the SAME data (see wantWrite())
	//  <0 : error
	[[nodiscard]] ptrdiff_t write(const uint8_t* buf, size_t len);

	// Decrypted bytes buffered inside mbedTLS (not visible to select()).
	[[nodiscard]] size_t pending() const;

	// After a 0 / WantWrite result: does the socket need to become writable
	// (true) or readable (false) before retrying?
	[[nodiscard]] bool wantWrite() const { return lastWantWrite; }

	// Send close_notify (best effort, non-blocking).
	void closeNotify();

	// Human readable description of the last error.
	[[nodiscard]] const std::string& lastError() const { return errorText; }

	// Protocol version and cipher suite after the handshake.
	[[nodiscard]] std::string info() const;

	// Root certificates in use: where they came from and how many.
	[[nodiscard]] static std::string caInfo();

private:
	UnapiNetTls();
	void setError(const char* what, int ret);

	struct Impl;
	std::unique_ptr<Impl> impl;
	bool lastWantWrite = false;
	std::string errorText;
};

} // namespace openmsx

#endif // UNAPINETTLS_HH
