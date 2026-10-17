#!/usr/bin/env bash
# Clone openMSX at the supported release, drop the UnapiNet extension into
# place, and apply the platform patches required to build cleanly.
#
# Idempotent: safe to re-run. Detects platform via OPENMSX_TARGET_OS
# (autodetected from `uname` if unset).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OPENMSX_DIR="${OPENMSX_DIR:-${ROOT}/openMSX}"
OPENMSX_REF="${OPENMSX_REF:-RELEASE_21_0}"

if [ -z "${OPENMSX_TARGET_OS:-}" ]; then
    case "$(uname -s)" in
        Linux)              OPENMSX_TARGET_OS=linux   ;;
        Darwin)             OPENMSX_TARGET_OS=darwin  ;;
        MINGW*|MSYS*|CYGWIN*) OPENMSX_TARGET_OS=mingw32 ;;
        *)                  OPENMSX_TARGET_OS=linux   ;;
    esac
fi
echo "Target OS: ${OPENMSX_TARGET_OS}"

if [ ! -d "${OPENMSX_DIR}/.git" ]; then
    git clone --depth 1 --branch "${OPENMSX_REF}" \
        https://github.com/openMSX/openMSX.git "${OPENMSX_DIR}"
fi
cd "${OPENMSX_DIR}"

# Stage the extension sources. openMSX auto-discovers src/*/ subdirs in
# build/main.mk via `find src -type d`, so no makefile registration needed.
mkdir -p src/unapinet share/extensions
cp "${ROOT}/unapinet/UnapiNet.hh" "${ROOT}/unapinet/UnapiNet.cc" \
   "${ROOT}/unapinet/UnapiNetWire.hh" \
   "${ROOT}/unapinet/UnapiNetTls.hh" "${ROOT}/unapinet/UnapiNetTls.cc" src/unapinet/
cp "${ROOT}/unapinet/unapinet.xml" share/extensions/

# Register the device class in DeviceFactory.cc (idempotent).
if ! grep -q '"UnapiNet"' src/DeviceFactory.cc; then
    python3 - <<'PY'
import pathlib
p = pathlib.Path("src/DeviceFactory.cc")
s = p.read_text()
s = s.replace(
    '#include "SunriseIDE.hh"\n',
    '#include "SunriseIDE.hh"\n#include "UnapiNet.hh"\n', 1)
s = s.replace(
    '\t} else if (type == "SunriseIDE") {\n'
    '\t\tresult = std::make_unique<SunriseIDE>(conf);\n',
    '\t} else if (type == "SunriseIDE") {\n'
    '\t\tresult = std::make_unique<SunriseIDE>(conf);\n'
    '\t} else if (type == "UnapiNet") {\n'
    '\t\tresult = std::make_unique<UnapiNet>(conf);\n',
    1)
p.write_text(s)
PY
fi

# Extract generic host-socket helpers (used by UnapiNet) into openMSX's
# Socket.hh/.cc (matches the local build tree). Idempotent.
python3 - <<'PY'
import pathlib
hh = pathlib.Path("src/events/Socket.hh")
s = hh.read_text()
if "sock_makeIPv4" not in s:
    s = s.replace(
        "#include <cassert>\n#include <cstddef>\n#include <string>\n",
        "#include <cassert>\n#include <cstddef>\n#include <cstdint>\n#include <string>\n", 1)
    s = s.replace(
        "#include <sys/types.h>\n#include <sys/socket.h>\n#include <sys/un.h>\n"
        "#include <netinet/in.h>\n#include <fcntl.h>\n#include <unistd.h>\n",
        "#include <fcntl.h>\n#include <netinet/in.h>\n#include <sys/socket.h>\n"
        "#include <sys/types.h>\n#include <sys/un.h>\n#include <unistd.h>\n", 1)
    s = s.replace(
        "#include <winsock2.h>\n#include <ws2tcpip.h>\n#endif",
        "#include <winsock2.h>\n#include <ws2tcpip.h>\n"
        "#ifdef interface\n"
        "// windows.h (via winsock2.h) defines an 'interface' macro; undo it so it\n"
        "// cannot clobber other openMSX code that uses the word as an identifier.\n"
        "#undef interface\n"
        "#endif\n#endif", 1)
    s = s.replace(
        "[[nodiscard]] ptrdiff_t sock_send(SOCKET sd, const char* buf, size_t count);\n",
        "[[nodiscard]] ptrdiff_t sock_send(SOCKET sd, const char* buf, size_t count);\n"
        "\n"
        "// Make socket 'sd' non-blocking.\n"
        "void sock_setNonBlocking(SOCKET sd);\n"
        "// Set an integer/boolean socket option (wraps the Windows 'const char*' cast).\n"
        "void sock_setIntOption(SOCKET sd, int level, int optName, int value = 1);\n"
        "// Get an integer socket option (e.g. SO_ERROR), 0 on failure.\n"
        "[[nodiscard]] int sock_getIntOption(SOCKET sd, int level, int optName);\n"
        "// Non-blocking readiness poll (zero timeout): data ready or pending connection.\n"
        "[[nodiscard]] bool sock_readable(SOCKET sd);\n"
        "// Build an IPv4 sockaddr_in (network order); hostIp==0 -> INADDR_ANY.\n"
        "[[nodiscard]] sockaddr_in sock_makeIPv4(uint32_t hostIp, uint16_t port);\n"
        "// Best-effort local IPv4 (host order, 0 if unknown). Sends no packets.\n"
        "[[nodiscard]] uint32_t sock_localIPv4();\n", 1)
    hh.write_text(s)
cc = pathlib.Path("src/events/Socket.cc")
s = cc.read_text()
if "sock_makeIPv4" not in s:
    funcs = (
        "\nvoid sock_setNonBlocking(SOCKET sd)\n{\n"
        "#ifdef _WIN32\n\tu_long mode = 1;\n\tioctlsocket(sd, FIONBIO, &mode);\n"
        "#else\n\tint flags = fcntl(sd, F_GETFL, 0);\n\tfcntl(sd, F_SETFL, flags | O_NONBLOCK);\n#endif\n}\n\n"
        "void sock_setIntOption(SOCKET sd, int level, int optName, int value)\n{\n"
        "\tsetsockopt(sd, level, optName, std::bit_cast<const char*>(&value), sizeof(value));\n}\n\n"
        "int sock_getIntOption(SOCKET sd, int level, int optName)\n{\n"
        "\tint value = 0;\n\t::socklen_t len = sizeof(value);\n"
        "\tif (getsockopt(sd, level, optName, std::bit_cast<char*>(&value), &len) != 0) {\n"
        "\t\treturn 0;\n\t}\n\treturn value;\n}\n\n"
        "bool sock_readable(SOCKET sd)\n{\n"
        "\tfd_set rfds;\n\tFD_ZERO(&rfds);\n\tFD_SET(sd, &rfds);\n\ttimeval tv = {0, 0};\n"
        "\treturn select(static_cast<int>(sd) + 1, &rfds, nullptr, nullptr, &tv) > 0;\n}\n\n"
        "sockaddr_in sock_makeIPv4(uint32_t hostIp, uint16_t port)\n{\n"
        "\tsockaddr_in addr = {};\n\taddr.sin_family = AF_INET;\n"
        "\taddr.sin_addr.s_addr = htonl(hostIp);\n\taddr.sin_port = htons(port);\n\treturn addr;\n}\n\n"
        "uint32_t sock_localIPv4()\n{\n"
        "\tSOCKET sd = socket(AF_INET, SOCK_DGRAM, 0);\n\tif (sd == OPENMSX_INVALID_SOCKET) return 0;\n"
        "\tsockaddr_in remote = sock_makeIPv4(0x08080808, 53);\n\tuint32_t ip = 0;\n"
        "\tif (connect(sd, std::bit_cast<sockaddr*>(&remote), sizeof(remote)) == 0) {\n"
        "\t\tsockaddr_in local = {};\n\t\t::socklen_t len = sizeof(local);\n"
        "\t\tif (getsockname(sd, std::bit_cast<sockaddr*>(&local), &len) == 0) {\n"
        "\t\t\tip = ntohl(local.sin_addr.s_addr);\n\t\t}\n\t}\n\tsock_close(sd);\n\treturn ip;\n}\n")
    s = s.replace("\n} // namespace openmsx\n", funcs + "\n} // namespace openmsx\n", 1)
    cc.write_text(s)
PY

# Add converting constructors to the unaligned Endian::UA_* types (used by
# the UnapiNet wire structs' designated initializers). Idempotent.
python3 - <<'PY'
import pathlib
p = pathlib.Path("src/utils/endian.hh")
s = p.read_text()
if "explicit UA_B32" not in s:
    for name, ty, fn in [("UA_B16","uint16_t","write_UA_B16"), ("UA_L16","uint16_t","write_UA_L16"),
                         ("UA_L24","uint32_t","write_UA_L24"), ("UA_B32","uint32_t","write_UA_B32"),
                         ("UA_L32","uint32_t","write_UA_L32")]:
        old = "class %s {\npublic:\n\t[[nodiscard]] operator %s() const" % (name, ty)
        new = ("class %s {\npublic:\n\t%s() = default; // leave uninitialized\n"
               "\texplicit %s(%s a) { %s(x.data(), a); }\n"
               "\t[[nodiscard]] operator %s() const") % (name, name, name, ty, fn, ty)
        assert old in s, name
        s = s.replace(old, new, 1)
    p.write_text(s)
PY

# All platforms: gate -ldl to Linux only. The stock build adds -ldl on every
# non-mingw target, which fails on macOS where libdl does not exist.
python3 - <<'PY'
import pathlib
p = pathlib.Path("build/main.mk")
s = p.read_text()
old = ("ifneq ($(filter mingw%,$(OPENMSX_TARGET_OS)),)\n"
       "LINK_FLAGS:=-pthread\n"
       "else\n"
       "LINK_FLAGS:=-pthread -ldl\n"
       "endif\n")
new = ("ifneq ($(filter mingw%,$(OPENMSX_TARGET_OS)),)\n"
       "LINK_FLAGS:=-pthread\n"
       "else ifneq ($(filter linux%,$(OPENMSX_TARGET_OS)),)\n"
       "LINK_FLAGS:=-pthread -ldl\n"
       "else\n"
       "LINK_FLAGS:=-pthread\n"
       "endif\n")
if old in s:
    p.write_text(s.replace(old, new))
PY

# --- mbedTLS (TLS for UnapiNet TCP connections) -----------------------------
# Downloaded once, checked against its SHA-256, and built as three static
# libraries with the plain Makefile (no cmake, no python) using the compiler
# of the target. Rebuilt when the target changes. Override the compiler with
# MBEDTLS_CC / MBEDTLS_AR if needed.
MBEDTLS_VERSION="3.6.7"
MBEDTLS_SHA256="a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6"
MBEDTLS_URL="https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2"
case "${OPENMSX_TARGET_OS}" in
    mingw*)
        case "$(uname -s)" in
            MINGW*|MSYS*|CYGWIN*) MB_CC_DEF=gcc; MB_AR_DEF=ar ;;   # native MSYS2
            *) MB_CC_DEF=x86_64-w64-mingw32-gcc; MB_AR_DEF=x86_64-w64-mingw32-ar ;;
        esac ;;
    darwin) MB_CC_DEF=clang; MB_AR_DEF=ar ;;
    *)      MB_CC_DEF=gcc;   MB_AR_DEF=ar ;;
esac
MBEDTLS_CC="${MBEDTLS_CC:-${MB_CC_DEF}}"
MBEDTLS_AR="${MBEDTLS_AR:-${MB_AR_DEF}}"
if [ ! -f mbedtls/include/mbedtls/ssl.h ]; then
    curl -fsSL -o mbedtls.tar.bz2 "${MBEDTLS_URL}"
    if command -v sha256sum >/dev/null 2>&1; then
        SUM="$(sha256sum mbedtls.tar.bz2 | cut -d' ' -f1)"
    else
        SUM="$(shasum -a 256 mbedtls.tar.bz2 | cut -d' ' -f1)"
    fi
    if [ "${SUM}" != "${MBEDTLS_SHA256}" ]; then
        echo "mbedTLS download has the wrong SHA-256 (${SUM})" >&2
        exit 1
    fi
    rm -rf mbedtls && mkdir mbedtls
    tar xjf mbedtls.tar.bz2 -C mbedtls --strip-components=1
    rm -f mbedtls.tar.bz2
fi
MB_STAMP="${OPENMSX_TARGET_OS} ${MBEDTLS_CC} ${MBEDTLS_VERSION}"
if [ ! -f mbedtls/library/libmbedcrypto.a ] || [ "$(cat mbedtls/.openmsxnet-target 2>/dev/null)" != "${MB_STAMP}" ]; then
    make -C mbedtls/library clean >/dev/null 2>&1 || true
    make -C mbedtls/library -j4 CC="${MBEDTLS_CC}" AR="${MBEDTLS_AR}" \
        libmbedtls.a libmbedx509.a libmbedcrypto.a
    echo "${MB_STAMP}" > mbedtls/.openmsxnet-target
fi

# Compile and link openMSX against it (idempotent).
python3 - <<'PY'
import pathlib
p = pathlib.Path("build/main.mk")
s = p.read_text()
anchor = "LINK_FLAGS+=$(LIBRARY_LINK_FLAGS)\n"
if "openMSXnet mbedTLS" not in s:
    assert anchor in s
    s = s.replace(anchor, anchor +
        "\n# openMSXnet mbedTLS - TLS for the UnapiNet device (built by ci/setup-openmsx.sh)\n"
        "COMPILE_FLAGS+=-Imbedtls/include\n"
        "LINK_FLAGS+=mbedtls/library/libmbedtls.a mbedtls/library/libmbedx509.a mbedtls/library/libmbedcrypto.a\n"
        "ifneq ($(filter mingw%,$(OPENMSX_TARGET_OS)),)\n"
        "LINK_FLAGS+=-lbcrypt -lcrypt32\n"
        "endif\n", 1)
    p.write_text(s)
PY

# Windows MSYS2 patches.
if [ "${OPENMSX_TARGET_OS}" = "mingw32" ] || [ "${OPENMSX_TARGET_OS}" = "mingw-w64" ]; then
    # Python 3 print() and bytes->str decoding in msysutils.
    python3 - <<'PY'
import pathlib
p = pathlib.Path("build/msysutils.py")
s = p.read_text()
s = s.replace("import sys ; print sys.argv[1]",
              "import sys ; print(sys.argv[1])")
s = s.replace(
    "msysRoot = stdoutdata.strip()\n",
    "msysRoot = stdoutdata.strip().decode('utf-8') "
    "if isinstance(stdoutdata, bytes) else stdoutdata.strip()\n", 1)
p.write_text(s)
PY
    # NOTE: previous iterations replaced upstream's `-static` with
    # `-static-libgcc -static-libstdc++` to make the legacy dynamic
    # Tcl link path succeed. We now build via staticbindist (all
    # 3rdparty libs are .a archives) so the upstream `-static` works
    # again — and is required to pull libwinpthread-1.dll's symbols
    # into the .exe instead of leaving it as a runtime DLL dep.
    # Leaving platform-mingw-w64.mk untouched.
    # Winsock 2 + iphlpapi (for IcmpSendEcho).
    python3 - <<'PY'
import pathlib
p = pathlib.Path("build/platform-mingw32.mk")
s = p.read_text()
s = s.replace(
    "-L/mingw/lib -L/mingw/lib/w32api -lwsock32 -lwinmm",
    "-L/mingw/lib -L/mingw/lib/w32api -lws2_32 -lwsock32 -liphlpapi -lwinmm")
p.write_text(s)
PY
fi

echo "openMSX prepared at: ${OPENMSX_DIR}"
