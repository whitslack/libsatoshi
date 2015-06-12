#include <array>
#include <chrono>
#include <ostream>
#include <vector>

#include "script.h"
#include "common/compiler.h"
#include "common/enumflags.h"
#include "common/mpn.h"


typedef std::array<uint8_t, 20> digest160_t;
typedef std::array<uint8_t, 32> digest256_t;


namespace satoshi {


struct PrivateKey {
	mp_limb_t d[MP_NLIMBS(32)];
	enum class Flags : uint8_t {
		NONE = 0,
		COMPRESS = 1 << 0,
		MASK = COMPRESS
	} flags;
};
DEFINE_ENUM_FLAG_OPS(PrivateKey::Flags)

PrivateKey decode_privkey(const char privkey[], size_t n);
std::string encode_privkey(const PrivateKey &privkey);
std::istream & operator >> (std::istream &is, PrivateKey &privkey);
std::ostream & operator << (std::ostream &os, const PrivateKey &privkey);


struct PublicKey {
	mp_limb_t Q[3][MP_NLIMBS(32)];
	bool compress;
};

Source & operator >> (Source &source, PublicKey &pubkey);
Sink & operator << (Sink &sink, const PublicKey &pubkey);

PublicKey decode_pubkey(const char pubkey[], size_t n);
std::string encode_pubkey(const PublicKey &pubkey);
std::istream & operator >> (std::istream &is, PublicKey &pubkey);
std::ostream & operator << (std::ostream &os, const PublicKey &pubkey);

void decompress_pubkey(PublicKey &pubkey);


struct Address {
	enum class Type : uint8_t {
		PUBKEY_HASH = 0,
		SCRIPT_HASH = 5,
		TESTNET_PUBKEY_HASH = 111,
		TESTNET_SCRIPT_HASH = 196,
	} type;
	digest160_t hash;
};

Address decode_address(const char address[], size_t n);
std::string encode_address(const Address &address);
std::istream & operator >> (std::istream &is, Address &address);
std::ostream & operator << (std::ostream &os, const Address &address);


PublicKey privkey_to_pubkey(const PrivateKey &privkey);

Address pubkey_to_address(const PublicKey &pubkey, bool testnet = false);

Script address_to_script(const Address &address);


} // namespace satoshi


template <typename T>
static std::ostream & operator << (std::ostream &os, const std::vector<T> &vector) {
	os << '[';
	for (size_t i = 0; i < vector.size(); ++i) {
		if (i > 0) {
			os << ',';
		}
		os << " [" << i << "]=" << vector[i];
	}
	return os << " ]";
}

double compact_to_double(uint32_t compact) _const;

std::ostream & print_digest_le(std::ostream &os, const digest256_t &digest);

std::ostream & operator << (std::ostream &os, std::chrono::system_clock::time_point time);
