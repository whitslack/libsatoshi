#include "types.h"

#include <ctime>
#include <iomanip>

#include "base58check.h"
#include "common/codec.h"
#include "common/ecp.h"
#include "common/endian.h"
#include "common/fp.h"
#include "common/hex.h"
#include "common/narrow.h"
#include "common/ripemd.h"
#include "common/serial.h"
#include "common/sha.h"


namespace satoshi {


PrivateKey decode_privkey(const char privkey[], size_t n) {
	PrivateKey ret;
	uint8_t bytes[34];
	n = base58check_decode(bytes, sizeof bytes, privkey, n);
	if (bytes[0] == 0x80) {
		if (n == sizeof bytes) {
			ret.flags = static_cast<PrivateKey::Flags>(bytes[33]);
			if ((ret.flags & ~PrivateKey::Flags::MASK) != PrivateKey::Flags::NONE) {
				throw std::ios_base::failure("unrecognized flags in private key");
			}
			bytes_to_mpn(ret.d, bytes + 1, 32);
			return ret;
		}
		if (n == sizeof bytes - 1) {
			ret.flags = PrivateKey::Flags::NONE;
			bytes_to_mpn(ret.d, bytes + 1, 32);
			return ret;
		}
	}
	throw std::ios_base::failure("expected private key");
}

std::string encode_privkey(const PrivateKey &privkey) {
	uint8_t bytes[34];
	bytes[0] = 0x80;
	mpn_to_bytes(bytes + 1, privkey.d, 32);
	if (privkey.flags == PrivateKey::Flags::NONE) {
		return base58check_encode(bytes, sizeof bytes - 1);
	}
	bytes[33] = static_cast<uint8_t>(privkey.flags);
	return base58check_encode(bytes, sizeof bytes);
}

std::istream & operator >> (std::istream &is, PrivateKey &privkey) {
	std::string str;
	is >> str;
	privkey = decode_privkey(str.data(), str.size());
	return is;
}

std::ostream & operator << (std::ostream &os, const PrivateKey &privkey) {
	return os << encode_privkey(privkey);
}


Source & operator >> (Source &source, PublicKey &pubkey) {
	uint8_t type;
	source >> type;
	uint8_t bytes[32];
	switch (type) {
		case 0x02:
		case 0x03:
			source.read_fully(bytes, sizeof bytes);
			bytes_to_mpn(pubkey.Q[0], bytes);
			mpn_zero(pubkey.Q[1], MP_NLIMBS(32)), pubkey.Q[1][0] = type & 1;
			mpn_zero(pubkey.Q[2], MP_NLIMBS(32));
			pubkey.compress = true;
			return source;
		case 0x04:
			source.read_fully(bytes, sizeof bytes);
			bytes_to_mpn(pubkey.Q[0], bytes);
			source.read_fully(bytes, sizeof bytes);
			bytes_to_mpn(pubkey.Q[1], bytes);
			mpn_zero(pubkey.Q[2], MP_NLIMBS(32)), pubkey.Q[2][0] = 1;
			pubkey.compress = false;
			return source;
	}
	throw std::ios_base::failure("expected public key");
}

Sink & operator << (Sink &sink, const PublicKey &pubkey) {
	uint8_t bytes[32];
	mpn_to_bytes(bytes, pubkey.Q[0]);
	if (pubkey.compress) {
		sink << static_cast<uint8_t>(mpn_even_p(pubkey.Q[1], MP_NLIMBS(32)) ? 0x02 : 0x03);
		sink.write_fully(bytes, sizeof bytes);
	}
	else {
		sink << static_cast<uint8_t>(0x04);
		sink.write_fully(bytes, sizeof bytes);
		mpn_to_bytes(bytes, pubkey.Q[1]);
		sink.write_fully(bytes, sizeof bytes);
	}
	return sink;
}

PublicKey decode_pubkey(const char pubkey[], size_t n) {
	PublicKey ret;
	MemorySource ms(pubkey, n);
	CodecSource<HexDecoder> cs(ms);
	cs >> ret;
	return ret;
}

std::string encode_pubkey(const PublicKey &pubkey) {
	std::string ret;
	ret.reserve(pubkey.compress ? 66 : 130);
	StringSink ss(ret);
	CodecSink<HexEncoder> cs(ss);
	cs << pubkey;
	return ret;
}

std::istream & operator >> (std::istream &is, PublicKey &pubkey) {
	std::string str;
	is >> str;
	pubkey = decode_pubkey(str.data(), str.size());
	return is;
}

std::ostream & operator << (std::ostream &os, const PublicKey &pubkey) {
	return os << encode_pubkey(pubkey);
}

void decompress_pubkey(PublicKey &pubkey) {
	static constexpr mp_limb_t magic[] = {
		MP_LIMB_C(0xBFFFFF0C, 0xFFFFFFFF), MP_LIMB_C(0xFFFFFFFF, 0xFFFFFFFF),
		MP_LIMB_C(0xFFFFFFFF, 0xFFFFFFFF), MP_LIMB_C(0xFFFFFFFF, 0x3FFFFFFF)
	};
	if (mpn_zero_p(pubkey.Q[2], MP_NLIMBS(32))) {
		bool even = mpn_even_p(pubkey.Q[1], MP_NLIMBS(32));
		mp_limb_t y2[MP_NLIMBS(32)];
		fp_mul(pubkey.Q[2], pubkey.Q[0], pubkey.Q[0], secp256k1_p);
		fp_mul(y2, pubkey.Q[2], pubkey.Q[0], secp256k1_p);
		if (mpn_add_1(y2, y2, MP_NLIMBS(32), 7 /* secp256k1_b */) || mpn_cmp(y2, secp256k1_p, MP_NLIMBS(32)) >= 0) {
			mpn_sub_n(y2, y2, secp256k1_p, MP_NLIMBS(32));
		}
		fp_pow(pubkey.Q[1], y2, magic, secp256k1_p);
		if (mpn_even_p(pubkey.Q[1], MP_NLIMBS(32)) != even) {
			mpn_sub_n(pubkey.Q[1], secp256k1_p, pubkey.Q[1], MP_NLIMBS(32));
		}
		mpn_zero(pubkey.Q[2], MP_NLIMBS(32)), pubkey.Q[2][0] = 1;
	}
}


Address decode_address(const char address[], size_t n) {
	Address ret;
	n = base58check_decode(&ret, sizeof ret, address, n);
	if (n == sizeof ret && (ret.type == Address::Type::PUBKEY_HASH || ret.type == Address::Type::SCRIPT_HASH || ret.type == Address::Type::TESTNET_PUBKEY_HASH || ret.type == Address::Type::TESTNET_SCRIPT_HASH)) {
		return ret;
	}
	throw std::ios_base::failure("expected Bitcoin address");
}

std::string encode_address(const Address &address) {
	return base58check_encode(&address, sizeof address);
}

std::istream & operator >> (std::istream &is, Address &address) {
	std::string str;
	is >> str;
	address = decode_address(str.data(), str.size());
	return is;
}

std::ostream & operator << (std::ostream &os, const Address &address) {
	return os << encode_address(address);
}


PublicKey privkey_to_pubkey(const PrivateKey &privkey) {
	PublicKey ret;
	ecp_pubkey(ret.Q, secp256k1_p, secp256k1_a, secp256k1_G, privkey.d);
	ret.compress = (privkey.flags & PrivateKey::Flags::COMPRESS) != PrivateKey::Flags::NONE;
	return ret;
}

Address pubkey_to_address(const PublicKey &pubkey, bool testnet) {
	SHA256 sha;
	sha << pubkey;
	RIPEMD160 rmd;
	rmd << sha.digest();
	return { testnet ? Address::Type::TESTNET_PUBKEY_HASH : Address::Type::PUBKEY_HASH, rmd.digest() };
}

Script address_to_script(const Address &address) {
	Script txout_script;
	switch (address.type) {
		case Address::Type::PUBKEY_HASH:
		case Address::Type::TESTNET_PUBKEY_HASH:
			txout_script.push_opcode(Script::OP_DUP);
			txout_script.push_opcode(Script::OP_HASH160);
			txout_script.push_data(address.hash.data(), address.hash.size());
			txout_script.push_opcode(Script::OP_EQUALVERIFY);
			txout_script.push_opcode(Script::OP_CHECKSIG);
			break;
		case Address::Type::SCRIPT_HASH:
		case Address::Type::TESTNET_SCRIPT_HASH:
			txout_script.push_opcode(Script::OP_HASH160);
			txout_script.push_data(address.hash.data(), address.hash.size());
			txout_script.push_opcode(Script::OP_EQUAL);
			break;
	}
	return txout_script;
}


} // namespace satoshi


double compact_to_double(uint32_t compact) {
	uint32_t mantissa = compact & 0x7FFFFF;
	if (mantissa == 0) {
		return 0;
	}
	auto shift = _clz(mantissa);
	union {
		uint64_t bits;
		double value;
	} u;
	u.bits = static_cast<uint64_t>(mantissa << shift + 1) << 52 - 32 | static_cast<uint64_t>((compact >> 24) * 8 + 7 - shift + 1023) << 52 | static_cast<uint64_t>(compact & 0x800000) << 63 - 23;
	return u.value;
}

std::ostream & print_digest_le(std::ostream &os, const digest256_t &digest) {
	auto orig_flags = os.flags(std::ios_base::hex | std::ios_base::right);
	auto orig_fill = os.fill('0');
	for (auto itr = digest.rbegin(); itr != digest.rend(); ++itr) {
		os << std::setw(2) << static_cast<unsigned>(*itr);
	}
	os.fill(orig_fill);
	os.flags(orig_flags);
	return os;
}

std::ostream & operator << (std::ostream &os, std::chrono::system_clock::time_point time) {
	auto t = std::chrono::system_clock::to_time_t(time);
	std::tm tm;
	::localtime_r(&t, &tm);
	// [C++11] os << std::put_time(&tm, "%c");
	char buf[25];
	std::strftime(buf, sizeof buf, "%c", &tm);
	return os << buf;
}

Source & _varint_ops<4>::read_unsigned(Source &source, uint32_t &v) {
	v = narrow_check<uint32_t>(read_varint<uint64_t>(source));
	return source;
}

Source & _varint_ops<8>::read_unsigned(Source &source, uint64_t &v) {
	uint8_t byte;
	source >> byte;
	if (byte < 0xFD) {
		v = byte;
	}
	else if (byte == 0xFD) {
		le<uint16_t> value;
		source >> value;
		v = value;
	}
	else if (byte == 0xFE) {
		le<uint32_t> value;
		source >> value;
		v = value;
	}
	else { // (byte == 0xFF)
		le<uint64_t> value;
		source >> value;
		v = value;
	}
	return source;
}

Sink & _varint_ops<4>::write_unsigned(Sink &sink, uint32_t v) {
	if (v < 0xFD) {
		sink << static_cast<uint8_t>(v);
	}
	else if (v <= UINT16_MAX) {
		sink << static_cast<uint8_t>(0xFD) << htole(static_cast<uint16_t>(v));
	}
	else {
		sink << static_cast<uint8_t>(0xFE) << htole(v);
	}
	return sink;
}

Sink & _varint_ops<8>::write_unsigned(Sink &sink, uint64_t v) {
	if (v <= UINT32_MAX) {
		return write_varint(sink, static_cast<uint32_t>(v));
	}
	return sink << static_cast<uint8_t>(0xFF) << htole(v);
}
