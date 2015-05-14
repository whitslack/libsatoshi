#include "base58check.h"

#include "common/endian.h"
#include "common/mpn.h"
#include "common/sha.h"


static constexpr char encode[58] = {
	'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
	'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
	'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

static char * encode_limb(char *out, char *out_begin, mp_limb_t limb) {
#if GMP_LIMB_BITS == 64
	size_t n_limb = 10;
#elif GMP_LIMB_BITS == 32
	size_t n_limb = 5;
#endif
	if (out - n_limb < out_begin) {
		throw std::logic_error("buffer too small");
	}
	do {
		*--out = encode[limb % 58], limb /= 58;
	} while (--n_limb > 0);
	return out;
}

static char * encode_last_limb(char *out, char *out_begin, mp_limb_t limb) {
	while (limb > 0) {
		if (out == out_begin) {
			throw std::logic_error("buffer too small");
		}
		*--out = encode[limb % 58], limb /= 58;
	}
	return out;
}

size_t base58check_encode(char * _restrict out, size_t n_out, const void * _restrict in, size_t n_in) {
	if (n_out < n_in + 4) {
		throw std::logic_error("buffer too small");
	}
	SHA256 isha, osha;
	isha.write_fully(in, n_in);
	osha.write_fully(isha.digest().data(), SHA256::digest_size);
	std::memcpy(out, in, n_in);
	std::memcpy(out + n_in, osha.digest().data(), 4);
	size_t z = 0, n = n_in + 4;
	while (n > 0 && out[z] == 0) {
		out[z++] = '1', --n;
	}
	out += z, n_out -= z;
	size_t n_mpn = MP_NLIMBS(n);
	mp_limb_t _mpn[n_mpn], *mpn = _mpn;
	bytes_to_mpn(mpn, reinterpret_cast<uint8_t *>(out), n);
	char *p = out + n_out;
	while (mpn[n_mpn - 1] != 0 || --n_mpn > 0) {
#if GMP_LIMB_BITS == 64
		mp_limb_t limb = mpn_divrem_1(mpn, 0, mpn, n_mpn, UINT64_C(430804206899405824) /* 58**10 */);
#elif GMP_LIMB_BITS == 32
		mp_limb_t limb = mpn_divrem_1(mpn, 0, mpn, n_mpn, 656356768 /* 58**5 */);
#endif
		p = n_mpn == 1 && *mpn == 0 ? encode_last_limb(p, out, limb) : encode_limb(p, out, limb);
	}
	n = out + n_out - p;
	if (p != out) {
		std::memmove(out, p, n);
	}
	return z + n;
}

std::string base58check_encode(const void *in, size_t n_in) {
	std::string ret;
	ret.resize((n_in + 4) * 2);
	ret.resize(base58check_encode(&ret.front(), ret.size(), in, n_in));
	return ret;
}

static mp_limb_t decode_limb(const char *in, size_t n_in) {
	static constexpr int8_t decode['z' - '1' + 1] = {
		 0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1, -1,
		 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1, 22,
		23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1, -1,
		33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47,
		48, 49, 50, 51, 52, 53, 54, 55, 56, 57
	};
	mp_limb_t limb = 0;
	while (n_in-- > 0) {
		uint digit = static_cast<uint8_t>(*in++) - '1';
		if (digit > 'z' - '1' || static_cast<int>(digit = decode[digit]) < 0) {
			throw std::ios_base::failure("invalid Base58Check");
		}
		limb = limb * 58 + digit;
	}
	return limb;
}

size_t base58check_decode(void * _restrict out, size_t n_out, const char * _restrict in, size_t n_in) {
	uint8_t *p = static_cast<uint8_t *>(out), *end = p + n_out;
	while (n_in > 0 && *in == '1') {
		if (p == end) {
			throw std::logic_error("buffer too small");
		}
		*p++ = 0, ++in, --n_in;
	}
	mp_limb_t mpn[MP_NLIMBS(n_in)];
	mpn_zero(mpn, sizeof mpn / sizeof *mpn);
	while (n_in > 0) {
#if GMP_LIMB_BITS == 64
		static constexpr mp_limb_t power[] = {
			58, 3364, 195112, 11316496, 656356768, UINT64_C(38068692544),
			UINT64_C(2207984167552), UINT64_C(128063081718016),
			UINT64_C(7427658739644928), UINT64_C(430804206899405824)
		};
		size_t n_limb = std::min(n_in, size_t(10));
#elif GMP_LIMB_BITS == 32
		static constexpr mp_limb_t power[] = {
			58, 3364, 195112, 11316496, 656356768
		};
		size_t n_limb = std::min(n_in, size_t(5));
#endif
		mpn_mul_1(mpn, mpn, sizeof mpn / sizeof *mpn, power[n_limb - 1]);
		mpn_add_1(mpn, mpn, sizeof mpn / sizeof *mpn, decode_limb(in, n_limb));
		in += n_limb, n_in -= n_limb;
	}
	for (auto left = mpn, right = mpn + sizeof mpn / sizeof *mpn; left <= --right; ++left) {
		auto temp = *left;
		as_be(*left) = *right, as_be(*right) = temp;
	}
	auto p1 = reinterpret_cast<uint8_t *>(mpn), end1 = p1 + sizeof mpn - 4;
	while (p1 < end1 && *p1 == 0) {
		++p1;
	}
	if (p + (end1 - p1) > end) {
		throw std::logic_error("buffer too small");
	}
	std::memcpy(p, p1, end1 - p1);
	p += end1 - p1;
	SHA256 isha, osha;
	isha.write_fully(out, p - static_cast<uint8_t *>(out));
	osha.write_fully(isha.digest().data(), SHA256::digest_size);
	if (std::memcmp(end1, osha.digest().data(), 4) != 0) {
		throw std::ios_base::failure("invalid Base58Check");
	}
	return p - static_cast<uint8_t *>(out);
}
