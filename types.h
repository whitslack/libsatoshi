#include <array>
#include <ostream>
#include <vector>

#include "common/compiler.h"


typedef std::array<uint8_t, 20> digest160_t;
typedef std::array<uint8_t, 32> digest256_t;

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
