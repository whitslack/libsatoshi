#include "bloom.h"

#include "common/murmur3.h"
#include "common/serial.h"


namespace satoshi {


static inline void set_bit(uint8_t *bits, size_t bit_idx) {
	bits[bit_idx / 8] |= static_cast<uint8_t>(1 << bit_idx % 8);
}

static inline bool test_bit(const uint8_t *bits, size_t bit_idx) {
	return bits[bit_idx / 8] & 1 << bit_idx % 8;
}


void BloomFilter::insert(const void *data, size_t data_size) {
	size_t n_bits = bits.size() * 8;
	uint32_t seed = _tweak;
	for (uint32_t hash_idx = 0; hash_idx < _hash_count; ++hash_idx) {
		set_bit(bits.data(), murmur3_32(data, data_size, seed) % n_bits);
		seed += 0xfba4c795;
	}
}

bool BloomFilter::maybe_contains(const void *data, size_t data_size) const {
	size_t n_bits = bits.size() * 8;
	uint32_t seed = _tweak;
	for (uint32_t hash_idx = 0; hash_idx < _hash_count; ++hash_idx) {
		if (!test_bit(bits.data(), murmur3_32(data, data_size, seed) % n_bits)) {
			return false;
		}
		seed += 0xfba4c795;
	}
	return true;
}

Sink & operator << (Sink &sink, const BloomFilter &filter) {
	return sink << filter.bits << le(filter._hash_count) << le(filter._tweak);
}

Source & operator >> (Source &source, BloomFilter &filter) {
	return source >> filter.bits >> le(filter._hash_count) >> le(filter._tweak);
}


} // namespace satoshi
