#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "common/compiler.h"
#include "common/io.h"


namespace satoshi {


class BloomFilter {
	friend Sink & operator << (Sink &, const BloomFilter &);
	friend Source & operator >> (Source &, BloomFilter &);

private:
	std::vector<uint8_t> bits;
	uint32_t _hash_count, _tweak;

public:
	BloomFilter() : _hash_count(), _tweak() { }
	BloomFilter(size_t size, uint32_t hash_count, uint32_t tweak) : bits(size), _hash_count(hash_count), _tweak(tweak) { }
	BloomFilter(size_t capacity, double pfp, uint32_t tweak) :
			bits(std::min(static_cast<size_t>(std::ceil(static_cast<double>(capacity) * std::log(pfp) / -(std::log(2) * std::log(2)) / 8)), size_t(36000))),
			_hash_count(std::min(static_cast<uint32_t>(std::lround(std::log(2) * 8 * static_cast<double>(bits.size()) / static_cast<double>(capacity))), 50u)),
			_tweak(tweak) { }
	BloomFilter(size_t capacity, double pfp) : BloomFilter(capacity, pfp, static_cast<uint32_t>(std::chrono::steady_clock::now().time_since_epoch().count())) { }

public:
	uint8_t * data() { return bits.data(); }
	const uint8_t * data() const { return bits.data(); }
	size_t size() const { return bits.size(); }
	uint32_t hash_count() const { return _hash_count; }
	uint32_t tweak() const { return _tweak; }

	void insert(const void *data, size_t data_size);
	bool maybe_contains(const void *data, size_t data_size) const _pure;

};

Sink & operator << (Sink &sink, const BloomFilter &filter);
Source & operator >> (Source &source, BloomFilter &filter);


} // namespace satoshi
