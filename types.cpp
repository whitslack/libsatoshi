#include "types.h"

#include <ctime>
#include <iomanip>

#include "common/endian.h"
#include "common/narrow.h"
#include "common/serial.h"


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
		os << std::setw(2) << static_cast<uint>(*itr);
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

Source & read_varint(Source &source, uint32_t &v) {
	v = narrow_check<uint32_t>(read_varint<uint64_t>(source));
	return source;
}

Source & read_varint(Source &source, uint64_t &v) {
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

Sink & write_varint(Sink &sink, uint32_t v) {
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

Sink & write_varint(Sink &sink, uint64_t v) {
	if (v <= UINT32_MAX) {
		return write_varint(sink, static_cast<uint32_t>(v));
	}
	return sink << static_cast<uint8_t>(0xFF) << htole(v);
}
