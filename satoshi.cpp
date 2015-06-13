#include "satoshi.h"

#include <ostream>

#include "common/dns.h"
#include "common/serial.h"


namespace satoshi {


Source & operator >> (Source &source, NetworkAddress &addr) {
	return source >> addr.services >> addr.addr >> addr.port;
}

Sink & operator << (Sink &sink, const NetworkAddress &addr) {
	return sink << addr.services << addr.addr << addr.port;
}

std::ostream & operator << (std::ostream &os, const NetworkAddress &addr) {
	if (IN6_IS_ADDR_V4MAPPED(&addr.addr)) {
		sockaddr_in sai;
		sai.sin_family = AF_INET;
		sai.sin_addr.s_addr = addr.addr.s6_addr32[3];
		as_be(sai.sin_port) = addr.port;
		os << sai;
	}
	else {
		sockaddr_in6 sai6;
		sai6.sin6_family = AF_INET6;
		as_be(sai6.sin6_port) = addr.port;
		sai6.sin6_flowinfo = 0;
		sai6.sin6_addr = addr.addr;
		sai6.sin6_scope_id = 0;
		os << sai6;
	}
	return os;
}


std::ostream & operator << (std::ostream &os, const Message &) {
	return os << "{ }";
}


constexpr char VersionMessage::command[12];

Source & operator >> (Source &source, VersionMessage &msg) {
	source >> msg.version >> msg.services >> msg.timestamp >> msg.addr_recv;
	auto version = letoh(msg.version);
	if (version >= 106) {
		source >> msg.addr_from >> msg.nonce >> msg.user_agent;
		if (version >= 209) {
			source >> msg.start_height;
			if (version >= 70001) {
				source >> msg.relay;
			}
		}
	}
	return source;
}

Sink & operator << (Sink &sink, const VersionMessage &msg) {
	sink << msg.version << msg.services << msg.timestamp << msg.addr_recv;
	auto version = letoh(msg.version);
	if (version >= 106) {
		sink << msg.addr_from << msg.nonce << msg.user_agent;
		if (version >= 209) {
			sink << msg.start_height;
			if (version >= 70001) {
				sink << msg.relay;
			}
		}
	}
	return sink;
}

std::ostream & operator << (std::ostream &os, const VersionMessage &msg) {
	using ::operator <<;
	auto version = letoh(msg.version);
	auto timestamp = static_cast<std::time_t>(letoh(msg.timestamp));
	os << "{ .version = " << version << ", .services = " << msg.services << ", .timestamp = " << timestamp << " (" << std::chrono::system_clock::from_time_t(timestamp) << "), .addr_recv = " << msg.addr_recv;
	if (version >= 106) {
		os << ", .addr_from = " << msg.addr_from << ", .nonce = " << msg.nonce << ", .user_agent = \"" << msg.user_agent << '"';
		if (version >= 209) {
			os << ", .start_height = " << msg.start_height;
			if (version >= 70001) {
				os << ", .relay = " << std::boolalpha << msg.relay;
			}
		}
	}
	return os << " }";
}


constexpr char VerAckMessage::command[12];


constexpr char AddrMessage::command[12];

Source & operator >> (Source &source, AddrMessage &msg) {
	size_t count;
	source >> varint(count);
	msg.addr_list.resize(count);
	for (auto &addr : msg.addr_list) {
		source >> addr.timestamp >> addr.address;
	}
	return source;
}

Sink & operator << (Sink &sink, const AddrMessage &msg) {
	sink << varint(msg.addr_list.size());
	for (auto &addr : msg.addr_list) {
		sink << addr.timestamp << addr.address;
	}
	return sink;
}

std::ostream & operator << (std::ostream &os, const AddrMessage &msg) {
	return os << "{ .addr_list = (" << msg.addr_list.size() << ' ' << (msg.addr_list.size() == 1 ? "address" : "addresses") << ") }";
}


constexpr char InvMessage::command[12];

Source & operator >> (Source &source, InvMessage &msg) {
	return source >> msg.inventory;
}

Sink & operator << (Sink &sink, const InvMessage &msg) {
	return sink << msg.inventory;
}

std::ostream & operator << (std::ostream &os, const InvMessage &msg) {
	return os << "{ .inventory = (" << msg.inventory.size() << ' ' << (msg.inventory.size() == 1 ? "item" : "items") << ") }";
}


constexpr char GetDataMessage::command[12];


constexpr char NotFoundMessage::command[12];


constexpr char GetBlocksMessage::command[12];

Source & operator >> (Source &source, GetBlocksMessage &msg) {
	return source >> msg.version >> msg.block_locator_hashes >> msg.hash_stop;
}

Sink & operator << (Sink &sink, const GetBlocksMessage &msg) {
	return sink << msg.version << msg.block_locator_hashes << msg.hash_stop;
}

std::ostream & operator << (std::ostream &os, const GetBlocksMessage &msg) {
	return print_digest_le(os << "{ .version = " << msg.version << ", .block_locator_hashes = (" << msg.block_locator_hashes.size() << ' ' << (msg.block_locator_hashes.size() == 1 ? "hash" : "hashes") << "), .hash_stop = ", msg.hash_stop) << " }";
}


constexpr char GetHeadersMessage::command[12];


constexpr char TxMessage::command[12];


constexpr char BlockMessage::command[12];

Source & operator >> (Source &source, BlockMessage &msg) {
	return source >> static_cast<BlockHeader &>(msg) >> msg.txns;
}

Sink & operator << (Sink &sink, const BlockMessage &msg) {
	return sink << static_cast<const BlockHeader &>(msg) << msg.txns;
}

std::ostream & operator << (std::ostream &os, const BlockMessage &msg) {
	return os << static_cast<const BlockHeader &>(msg) << " (" << msg.txns.size() << ' ' << (msg.txns.size() == 1 ? "transaction" : "transactions") << ')';
}


constexpr char HeadersMessage::command[12];

Source & operator >> (Source &source, HeadersMessage &msg) {
	size_t count;
	source >> varint(count);
	msg.headers.resize(count);
	for (auto &hdr : msg.headers) {
		source >> hdr >> varint(count);
		if (count != 0) {
			throw std::ios_base::failure("block header has non-zero transaction count in headers message");
		}
	}
	return source;
}

Sink & operator << (Sink &sink, const HeadersMessage &msg) {
	sink << varint(msg.headers.size());
	for (auto &hdr : msg.headers) {
		sink << hdr << varint(0);
	}
	return sink;
}

std::ostream & operator << (std::ostream &os, const HeadersMessage &msg) {
	using ::operator <<;
	return os << "{ .headers = " << msg.headers << " }";
}


constexpr char GetAddrMessage::command[12];


constexpr char MemPoolMessage::command[12];


constexpr char PingMessage::command[12];

Source & operator >> (Source &source, PingMessage &msg) {
	return source >> msg.nonce;
}

Sink & operator << (Sink &sink, const PingMessage &msg) {
	return sink << msg.nonce;
}

std::ostream & operator << (std::ostream &os, const PingMessage &msg) {
	return os << "{ .nonce = " << msg.nonce << " }";
}


constexpr char PongMessage::command[12];


constexpr char RejectMessage::command[12];

LimitedSource & operator >> (LimitedSource &source, RejectMessage &msg) {
	source >> msg.message >> msg.ccode >> msg.reason;
	msg.data.resize(source.remaining);
	source.read_fully(msg.data.data(), msg.data.size());
	return source;
}

Sink & operator << (Sink &sink, const RejectMessage &msg) {
	sink << msg.message << msg.ccode << msg.reason;
	sink.write_fully(msg.data.data(), msg.data.size());
	return sink;
}

std::ostream & operator << (std::ostream &os, const RejectMessage &msg) {
	return os << "{ .message = \"" << msg.message << "\", .ccode = " << std::hex << std::showbase << static_cast<uint>(msg.ccode) << std::dec << ", .reason = \"" << msg.reason << "\", .data = (" << msg.data.size() << ' ' << (msg.data.size() == 1 ? "byte" : "bytes") << ") }";
}


constexpr char FilterLoadMessage::command[12];

Source & operator >> (Source &source, FilterLoadMessage &msg) {
	return source >> msg.filter >> msg.nFlags;
}

Sink & operator << (Sink &sink, const FilterLoadMessage &msg) {
	return sink << msg.filter << msg.nFlags;
}

std::ostream & operator << (std::ostream &os, const FilterLoadMessage &msg) {
	using ::operator <<;
	return os << "{ .filter = (" << msg.filter.size() << ' ' << (msg.filter.size() == 1 ? "byte" : "bytes") << "), .nHashFuncs = " << msg.filter.hash_count() << ", .nTweak = " << msg.filter.tweak() << ", .nFlags = " << msg.nFlags << " }";
}


constexpr char FilterAddMessage::command[12];

Source & operator >> (Source &source, FilterAddMessage &msg) {
	return source >> msg.data;
}

Sink & operator << (Sink &sink, const FilterAddMessage &msg) {
	return sink << msg.data;
}

std::ostream & operator << (std::ostream &os, const FilterAddMessage &msg) {
	return os << "{ .data = (" << msg.data.size() << ' ' << (msg.data.size() == 1 ? "byte" : "bytes") << ") }";
}


constexpr char FilterClearMessage::command[12];


constexpr char MerkleBlockMessage::command[12];

Source & operator >> (Source &source, MerkleBlockMessage &msg) {
	return source >> static_cast<BlockHeader &>(msg) >> msg.total_transactions >> msg.hashes >> msg.flags;
}

Sink & operator << (Sink &sink, const MerkleBlockMessage &msg) {
	return sink << static_cast<const BlockHeader &>(msg) << msg.total_transactions << msg.hashes << msg.flags;
}

std::ostream & operator << (std::ostream &os, const MerkleBlockMessage &msg) {
	return os << static_cast<const BlockHeader &>(msg) << "{ .total_transactions = " << msg.total_transactions << ", .hashes = (" << msg.hashes.size() << ' ' << (msg.hashes.size() == 1 ? "hash" : "hashes") << "), .flags = (" << msg.flags.size() << ' ' << (msg.flags.size() == 1 ? "byte" : "bytes") << ") }";
}


constexpr char AlertMessage::command[12];

Source & operator >> (Source &source, AlertMessage &msg) {
	return source >> msg.payload >> msg.signature;
}

Sink & operator << (Sink &sink, const AlertMessage &msg) {
	return sink << msg.payload << msg.signature;
}

std::ostream & operator << (std::ostream &os, const AlertMessage &msg) {
	return os << "{ .payload = (" << msg.payload.size() << ' ' << (msg.payload.size() == 1 ? "byte" : "bytes") << "), .signature = (" << msg.signature.size() << ' ' << (msg.signature.size() == 1 ? "byte" : "bytes") << ") }";
}


Source & operator >> (Source &source, AlertPayload &payload) {
	source >> payload.version;
	if (payload.version == htole<uint32_t>(1)) {
		source >> payload.relay_until >> payload.expiration >> payload.id >> payload.cancel >> payload.set_cancel >> payload.min_ver >> payload.max_ver >> payload.set_sub_ver >> payload.priority >> payload.comment >> payload.status_bar >> payload.reserved;
	}
	return source;
}

Sink & operator << (Sink &sink, const AlertPayload &payload) {
	sink << payload.version;
	if (payload.version == htole<uint32_t>(1)) {
		sink << payload.relay_until << payload.expiration << payload.id << payload.cancel << payload.set_cancel << payload.min_ver << payload.max_ver << payload.set_sub_ver << payload.priority << payload.comment << payload.status_bar << payload.reserved;
	}
	return sink;
}

std::ostream & operator << (std::ostream &os, const AlertPayload &payload) {
	using ::operator <<;
	auto version = letoh(payload.version);
	os << "{ .version = " << version;
	if (version == 1) {
		auto relay_until = static_cast<std::time_t>(letoh(payload.relay_until));
		auto expiration = static_cast<std::time_t>(letoh(payload.expiration));
		os << ", .relay_until = " << relay_until << " (" << std::chrono::system_clock::from_time_t(relay_until) << "), .expiration = " << expiration << " (" << std::chrono::system_clock::from_time_t(expiration) << "), .id = " << payload.id << ", .cancel = " << payload.cancel << ", .set_cancel = " << payload.set_cancel << ", .min_ver = " << payload.min_ver << ", .max_ver = " << payload.max_ver << ", .set_sub_ver = " << payload.set_sub_ver << ", .priority = " << payload.priority << ", .comment = \"" << payload.comment << "\", .status_bar = \"" << payload.status_bar << "\", .reserved = \"" << payload.reserved << '"';
	}
	return os << " }";
}


Source & operator >> (LimitedSource &source, UnsupportedMessage &msg) {
	msg.data.resize(source.remaining);
	source.read_fully(msg.data.data(), msg.data.size());
	return source;
}

Sink & operator << (Sink &sink, const UnsupportedMessage &msg) {
	sink.write_fully(msg.data.data(), msg.data.size());
	return sink;
}

std::ostream & operator << (std::ostream &os, const UnsupportedMessage &msg) {
	return os << '(' << msg.data.size() << ' ' << (msg.data.size() == 1 ? "byte" : "bytes") << ')';
}


} // namespace satoshi
