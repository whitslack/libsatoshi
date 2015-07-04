#include <iosfwd>

#include <netinet/in.h>

#include "blockchain.h"
#include "bloom.h"
#include "common/enumflags.h"
#include "common/io.h"


namespace satoshi {


enum class Services : uint64_t {
	NODE_NETWORK = 1 << 0,
};

DEFINE_ENUM_FLAG_OPS(Services)


struct MessageHeader {
	enum class Magic : uint32_t {
		MAIN = 0xD9B4BEF9,
		TESTNET3 = 0x0709110B,
	};
	le<Magic> magic;
	char command[12];
	le<uint32_t> length;
	uint32_t checksum;
};


struct NetworkAddress {
	le<Services> services;
	in6_addr addr;
	be<uint16_t> port;
};

Source & operator >> (Source &source, NetworkAddress &addr);
Sink & operator << (Sink &sink, const NetworkAddress &addr);
std::ostream & operator << (std::ostream &os, const NetworkAddress &addr);


struct InventoryVector {
	enum class Type : uint32_t {
		ERROR = 0,
		MSG_TX = 1,
		MSG_BLOCK = 2,
		MSG_FILTERED_BLOCK = 3,
	};
	le<Type> type;
	digest256_t hash;
};


struct Message {
	Message() { } // force non-POD type
};

static inline Source & operator >> (Source &source, Message &) { return source; }
static inline Sink & operator << (Sink &sink, const Message &) { return sink; }
std::ostream & operator << (std::ostream &os, const Message &msg);


struct VersionMessage : Message {
	static constexpr char command[12] = "version";

	le<uint32_t> version;
	le<Services> services;
	le<int64_t> timestamp;
	NetworkAddress addr_recv;
	NetworkAddress addr_from;
	le<uint64_t> nonce;
	std::string user_agent;
	le<int32_t> start_height;
	bool relay;
};

Source & operator >> (Source &source, VersionMessage &msg);
Sink & operator << (Sink &sink, const VersionMessage &msg);
std::ostream & operator << (std::ostream &os, const VersionMessage &msg);


struct VerAckMessage : Message {
	static constexpr char command[12] = "verack";
};


struct AddrMessage : Message {
	static constexpr char command[12] = "addr";

	struct AddressWithTimestamp {
		le<uint32_t> timestamp;
		NetworkAddress address;
	};
	std::vector<AddressWithTimestamp> addr_list;
};

Source & operator >> (Source &source, AddrMessage &msg);
Sink & operator << (Sink &sink, const AddrMessage &msg);
std::ostream & operator << (std::ostream &os, const AddrMessage &msg);


struct InvMessage : Message {
	static constexpr char command[12] = "inv";

	std::vector<InventoryVector> inventory;
};

Source & operator >> (Source &source, InvMessage &msg);
Sink & operator << (Sink &sink, const InvMessage &msg);
std::ostream & operator << (std::ostream &os, const InvMessage &msg);


struct GetDataMessage : InvMessage {
	static constexpr char command[12] = "getdata";
};


struct NotFoundMessage : InvMessage {
	static constexpr char command[12] = "notfound";
};


struct GetBlocksMessage : Message {
	static constexpr char command[12] = "getblocks";

	le<uint32_t> version;
	std::vector<digest256_t> block_locator_hashes;
	digest256_t hash_stop;
};

Source & operator >> (Source &source, GetBlocksMessage &msg);
Sink & operator << (Sink &sink, const GetBlocksMessage &msg);
std::ostream & operator << (std::ostream &os, const GetBlocksMessage &msg);


struct GetHeadersMessage : GetBlocksMessage {
	static constexpr char command[12] = "getheaders";
};


struct TxMessage : Message, Tx {
	static constexpr char command[12] = "tx";
};

static inline Source & operator >> (Source &source, TxMessage &msg) { return source >> static_cast<Tx &>(msg); }
static inline Sink & operator << (Sink &sink, const TxMessage &msg) { return sink << static_cast<const Tx &>(msg); }
static inline std::ostream & operator << (std::ostream &os, const TxMessage &msg) { return os << static_cast<const Tx &>(msg); }


struct BlockMessage : Message, BlockHeader {
	static constexpr char command[12] = "block";

	std::vector<Tx> txns;
};

Source & operator >> (Source &source, BlockMessage &msg);
Sink & operator << (Sink &sink, const BlockMessage &msg);
std::ostream & operator << (std::ostream &os, const BlockMessage &msg);


struct HeadersMessage : Message {
	static constexpr char command[12] = "headers";

	std::vector<BlockHeader> headers;
};

Source & operator >> (Source &source, HeadersMessage &msg);
Sink & operator << (Sink &sink, const HeadersMessage &msg);
std::ostream & operator << (std::ostream &os, const HeadersMessage &msg);


struct GetAddrMessage : Message {
	static constexpr char command[12] = "getaddr";
};


struct MemPoolMessage : Message {
	static constexpr char command[12] = "mempool";
};


struct PingMessage : Message {
	static constexpr char command[12] = "ping";

	le<uint64_t> nonce;
};

Source & operator >> (Source &source, PingMessage &msg);
Sink & operator << (Sink &sink, const PingMessage &msg);
std::ostream & operator << (std::ostream &os, const PingMessage &msg);


struct PongMessage : PingMessage {
	static constexpr char command[12] = "pong";
};


struct RejectMessage : Message {
	static constexpr char command[12] = "reject";

	std::string message;
	enum class CCode : uint8_t {
		REJECT_MALFORMED = 0x01,
		REJECT_INVALID = 0x10,
		REJECT_OBSOLETE = 0x11,
		REJECT_DUPLICATE = 0x12,
		REJECT_NONSTANDARD = 0x40,
		REJECT_DUST = 0x41,
		REJECT_INSUFFICIENTFEE = 0x42,
		REJECT_CHECKPOINT = 0x43,
	} ccode;
	std::string reason;
	std::vector<uint8_t> data;
};

LimitedSource & operator >> (LimitedSource &source, RejectMessage &msg);
Sink & operator << (Sink &sink, const RejectMessage &msg);
std::ostream & operator << (std::ostream &os, const RejectMessage &msg);


struct FilterLoadMessage : Message {
	static constexpr char command[12] = "filterload";

	BloomFilter filter;
	enum class Flags : uint8_t {
		BLOOM_UPDATE_NONE = 0,
		BLOOM_UPDATE_ALL = 1 << 0,
		BLOOM_UPDATE_P2PUBKEY_ONLY = 1 << 1,
	} nFlags;
};
DEFINE_ENUM_FLAG_OPS(FilterLoadMessage::Flags)

Source & operator >> (Source &source, FilterLoadMessage &msg);
Sink & operator << (Sink &sink, const FilterLoadMessage &msg);
std::ostream & operator << (std::ostream &os, const FilterLoadMessage &msg);


struct FilterAddMessage : Message {
	static constexpr char command[12] = "filteradd";

	std::vector<uint8_t> data;
};

Source & operator >> (Source &source, FilterAddMessage &msg);
Sink & operator << (Sink &sink, const FilterAddMessage &msg);
std::ostream & operator << (std::ostream &os, const FilterAddMessage &msg);


struct FilterClearMessage : Message {
	static constexpr char command[12] = "filterclear";
};


struct MerkleBlockMessage : Message, BlockHeader {
	static constexpr char command[12] = "merkleblock";

	le<uint32_t> total_transactions;
	std::vector<digest256_t> hashes;
	std::vector<uint8_t> flags;
};

Source & operator >> (Source &source, MerkleBlockMessage &msg);
Sink & operator << (Sink &sink, const MerkleBlockMessage &msg);
std::ostream & operator << (std::ostream &os, const MerkleBlockMessage &msg);


struct AlertMessage : Message {
	static constexpr char command[12] = "alert";

	std::vector<uint8_t> payload;
	std::vector<uint8_t> signature;
};

Source & operator >> (Source &source, AlertMessage &msg);
Sink & operator << (Sink &sink, const AlertMessage &msg);
std::ostream & operator << (std::ostream &os, const AlertMessage &msg);


struct AlertPayload {
	le<uint32_t> version;
	le<int64_t> relay_until;
	le<int64_t> expiration;
	le<uint32_t> id;
	le<uint32_t> cancel;
	std::vector<le<uint32_t>> set_cancel;
	le<uint32_t> min_ver;
	le<uint32_t> max_ver;
	std::vector<std::string> set_sub_ver;
	le<uint32_t> priority;
	std::string comment;
	std::string status_bar;
	std::string reserved;
};

Source & operator >> (Source &source, AlertPayload &payload);
Sink & operator << (Sink &sink, const AlertPayload &payload);
std::ostream & operator << (std::ostream &os, const AlertPayload &msg);


struct UnsupportedMessage : Message {
	std::vector<uint8_t> data;
};

Source & operator >> (LimitedSource &source, UnsupportedMessage &msg);
Sink & operator << (Sink &sink, const UnsupportedMessage &msg);
std::ostream & operator << (std::ostream &os, const UnsupportedMessage &msg);


} // namespace satoshi
