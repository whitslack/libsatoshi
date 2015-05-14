#include "node.h"

#include <chrono>
#include <iosfwd>

#include "common/log.h"
#include "common/narrow.h"
#include "common/serial.h"
#include "common/sha.h"

extern Log elog;


namespace satoshi {


static void sockaddr_to_NetworkAddress(NetworkAddress &na, const sockaddr &sa) {
	switch (sa.sa_family) {
		case AF_INET: {
			auto &sai = reinterpret_cast<const sockaddr_in &>(sa);
			std::memset(na.addr.s6_addr, 0, 8);
			na.addr.s6_addr32[2] = htobe(0xFFFF);
			std::memcpy(na.addr.s6_addr + 12, &sai.sin_addr, 4);
			na.port_be = sai.sin_port;
			break;
		}
		case AF_INET6: {
			auto &sai6 = reinterpret_cast<const sockaddr_in6 &>(sa);
			std::memcpy(&na.addr, &sai6.sin6_addr, sizeof na.addr);
			na.port_be = sai6.sin6_port;
			break;
		}
		default:
			std::memset(&na.addr, 0, sizeof na.addr);
			na.port_be = 0;
			break;
	}
}


void Node::init_version_message(VersionMessage &msg) const {
	msg.version_le = htole(protocol_version);
	msg.services_le = { };
	msg.timestamp_le = htole(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
	union {
		sockaddr sa;
		sockaddr_in sai;
		sockaddr_in6 sai6;
	} addr;
	socklen_t addr_len = static_cast<socklen_t>(sizeof addr);
	this->socket.getpeername(&addr.sa, &addr_len);
	sockaddr_to_NetworkAddress(msg.addr_recv, addr.sa);
	msg.addr_recv.services_le = htole(Services::NODE_NETWORK);
	addr_len = static_cast<socklen_t>(sizeof addr);
	msg.addr_from.addr = in6addr_any;
	msg.addr_from.port_be = 0;
	msg.addr_from.services_le = msg.services_le;
	msg.nonce = std::chrono::steady_clock::now().time_since_epoch().count();
	msg.start_height_le = htole(-1);
	msg.relay = true;
}

void Node::run() {
	BufferedSource<3072> source(socket);
	for (;;) {
		MessageHeader hdr;
		source >> hdr;
		if (hdr.magic_le != magic_le) {
			throw std::ios_base::failure("received message has incorrect magic value");
		}
		switch (hdr.command[0]) {
			case 'a':
				switch (hdr.command[1]) {
					case 'd': // ad
						if (std::memcmp(hdr.command + 2, AddrMessage::command + 2, 12 - 2) == 0) { // addr
							this->dispatch(this->receive<AddrMessage>(source, hdr));
							continue;
						}
						break;
					case 'l': // al
						if (std::memcmp(hdr.command + 2, AlertMessage::command + 2, 12 - 2) == 0) { // alert
							this->dispatch(this->receive<AlertMessage>(source, hdr));
							continue;
						}
						break;
				}
				break;
			case 'b':
				if (std::memcmp(hdr.command + 1, BlockMessage::command + 1, 12 - 1) == 0) { // block
					this->dispatch(this->receive<BlockMessage>(source, hdr));
					continue;
				}
				break;
			case 'f':
				if (std::memcmp(hdr.command + 1, FilterAddMessage::command + 1, 5) == 0) { // filter
					switch (hdr.command[6]) {
						case 'a': // filtera
							if (std::memcmp(hdr.command + 7, FilterAddMessage::command + 7, 12 - 7) == 0) { // filteradd
								this->dispatch(this->receive<FilterAddMessage>(source, hdr));
								continue;
							}
							break;
						case 'c': // filterc
							if (std::memcmp(hdr.command + 7, FilterClearMessage::command + 7, 12 - 7) == 0) { // filterclear
								this->dispatch(this->receive<FilterClearMessage>(source, hdr));
								continue;
							}
							break;
						case 'l': // filterl
							if (std::memcmp(hdr.command + 7, FilterLoadMessage::command + 7, 12 - 7) == 0) { // filterload
								this->dispatch(this->receive<FilterLoadMessage>(source, hdr));
								continue;
							}
							break;
					}
				}
				break;
			case 'g':
				if (std::memcmp(hdr.command + 1, GetAddrMessage::command + 1, 2) == 0) { // get
					switch (hdr.command[3]) {
						case 'a': // geta
							if (std::memcmp(hdr.command + 4, GetAddrMessage::command + 4, 12 - 4) == 0) { // getaddr
								this->dispatch(this->receive<GetAddrMessage>(source, hdr));
								continue;
							}
							break;
						case 'b': // getb
							if (std::memcmp(hdr.command + 4, GetBlocksMessage::command + 4, 12 - 4) == 0) { // getblocks
								this->dispatch(this->receive<GetBlocksMessage>(source, hdr));
								continue;
							}
							break;
						case 'd': // getd
							if (std::memcmp(hdr.command + 4, GetDataMessage::command + 4, 12 - 4) == 0) { // getdata
								this->dispatch(this->receive<GetDataMessage>(source, hdr));
								continue;
							}
							break;
						case 'h': // geth
							if (std::memcmp(hdr.command + 4, GetHeadersMessage::command + 4, 12 - 4) == 0) { // getheaders
								this->dispatch(this->receive<GetHeadersMessage>(source, hdr));
								continue;
							}
							break;
					}
				}
				break;
			case 'h':
				if (std::memcmp(hdr.command + 1, HeadersMessage::command + 1, 12 - 1) == 0) { // headers
					this->dispatch(this->receive<HeadersMessage>(source, hdr));
					continue;
				}
				break;
			case 'i':
				if (std::memcmp(hdr.command + 1, InvMessage::command + 1, 12 - 1) == 0) { // inv
					this->dispatch(this->receive<InvMessage>(source, hdr));
					continue;
				}
				break;
			case 'm':
				if (hdr.command[1] == 'e') { // me
					switch (hdr.command[2]) {
						case 'm': // mem
							if (std::memcmp(hdr.command + 3, MemPoolMessage::command + 3, 12 - 3) == 0) { // mempool
								this->dispatch(this->receive<MemPoolMessage>(source, hdr));
								continue;
							}
							break;
						case 'r': // mer
							if (std::memcmp(hdr.command + 3, MerkleBlockMessage::command + 3, 12 - 3) == 0) { // merkleblock
								this->dispatch(this->receive<MerkleBlockMessage>(source, hdr));
								continue;
							}
							break;
					}
				}
				break;
			case 'n':
				if (std::memcmp(hdr.command + 1, NotFoundMessage::command + 1, 12 - 1) == 0) { // notfound
					this->dispatch(this->receive<NotFoundMessage>(source, hdr));
					continue;
				}
				break;
			case 'p':
				switch (hdr.command[1]) {
					case 'i': // pi
						if (std::memcmp(hdr.command + 2, PingMessage::command + 2, 12 - 2) == 0) { // ping
							this->dispatch(this->receive<PingMessage>(source, hdr));
							continue;
						}
						break;
					case 'o': // po
						if (std::memcmp(hdr.command + 2, PongMessage::command + 2, 12 - 2) == 0) { // pong
							this->dispatch(this->receive<PongMessage>(source, hdr));
							continue;
						}
						break;
				}
				break;
			case 'r':
				if (std::memcmp(hdr.command + 1, RejectMessage::command + 1, 12 - 1) == 0) { // reject
					this->dispatch(this->receive<RejectMessage>(source, hdr));
					continue;
				}
				break;
			case 't':
				if (std::memcmp(hdr.command + 1, TxMessage::command + 1, 12 - 1) == 0) { // tx
					this->dispatch(this->receive<TxMessage>(source, hdr));
					continue;
				}
				break;
			case 'v':
				if (std::memcmp(hdr.command + 1, VerAckMessage::command + 1, 2) == 0) { // ver
					switch (hdr.command[3]) {
						case 'a': // vera
							if (std::memcmp(hdr.command + 4, VerAckMessage::command + 4, 12 - 4) == 0) { // verack
								this->dispatch(this->receive<VerAckMessage>(source, hdr));
								continue;
							}
							break;
						case 's': // vers
							if (std::memcmp(hdr.command + 4, VersionMessage::command + 4, 12 - 4) == 0) { // version
								this->dispatch(this->receive<VersionMessage>(source, hdr));
								continue;
							}
							break;
					}
				}
				break;
		}
		this->dispatch(this->receive<UnsupportedMessage>(source, hdr));
		if (elog.warn_enabled()) {
			elog.warn() << "received unsupported message: \"" << std::string(hdr.command, 12).c_str() << '"' << std::endl;
		}
	}
}

template <typename M>
void Node::send(const M &msg) {
	struct _hidden CountingSHA256 : SHA256 {
		size_t length;
		CountingSHA256() : length() { }
		size_t write(const void *buf, size_t n) override { length += n = this->SHA256::write(buf, n); return n; }
	} isha;
	isha << msg;
	SHA256 osha;
	osha << isha.digest();
	MessageHeader hdr;
	hdr.magic_le = magic_le;
	std::memcpy(hdr.command, M::command, sizeof hdr.command);
	auto length = narrow_check<uint32_t>(isha.length - 1);
	hdr.length_le = htole(length);
	hdr.checksum = *reinterpret_cast<const uint32_t *>(osha.digest().data());
	if (elog.trace_enabled()) {
		elog.trace() << "sending " << std::string(hdr.command, sizeof hdr.command).c_str() << " (" << sizeof hdr + length << " bytes) " << msg << std::endl;
	}
	BufferedSink<3072> sink(socket);
	(sink << hdr << msg).flush_fully();
}

template void Node::send(const VersionMessage &);
template void Node::send(const VerAckMessage &);
template void Node::send(const AddrMessage &);
template void Node::send(const InvMessage &);
template void Node::send(const GetDataMessage &);
template void Node::send(const NotFoundMessage &);
template void Node::send(const GetBlocksMessage &);
template void Node::send(const GetHeadersMessage &);
template void Node::send(const TxMessage &);
template void Node::send(const BlockMessage &);
template void Node::send(const HeadersMessage &);
template void Node::send(const GetAddrMessage &);
template void Node::send(const MemPoolMessage &);
template void Node::send(const PingMessage &);
template void Node::send(const PongMessage &);
template void Node::send(const RejectMessage &);
template void Node::send(const FilterLoadMessage &);
template void Node::send(const FilterAddMessage &);
template void Node::send(const FilterClearMessage &);
template void Node::send(const MerkleBlockMessage &);
template void Node::send(const AlertMessage &);

template <typename M>
M Node::receive(Source &source, const MessageHeader &hdr) {
	SHA256 isha;
	Tap tap(source, isha);
	auto length = letoh(hdr.length_le);
	LimitedSource ls(tap, length);
	M msg;
	ls >> msg;
	if (ls.remaining != 0) {
		throw std::ios_base::failure("received message contains extraneous data");
	}
	SHA256 osha;
	osha << isha.digest();
	if (*reinterpret_cast<const uint32_t *>(osha.digest().data()) != hdr.checksum) {
		throw std::ios_base::failure("received message has incorrect checksum");
	}
	if (elog.trace_enabled()) {
		elog.trace() << "received " << std::string(hdr.command, sizeof hdr.command).c_str() << " (" << sizeof hdr + length << " bytes) " << msg << std::endl;
	}
	return msg;
}


} // namespace satoshi
