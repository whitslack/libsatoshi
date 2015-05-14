#include "satoshi.h"
#include "common/socket.h"


namespace satoshi {


class Node {

public:
	static constexpr uint32_t protocol_version = 70001;

private:
	MessageHeader::Magic magic_le;
	Socket socket;

public:
	Node(MessageHeader::Magic magic, Socket &&socket) : magic_le(htole(magic)), socket(std::move(socket)) { }

public:
	void init_version_message(VersionMessage &msg) const;

	void run() _noreturn;

protected:
	template <typename M>
	void send(const M &msg);

	virtual void dispatch(const VersionMessage &) { }
	virtual void dispatch(const VerAckMessage &) { }
	virtual void dispatch(const AddrMessage &) { }
	virtual void dispatch(const InvMessage &) { }
	virtual void dispatch(const GetDataMessage &) { }
	virtual void dispatch(const NotFoundMessage &) { }
	virtual void dispatch(const GetBlocksMessage &) { }
	virtual void dispatch(const GetHeadersMessage &) { }
	virtual void dispatch(const TxMessage &) { }
	virtual void dispatch(const BlockMessage &) { }
	virtual void dispatch(const HeadersMessage &) { }
	virtual void dispatch(const GetAddrMessage &) { }
	virtual void dispatch(const MemPoolMessage &) { }
	virtual void dispatch(const PingMessage &) { }
	virtual void dispatch(const PongMessage &) { }
	virtual void dispatch(const RejectMessage &) { }
	virtual void dispatch(const FilterLoadMessage &) { }
	virtual void dispatch(const FilterAddMessage &) { }
	virtual void dispatch(const FilterClearMessage &) { }
	virtual void dispatch(const MerkleBlockMessage &) { }
	virtual void dispatch(const AlertMessage &) { }
	virtual void dispatch(const UnsupportedMessage &) { }

private:
	template <typename M>
	M receive(Source &source, const MessageHeader &hdr);

};


} // namespace satoshi
