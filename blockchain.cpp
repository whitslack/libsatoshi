#include "blockchain.h"

#include <ctime>

#include "common/serial.h"


namespace satoshi {


bool operator < (const OutPoint &lhs, const OutPoint &rhs) {
	return lhs.tx_hash < rhs.tx_hash || lhs.tx_hash == rhs.tx_hash && lhs.txout_idx < rhs.txout_idx;
}

std::ostream & operator << (std::ostream &os, const OutPoint &outpoint) {
	return print_digest_le(os << "{ .tx_hash = ", outpoint.tx_hash) << ", .txout_idx = " << outpoint.txout_idx << " }";
}


Source & operator >> (Source &source, TxIn &txin) {
	return source >> txin.prevout >> txin.script >> txin.seq_num;
}

Sink & operator << (Sink &sink, const TxIn &txin) {
	return sink << txin.prevout << txin.script << txin.seq_num;
}

std::ostream & operator << (std::ostream &os, const TxIn &txin) {
	return os << "{ .prevout = " << txin.prevout << ", .script = [ " << txin.script << " ], .seq_num = " << txin.seq_num << " }";
}


Source & operator >> (Source &source, TxOut &txout) {
	return source >> txout.amount >> txout.script;
}

Sink & operator << (Sink &sink, const TxOut &txout) {
	return sink << txout.amount << txout.script;
}

std::ostream & operator << (std::ostream &os, const TxOut &txout) {
	return os << "{ .amount = " << txout.amount << ", .script = [ " << txout.script << " ] }";
}


Source & operator >> (Source &source, Tx &tx) {
	return source >> tx.version >> tx.inputs >> tx.outputs >> tx.lock_time;
}

Sink & operator << (Sink &sink, const Tx &tx) {
	return sink << tx.version << tx.inputs << tx.outputs << tx.lock_time;
}

std::ostream & operator << (std::ostream &os, const Tx &tx) {
	using ::operator <<;
	return os << "{ .version = " << tx.version << ", .inputs = " << tx.inputs << ", .outputs = " << tx.outputs << ", .lock_time = " << tx.lock_time << " }";
}


Source & operator >> (Source &source, BlockHeader &hdr) {
	return source >> hdr.version >> hdr.parent_block_hash >> hdr.merkle_root_hash >> hdr.time >> hdr.bits >> hdr.nonce;
}

Sink & operator << (Sink &sink, const BlockHeader &hdr) {
	return sink << hdr.version << hdr.parent_block_hash << hdr.merkle_root_hash << hdr.time << hdr.bits << hdr.nonce;
}

std::ostream & operator << (std::ostream &os, const BlockHeader &hdr) {
	using ::operator <<;
	auto time = static_cast<std::time_t>(letoh(hdr.time));
	return print_digest_le(print_digest_le(os << "{ .version = " << hdr.version << ", .parent_block_hash = ", hdr.parent_block_hash) << ", .merkle_root_hash = ", hdr.merkle_root_hash) << ", .time = " << time << " (" << std::chrono::system_clock::from_time_t(time) << "), .bits = " << compact_to_double(hdr.bits) << ", .nonce = " << hdr.nonce << " }";
}


} // namespace satoshi
