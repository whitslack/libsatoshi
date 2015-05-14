#include "blockchain.h"

#include <ctime>

#include "common/serial.h"


namespace satoshi {


bool operator < (const OutPoint &lhs, const OutPoint &rhs) {
	return lhs.tx_hash < rhs.tx_hash || lhs.tx_hash == rhs.tx_hash && letoh(lhs.txout_idx_le) < letoh(rhs.txout_idx_le);
}

std::ostream & operator << (std::ostream &os, const OutPoint &outpoint) {
	return print_digest_le(os << "{ .tx_hash = ", outpoint.tx_hash) << ", .txout_idx = " << letoh(outpoint.txout_idx_le) << " }";
}


Source & operator >> (Source &source, TxIn &txin) {
	return source >> txin.prevout >> txin.script >> txin.seq_num_le;
}

Sink & operator << (Sink &sink, const TxIn &txin) {
	return sink << txin.prevout << txin.script << txin.seq_num_le;
}

std::ostream & operator << (std::ostream &os, const TxIn &txin) {
	return os << "{ .prevout = " << txin.prevout << ", .script = [ " << txin.script << " ], .seq_num = " << letoh(txin.seq_num_le) << " }";
}


Source & operator >> (Source &source, TxOut &txout) {
	return source >> txout.amount_le >> txout.script;
}

Sink & operator << (Sink &sink, const TxOut &txout) {
	return sink << txout.amount_le << txout.script;
}

std::ostream & operator << (std::ostream &os, const TxOut &txout) {
	return os << "{ .amount = " << letoh(txout.amount_le) << ", .script = [ " << txout.script << " ] }";
}


Source & operator >> (Source &source, Tx &tx) {
	return source >> tx.version_le >> tx.inputs >> tx.outputs >> tx.lock_time_le;
}

Sink & operator << (Sink &sink, const Tx &tx) {
	return sink << tx.version_le << tx.inputs << tx.outputs << tx.lock_time_le;
}

std::ostream & operator << (std::ostream &os, const Tx &tx) {
	using ::operator <<;
	return os << "{ .version = " << letoh(tx.version_le) << ", .inputs = " << tx.inputs << ", .outputs = " << tx.outputs << ", .lock_time = " << letoh(tx.lock_time_le) << " }";
}


Source & operator >> (Source &source, BlockHeader &hdr) {
	return source >> hdr.version_le >> hdr.parent_block_hash >> hdr.merkle_root_hash >> hdr.time_le >> hdr.bits_le >> hdr.nonce;
}

Sink & operator << (Sink &sink, const BlockHeader &hdr) {
	return sink << hdr.version_le << hdr.parent_block_hash << hdr.merkle_root_hash << hdr.time_le << hdr.bits_le << hdr.nonce;
}

std::ostream & operator << (std::ostream &os, const BlockHeader &hdr) {
	using ::operator <<;
	auto time = static_cast<std::time_t>(letoh(hdr.time_le));
	return print_digest_le(print_digest_le(os << "{ .version = " << letoh(hdr.version_le) << ", .parent_block_hash = ", hdr.parent_block_hash) << ", .merkle_root_hash = ", hdr.merkle_root_hash) << ", .time = " << time << " (" << std::chrono::system_clock::from_time_t(time) << "), .bits = " << compact_to_double(letoh(hdr.bits_le)) << ", .nonce = " << hdr.nonce << " }";
}


} // namespace satoshi
