#include "blockchain.h"

#include "common/serial.h"


namespace satoshi {


Source & operator >> (Source &source, TxIn &txin) {
	return source >> txin.prevout_tx_hash >> txin.prevout_txout_idx_le >> txin.script >> txin.seq_num_le;
}

Sink & operator << (Sink &sink, const TxIn &txin) {
	return sink << txin.prevout_tx_hash << txin.prevout_txout_idx_le << txin.script << txin.seq_num_le;
}


Source & operator >> (Source &source, TxOut &txout) {
	return source >> txout.amount_le >> txout.script;
}

Sink & operator << (Sink &sink, const TxOut &txout) {
	return sink << txout.amount_le << txout.script;
}


Source & operator >> (Source &source, Tx &tx) {
	return source >> tx.version_le >> tx.inputs >> tx.outputs >> tx.lock_time_le;
}

Sink & operator << (Sink &sink, const Tx &tx) {
	return sink << tx.version_le << tx.inputs << tx.outputs << tx.lock_time_le;
}


Source & operator >> (Source &source, BlockHeader &hdr) {
	source >> hdr.version_le;
	uint32_t version = letoh(hdr.version_le);
	if (version == 0 || version > 3) {
		throw std::ios_base::failure("block version not supported");
	}
	return source >> hdr.parent_block_hash >> hdr.merkle_root_hash >> hdr.time_le >> hdr.bits_le >> hdr.nonce;
}

Sink & operator << (Sink &sink, const BlockHeader &hdr) {
	return sink << hdr.version_le << hdr.parent_block_hash << hdr.merkle_root_hash << hdr.time_le << hdr.bits_le << hdr.nonce;
}


} // namespace satoshi
