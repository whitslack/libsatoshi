#include <iosfwd>

#include "script.h"
#include "types.h"


namespace satoshi {


struct TxIn {
	digest256_t prevout_tx_hash;
	uint32_t prevout_txout_idx_le;
	Script script;
	uint32_t seq_num_le;
};

Source & operator >> (Source &source, TxIn &txin);
Sink & operator << (Sink &sink, const TxIn &txin);


struct TxOut {
	uint64_t amount_le;
	Script script;
};

Source & operator >> (Source & source, TxOut &txout);
Sink & operator << (Sink &sink, const TxOut &txout);


struct Tx {
	uint32_t version_le;
	std::vector<TxIn> inputs;
	std::vector<TxOut> outputs;
	int32_t lock_time_le;
};

Source & operator >> (Source &source, Tx &tx);
Sink & operator << (Sink &sink, const Tx &tx);


struct BlockHeader {
	uint32_t version_le;
	digest256_t parent_block_hash;
	digest256_t merkle_root_hash;
	uint32_t time_le;
	uint32_t bits_le;
	uint32_t nonce;
};

Source & operator >> (Source &source, BlockHeader &hdr);
Sink & operator << (Sink &sink, const BlockHeader &hdr);


} // namespace satoshi
