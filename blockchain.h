#pragma once

#include <iosfwd>

#include "script.h"
#include "types.h"
#include "common/endian.h"


namespace satoshi {


struct OutPoint {
	digest256_t tx_hash;
	le<uint32_t> txout_idx;
};

bool operator < (const OutPoint &lhs, const OutPoint &rhs) _pure;
std::ostream & operator << (std::ostream &os, const OutPoint &outpoint);


struct TxIn {
	OutPoint prevout;
	Script script;
	le<uint32_t> seq_num;
};

Source & operator >> (Source &source, TxIn &txin);
Sink & operator << (Sink &sink, const TxIn &txin);
std::ostream & operator << (std::ostream &os, const TxIn &txin);


struct TxOut {
	le<uint64_t> amount;
	Script script;
};

Source & operator >> (Source & source, TxOut &txout);
Sink & operator << (Sink &sink, const TxOut &txout);
std::ostream & operator << (std::ostream &os, const TxOut &txout);


struct Tx {
	le<uint32_t> version;
	std::vector<TxIn> inputs;
	std::vector<TxOut> outputs;
	le<int32_t> lock_time;
};

Source & operator >> (Source &source, Tx &tx);
Sink & operator << (Sink &sink, const Tx &tx);
std::ostream & operator << (std::ostream &os, const Tx &tx);


struct BlockHeader {
	le<uint32_t> version;
	digest256_t parent_block_hash;
	digest256_t merkle_root_hash;
	le<uint32_t> time;
	le<uint32_t> bits;
	le<uint32_t> nonce;
};

Source & operator >> (Source &source, BlockHeader &hdr);
Sink & operator << (Sink &sink, const BlockHeader &hdr);
std::ostream & operator << (std::ostream &os, const BlockHeader &hdr);


} // namespace satoshi
