#include "script.h"

#include <iomanip>
#include <iostream>

#include "common/serial.h"


namespace satoshi {


size_t Script::Iterator::size() const {
	auto itr = this->itr;
	if (*itr <= 0x4B) {
		return *itr;
	}
	switch (static_cast<Opcode>(*itr)) {
		case OP_PUSHDATA1:
			return *++itr;
		case OP_PUSHDATA2:
			return be16toh(*reinterpret_cast<const uint16_t *>(&*++itr));
		case OP_PUSHDATA4:
			return be32toh(*reinterpret_cast<const uint32_t *>(&*++itr));
		default:
			return 0;
	}
}

std::vector<uint8_t>::const_iterator Script::Iterator::begin() const {
	auto itr = this->itr;
	switch (static_cast<Opcode>(*itr)) {
		case OP_PUSHDATA1:
			return itr + 2;
		case OP_PUSHDATA2:
			return itr + 3;
		case OP_PUSHDATA4:
			return itr + 5;
		default:
			return itr + 1;
	}
}

intmax_t Script::Iterator::intval() const {
	switch (this->opcode()) {
#define _(v) case OP_##v: return v;
		_(0) _(1) _(2) _(3) _(4) _(5) _(6) _(7) _(8)
		_(9) _(10) _(11) _(12) _(13) _(14) _(15) _(16)
#undef _
		case OP_1NEGATE:
			return -1;
		default: {
			auto data = this->data();
			switch (this->size()) {
				case 0:
					return 0;
				case 1: {
					int8_t v = *data;
					return v < 0 ? -0x80 - v : v;
				}
				case 2: {
					int16_t v = le16toh(*reinterpret_cast<const uint16_t *>(data));
					return v < 0 ? -0x8000 - v : v;
				}
				case 3: {
					int32_t v = le16toh(*reinterpret_cast<const uint16_t *>(data)) | data[2] << 16;
					return v & 0x800000 ? -0x800000 - v : v;
				}
				case 4: {
					int32_t v = le32toh(*reinterpret_cast<const uint32_t *>(data));
					return v < 0 ? -0x80000000 - v : v;
				}
				case 5: {
					int64_t v = le32toh(*reinterpret_cast<const uint32_t *>(data)) | static_cast<uint64_t>(data[4]) << 32;
					return v & UINT64_C(0x8000000000) ? INT64_C(-0x8000000000) - v : v;
				}
				case 6: {
					int64_t v = le32toh(*reinterpret_cast<const uint32_t *>(data)) | static_cast<uint64_t>(le16toh(*reinterpret_cast<const uint16_t *>(data + 4))) << 32;
					return v & UINT64_C(0x800000000000) ? INT64_C(-0x800000000000) - v : v;
				}
				case 7: {
					int64_t v = le32toh(*reinterpret_cast<const uint32_t *>(data)) | static_cast<uint64_t>(le16toh(*reinterpret_cast<const uint16_t *>(data + 4))) << 32 | static_cast<uint64_t>(data[6]) << 48;
					return v & UINT64_C(0x80000000000000) ? INT64_C(-0x80000000000000) - v : v;
				}
				default: {
					int64_t v = le64toh(*reinterpret_cast<const uint64_t *>(data));
					return v < 0 ? INT64_C(-0x8000000000000000) - v : v;
				}
			}
		}
	}
}


bool Script::valid() const {
	auto end = script.end();
	for (auto itr = this->begin(); itr != this->end(); ++itr) {
		auto begin = itr.begin();
		if (begin > end || itr.size() > static_cast<size_t>(end - begin)) {
			return false;
		}
	}
	return true;
}

void Script::push_int(intmax_t value) {
	switch (value) {
#define _(v) case v: this->push_opcode(OP_##v); break;
		_(0) _(1) _(2) _(3) _(4) _(5) _(6) _(7) _(8)
		_(9) _(10) _(11) _(12) _(13) _(14) _(15) _(16)
#undef _
		case -1:
			this->push_opcode(OP_1NEGATE);
			break;
		default: {
			bool negate = value < 0;
			if (negate) {
				value = -value;
			}
			if (value < 0x80) {
				uint8_t v = static_cast<uint8_t>(value);
				this->push_data(&v, 1);
			}
			else if (value < 0x8000) {
				uint16_t v = htole16(static_cast<uint16_t>(value));
				this->push_data(&v, 2);
			}
			else if (value < 0x80000000) {
				uint32_t v = htole32(static_cast<uint32_t>(value));
				this->push_data(&v, value < 0x800000 ? 3 : 4);
			}
			else {
				uint64_t v = htole64(static_cast<uint64_t>(value));
				this->push_data(&v, value < INT64_C(0x800000000000) ? value < INT64_C(0x8000000000) ? 5 : 6 : value < INT64_C(0x80000000000000) ? 7 : 8);
			}
			if (negate) {
				script.back() |= 0x80;
			}
		}
	}
}

void Script::push_data(const void *data, size_t size) {
	if (size <= 0x4B) {
		this->push_opcode(static_cast<Opcode>(size));
	}
	else if (size <= UINT8_MAX) {
		this->push_opcode(OP_PUSHDATA1);
		script.push_back(static_cast<uint8_t>(size));
	}
	else if (size <= UINT16_MAX) {
		this->push_opcode(OP_PUSHDATA2);
		uint16_t n = htobe16(static_cast<uint16_t>(size));
		script.insert(script.end(), reinterpret_cast<uint8_t *>(&n), reinterpret_cast<uint8_t *>(&n + 1));
	}
#if SIZE_MAX > UINT32_MAX
	else if (size > UINT32_MAX) {
		throw std::length_error("data is too large");
	}
#endif
	else {
		this->push_opcode(OP_PUSHDATA4);
		uint32_t n = htobe32(static_cast<uint32_t>(size));
		script.insert(script.end(), reinterpret_cast<uint8_t *>(&n), reinterpret_cast<uint8_t *>(&n + 1));
	}
	script.insert(script.end(), static_cast<const uint8_t *>(data), static_cast<const uint8_t *>(data) + size);
}


Source & operator >> (Source &source, Script &script) {
	return source >> script.script;
}

Sink & operator << (Sink &sink, const Script &script) {
	return sink << script.script;
}

std::ostream & operator << (std::ostream &os, Script::Opcode opcode) {
	switch (opcode) {
#define _(o) case Script::o: return os << #o;
		_(OP_0)
		_(OP_PUSHDATA1)
		_(OP_PUSHDATA2)
		_(OP_PUSHDATA4)
		_(OP_1NEGATE)
		_(OP_RESERVED)
		_(OP_1) _(OP_2) _(OP_3) _(OP_4) _(OP_5) _(OP_6) _(OP_7) _(OP_8)
		_(OP_9) _(OP_10) _(OP_11) _(OP_12) _(OP_13) _(OP_14) _(OP_15) _(OP_16)
		_(OP_NOP)
		_(OP_VER)
		_(OP_IF)
		_(OP_NOTIF)
		_(OP_VERIF)
		_(OP_VERNOTIF)
		_(OP_ELSE)
		_(OP_ENDIF)
		_(OP_VERIFY)
		_(OP_RETURN)
		_(OP_TOALTSTACK)
		_(OP_FROMALTSTACK)
		_(OP_2DROP)
		_(OP_2DUP)
		_(OP_3DUP)
		_(OP_2OVER)
		_(OP_2ROT)
		_(OP_2SWAP)
		_(OP_IFDUP)
		_(OP_DEPTH)
		_(OP_DROP)
		_(OP_DUP)
		_(OP_NIP)
		_(OP_OVER)
		_(OP_PICK)
		_(OP_ROLL)
		_(OP_ROT)
		_(OP_SWAP)
		_(OP_TUCK)
		_(OP_CAT)
		_(OP_SUBSTR)
		_(OP_LEFT)
		_(OP_RIGHT)
		_(OP_SIZE)
		_(OP_INVERT)
		_(OP_AND)
		_(OP_OR)
		_(OP_XOR)
		_(OP_EQUAL)
		_(OP_EQUALVERIFY)
		_(OP_RESERVED1)
		_(OP_RESERVED2)
		_(OP_1ADD)
		_(OP_1SUB)
		_(OP_2MUL)
		_(OP_2DIV)
		_(OP_NEGATE)
		_(OP_ABS)
		_(OP_NOT)
		_(OP_0NOTEQUAL)
		_(OP_ADD)
		_(OP_SUB)
		_(OP_MUL)
		_(OP_DIV)
		_(OP_MOD)
		_(OP_LSHIFT)
		_(OP_RSHIFT)
		_(OP_BOOLAND)
		_(OP_BOOLOR)
		_(OP_NUMEQUAL)
		_(OP_NUMEQUALVERIFY)
		_(OP_NUMNOTEQUAL)
		_(OP_LESSTHAN)
		_(OP_GREATERTHAN)
		_(OP_LESSTHANOREQUAL)
		_(OP_GREATERTHANOREQUAL)
		_(OP_MIN)
		_(OP_MAX)
		_(OP_WITHIN)
		_(OP_RIPEMD160)
		_(OP_SHA1)
		_(OP_SHA256)
		_(OP_HASH160)
		_(OP_HASH256)
		_(OP_CODESEPARATOR)
		_(OP_CHECKSIG)
		_(OP_CHECKSIGVERIFY)
		_(OP_CHECKMULTISIG)
		_(OP_CHECKMULTISIGVERIFY)
		_(OP_NOP1) _(OP_NOP2) _(OP_NOP3) _(OP_NOP4) _(OP_NOP5)
		_(OP_NOP6) _(OP_NOP7) _(OP_NOP8) _(OP_NOP9) _(OP_NOP10)
		_(OP_SMALLDATA)
		_(OP_SMALLINTEGER)
		_(OP_PUBKEYS)
		_(OP_PUBKEYHASH)
		_(OP_PUBKEY)
		_(OP_INVALIDOPCODE)
#undef _
	}
	auto orig_flags = os.flags(std::ios_base::hex | std::ios_base::internal | std::ios_base::showbase);
	auto orig_fill = os.fill('0');
	os << std::setw(4) << static_cast<uint>(opcode);
	os.fill(orig_fill);
	os.flags(orig_flags);
	return os;
}

std::ostream & operator << (std::ostream &os, const Script &script) {
	if (!script.valid()) {
		return os << "(invalid)";
	}
	auto orig_flags = os.flags(std::ios_base::dec | std::ios_base::right);
	auto orig_fill = os.fill('0');
	for (auto itr = script.begin(); itr != script.end(); ++itr) {
		if (itr != script.begin()) {
			os << ' ';
		}
		auto opcode = itr.opcode();
		switch (opcode) {
#define _(v) case Script::OP_##v: os << v; break;
			_(0) _(1) _(2) _(3) _(4) _(5) _(6) _(7) _(8)
			_(9) _(10) _(11) _(12) _(13) _(14) _(15) _(16)
#undef _
			case Script::OP_1NEGATE:
				os << -1;
				break;
			default: {
				auto size = itr.size();
				if (size > 0) {
					os << std::hex << "0x";
					for (auto b : itr) {
						os << std::setw(2) << static_cast<uint>(b);
					}
					os << std::dec;
				}
				else {
					os << itr.opcode();
				}
			}
		}
	}
	os.fill(orig_fill);
	os.flags(orig_flags);
	return os;
}


} // namespace satoshi
