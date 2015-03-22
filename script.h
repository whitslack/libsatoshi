#include "common/io.h"


namespace satoshi {


class Script {
	friend Source & operator >> (Source &, Script &);
	friend Sink & operator << (Sink &, const Script &);

public:
	enum Opcode : uint8_t {
		// constants
		OP_0 = 0x00, OP_FALSE = OP_0,
		OP_PUSHDATA1 = 0x4C,
		OP_PUSHDATA2 = 0x4D,
		OP_PUSHDATA4 = 0x4E,
		OP_1NEGATE = 0x4F,
		OP_RESERVED = 0x50,
		OP_1 = 0x51, OP_TRUE = OP_1,
		OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_9,
		OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16,

		// flow control
		OP_NOP = 0x61,
		OP_VER = 0x62,
		OP_IF = 0x63,
		OP_NOTIF = 0x64,
		OP_VERIF = 0x65,
		OP_VERNOTIF = 0x66,
		OP_ELSE = 0x67,
		OP_ENDIF = 0x68,
		OP_VERIFY = 0x69,
		OP_RETURN = 0x6A,

		// stack
		OP_TOALTSTACK = 0x6B,
		OP_FROMALTSTACK = 0x6C,
		OP_2DROP = 0x6D,
		OP_2DUP = 0x6E,
		OP_3DUP = 0x6F,
		OP_2OVER = 0x70,
		OP_2ROT = 0x71,
		OP_2SWAP = 0x72,
		OP_IFDUP = 0x73,
		OP_DEPTH = 0x74,
		OP_DROP = 0x75,
		OP_DUP = 0x76,
		OP_NIP = 0x77,
		OP_OVER = 0x78,
		OP_PICK = 0x79,
		OP_ROLL = 0x7A,
		OP_ROT = 0x7B,
		OP_SWAP = 0x7C,
		OP_TUCK = 0x7D,

		// splice
		OP_CAT = 0x7E,
		OP_SUBSTR = 0x7F,
		OP_LEFT = 0x80,
		OP_RIGHT = 0x81,
		OP_SIZE = 0x82,

		// bitwise
		OP_INVERT = 0x83,
		OP_AND = 0x84,
		OP_OR = 0x85,
		OP_XOR = 0x86,
		OP_EQUAL = 0x87,
		OP_EQUALVERIFY = 0x88,
		OP_RESERVED1 = 0x89,
		OP_RESERVED2 = 0x8A,

		// arithmetic
		OP_1ADD = 0x8B,
		OP_1SUB = 0x8C,
		OP_2MUL = 0x8D,
		OP_2DIV = 0x8E,
		OP_NEGATE = 0x8F,
		OP_ABS = 0x90,
		OP_NOT = 0x91,
		OP_0NOTEQUAL = 0x92,
		OP_ADD = 0x93,
		OP_SUB = 0x94,
		OP_MUL = 0x95,
		OP_DIV = 0x96,
		OP_MOD = 0x97,
		OP_LSHIFT = 0x98,
		OP_RSHIFT = 0x99,
		OP_BOOLAND = 0x9A,
		OP_BOOLOR = 0x9B,
		OP_NUMEQUAL = 0x9C,
		OP_NUMEQUALVERIFY = 0x9D,
		OP_NUMNOTEQUAL = 0x9E,
		OP_LESSTHAN = 0x9F,
		OP_GREATERTHAN = 0xA0,
		OP_LESSTHANOREQUAL = 0xA1,
		OP_GREATERTHANOREQUAL = 0xA2,
		OP_MIN = 0xA3,
		OP_MAX = 0xA4,
		OP_WITHIN = 0xA5,

		// crypto
		OP_RIPEMD160 = 0xA6,
		OP_SHA1 = 0xA7,
		OP_SHA256 = 0xA8,
		OP_HASH160 = 0xA9,
		OP_HASH256 = 0xAA,
		OP_CODESEPARATOR = 0xAB,
		OP_CHECKSIG = 0xAC,
		OP_CHECKSIGVERIFY = 0xAD,
		OP_CHECKMULTISIG = 0xAE,
		OP_CHECKMULTISIGVERIFY = 0xAF,

		// expansion
		OP_NOP1 = 0xB0,
		OP_NOP2, OP_NOP3, OP_NOP4, OP_NOP5, OP_NOP6,
		OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10,

		// template matching
		OP_SMALLDATA = 0xF9,
		OP_SMALLINTEGER = 0xFA,
		OP_PUBKEYS = 0xFB,
		OP_PUBKEYHASH = 0xFD,
		OP_PUBKEY = 0xFE,
		OP_INVALIDOPCODE = 0xFF,
	};

	class Iterator {
		friend Script;
	private:
		std::vector<uint8_t>::const_iterator itr;
	private:
		explicit Iterator(std::vector<uint8_t>::const_iterator itr) : itr(itr) { }
	public:
		Opcode opcode() const { return static_cast<Opcode>(*itr); }
		const uint8_t * data() const { return &*this->begin(); }
		size_t size() const _pure;
		std::vector<uint8_t>::const_iterator begin() const _pure;
		std::vector<uint8_t>::const_iterator end() const { return this->begin() + this->size(); }
		std::vector<uint8_t>::const_reverse_iterator rbegin() const { return std::vector<uint8_t>::const_reverse_iterator(this->end()); }
		std::vector<uint8_t>::const_reverse_iterator rend() const { return std::vector<uint8_t>::const_reverse_iterator(this->begin()); }
		intmax_t intval() const _pure;
	public:
		Opcode operator * () const { return this->opcode(); }
		Iterator & operator ++ () { itr = this->end(); return *this; }
		bool operator == (const Iterator &o) const { return itr == o.itr; }
		bool operator != (const Iterator &o) const { return itr != o.itr; }
	};

private:
	std::vector<uint8_t> script;

public:
	template <typename... Args>
	explicit Script(Args&&... args) : script(std::forward<Args>(args)...) { }

public:
	const uint8_t * data() const { return script.data(); }
	size_t size() const { return script.size(); }
	Iterator begin() const { return Iterator(script.begin()); }
	Iterator end() const { return Iterator(script.end()); }

	void clear() { script.clear(); }
	void reserve(size_t capacity) { script.reserve(capacity); }
	void push_opcode(Opcode opcode) { script.push_back(opcode); }
	void push_int(intmax_t value);
	void push_data(const void *data, size_t size);
	void push_copy(Iterator itr) { script.insert(script.end(), itr.itr, itr.end()); }

};

Source & operator >> (Source &source, Script &script);
Sink & operator << (Sink &sink, const Script &script);

std::ostream & operator << (std::ostream &os, Script::Opcode opcode);
std::ostream & operator << (std::ostream &os, const Script &script);


} // namespace satoshi
