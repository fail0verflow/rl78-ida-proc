// Renesas RL78 processor module for IDA
// Based on R01US0015EJ0220, Rev.2.20, Nov 20, 2014

// In reality all registers are just references to memory locations.
// Pick the ones which are architecturally defined to be commonly used in
// instructions to list here, as well as those which IDA needs to track.
// The rest can be named via io naming.
enum RL78Register : decltype(op_t::reg) {
	rX, rA, rC, rB, rE, rD, rL, rH, rAX, rBC, rDE, rHL,
	rRB0, rRB1, rRB2, rRB3,
	rPSW, rSP,
	rCY,
	// Fake segreg to make IDA happy
	rVcs, rVds,
	// RL78 segregs we'll use IDA to track
	rCS, rES,
	r_count
};

static const char *const reg_names[] = {
	"x", "a", "c", "b", "e", "d", "l", "h", "ax", "bc", "de", "hl",
	"rb0", "rb1", "rb2", "rb3",
	"psw", "sp",
	"cy",
	"vcs", "vds",
	"cs", "es",
};
static_assert(qnumber(reg_names) == r_count, "array doesn't match enum");

enum : decltype(insn_t::itype) {
	RL78_unknown,
	RL78_mov,
	RL78_xch,
	RL78_oneb,
	RL78_clrb,
	RL78_movs,
	RL78_movw,
	RL78_xchw,
	RL78_onew,
	RL78_clrw,
	RL78_add,
	RL78_addc,
	RL78_sub,
	RL78_subc,
	RL78_and,
	RL78_or,
	RL78_xor,
	RL78_cmp,
	RL78_cmp0,
	RL78_cmps,
	RL78_addw,
	RL78_subw,
	RL78_cmpw,
	RL78_mulu,
	// S3 only
	RL78_mulhu,
	RL78_mulh,
	RL78_divhu,
	RL78_divwu,
	RL78_machu,
	RL78_mach,
	// S3 only end
	RL78_inc,
	RL78_dec,
	RL78_incw,
	RL78_decw,
	RL78_shr,
	RL78_shrw,
	RL78_shl,
	RL78_shlw,
	RL78_sar,
	RL78_sarw,
	RL78_ror,
	RL78_rol,
	RL78_rorc,
	RL78_rolc,
	RL78_rolwc,
	RL78_mov1,
	RL78_and1,
	RL78_or1,
	RL78_xor1,
	RL78_set1,
	RL78_clr1,
	RL78_not1,
	RL78_call,
	RL78_callt,
	RL78_brk,
	RL78_ret,
	RL78_reti,
	RL78_retb,
	RL78_push,
	RL78_pop,
	RL78_br,
	RL78_bc,
	RL78_bnc,
	RL78_bz,
	RL78_bnz,
	RL78_bh,
	RL78_bnh,
	RL78_bt,
	RL78_bf,
	RL78_btclr,
	RL78_skc,
	RL78_sknc,
	RL78_skz,
	RL78_sknz,
	RL78_skh,
	RL78_sknh,
	// sel is not on S1 (only one bank)
	RL78_sel,
	RL78_nop,
	RL78_ei,
	RL78_di,
	RL78_halt,
	RL78_stop,
	// not real opcode?
	RL78_brk1,
	RL78_itype_count
};

static const instruc_t instructions[] = {
	{ "" },
	{ "mov",	CF_CHG1 | CF_USE2 },
	{ "xch",	CF_CHG1 | CF_CHG2 },
	{ "oneb",	CF_CHG1 },
	{ "clrb",	CF_CHG1 },
	{ "movs",	CF_CHG1 | CF_USE2 },
	{ "movw",	CF_CHG1 | CF_USE2 },
	{ "xchw",	CF_CHG1 | CF_CHG2 },
	{ "onew",	CF_CHG1 },
	{ "clrw",	CF_CHG1 },
	{ "add",	CF_CHG1 | CF_USE2 },
	{ "addc",	CF_CHG1 | CF_USE2 },
	{ "sub",	CF_CHG1 | CF_USE2 },
	{ "subc",	CF_CHG1 | CF_USE2 },
	{ "and",	CF_CHG1 | CF_USE2 },
	{ "or",		CF_CHG1 | CF_USE2 },
	{ "xor",	CF_CHG1 | CF_USE2 },
	{ "cmp",	CF_USE1 | CF_USE2 },
	{ "cmp0",	CF_USE1 },
	{ "cmps",	CF_USE1 | CF_USE2 },
	{ "addw",	CF_CHG1 | CF_USE2 },
	{ "subw",	CF_CHG1 | CF_USE2 },
	{ "cmpw",	CF_USE1 | CF_USE2 },
	{ "mulu",	CF_USE1 },
	{ "mulhu",	 },
	{ "mulh",	 },
	{ "divhu",	 },
	{ "divwu",	 },
	{ "machu",	 },
	{ "mach",	 },
	{ "inc",	CF_CHG1 },
	{ "dec",	CF_CHG1 },
	{ "incw",	CF_CHG1 },
	{ "decw",	CF_CHG1 },
	{ "shr",	CF_CHG1 | CF_USE2 | CF_SHFT },
	{ "shrw",	CF_CHG1 | CF_USE2 | CF_SHFT },
	{ "shl",	CF_CHG1 | CF_USE2 | CF_SHFT },
	{ "shlw",	CF_CHG1 | CF_USE2 | CF_SHFT },
	{ "sar",	CF_CHG1 | CF_USE2 | CF_SHFT },
	{ "sarw",	CF_CHG1 | CF_USE2 | CF_SHFT },
	{ "ror",	CF_CHG1 | CF_USE2 },
	{ "rol",	CF_CHG1 },
	{ "rorc",	CF_CHG1 },
	{ "rolc",	CF_CHG1 },
	{ "rolwc",	CF_CHG1 },
	{ "mov1",	CF_CHG1 | CF_USE2 },
	{ "and1",	CF_CHG1 | CF_USE2 },
	{ "or1",	CF_CHG1 | CF_USE2 },
	{ "xor1",	CF_CHG1 | CF_USE2 },
	{ "set1",	CF_CHG1 },
	{ "clr1",	CF_CHG1 },
	{ "not1",	CF_CHG1 },
	{ "call",	CF_USE1 | CF_CALL },
	{ "callt",	CF_USE1 | CF_CALL },
	{ "brk",	CF_STOP },
	{ "ret",	CF_STOP },
	{ "reti",	CF_STOP },
	{ "retb",	CF_STOP },
	{ "push",	CF_USE1 },
	{ "pop",	CF_CHG1 },
	{ "br",		CF_USE1 | CF_STOP | CF_JUMP },
	{ "bc",		CF_USE1 },
	{ "bnc",	CF_USE1 },
	{ "bz",		CF_USE1 },
	{ "bnz",	CF_USE1 },
	{ "bh",		CF_USE1 },
	{ "bnh",	CF_USE1 },
	{ "bt",		CF_USE1 | CF_USE2 },
	{ "bf",		CF_USE1 | CF_USE2 },
	{ "btclr",	CF_USE1 | CF_USE2 },
	{ "skc",	 }, // sk* possibly branch over *next* insn
	{ "sknc",	 },
	{ "skz",	 },
	{ "sknz",	 },
	{ "skh",	 },
	{ "sknh",	 },
	{ "sel",	 }, // CF_USE1 ?
	{ "nop",	 },
	{ "ei",		 }, // ei/di are macros
	{ "di",		 },
	{ "halt",	 },
	{ "stop",   CF_STOP },
	{ "brk1",   CF_STOP },
};
static_assert(qnumber(instructions) == RL78_itype_count, "array doesn't match enum");

static const asm_t assembler = {
	AS_COLON | AS_N2CHR | ASH_HEXF0 | ASD_DECF0 | ASB_BINF0 | AS_ONEDUP | AS_NOXRF,
	0,
	"RL78 Assembler",
	0,
	nullptr,		// array of automatically generated header lines
					// they appear at the start of disassembled text
	".org",			// org directive
	".end",			// end directive
	";",			// comment string (see also cmnt2)
	'"',			// string literal delimiter
	'\'',			// char constant delimiter
	"'\"",			// special chars that can not appear
					// as is in string and char literals
	// Data representation (db,dw,...):
	".db",			// ascii
	".db",			// byte
	".dw",			// word
	".dd",			// dword
	nullptr,		// qword
	nullptr,		// oword
	nullptr,		// float
	nullptr,		// double
	nullptr,		// tbytes
	nullptr,		// packreal
	nullptr,		// dups
	nullptr,		// bss
	".equ",			// equ
	nullptr,		// seg
	"$",			// curip
	nullptr,		// out_func_header
	nullptr,		// out_func_footer
	nullptr,		// public
	nullptr,		// weak
	nullptr,		// extern
	nullptr,		// communal variable
	nullptr,		// get_type_name
	nullptr,		// align
	'(',			// lbrace
	')',			// rbrace
	// Assembler-time operators
	nullptr,		// %
	nullptr,		// &
	nullptr,		// |
	nullptr,		// ^
	nullptr,		// ~
	nullptr,		// <<
	nullptr,		// >>
	nullptr,		// size of type (format string)
	0,				// flag2
	nullptr,		// cmnt2
	nullptr,		// low8
	nullptr,		// high8
	nullptr,		// low16
	nullptr,		// high16
	nullptr,		// include_fmt
	nullptr,		// vstruc_fmt
	nullptr,		// rva
	nullptr,		// yword
};

#define RL78_MAX_OPERANDS 2

enum : decltype(insn_t::auxpref) {
	kHasPrefix = 1,
};

enum : optype_t {
	o_bit = o_idpspec0,
};

enum : decltype(op_t::specflag2) {
	kDirect,
	kIndirect,
};

enum RL78Phrase : decltype(op_t::phrase) {
	kReg,
	kHlReg,
	kReg8,
	kReg16,
};

// for o_bit, actual type of base operand
#define bit_base_type specflag1
// for o_bit, indicate if operand is indirect
#define addr_mode specflag2
// for o_phrase and o_displ, RL78Phrase value
#define ind_reg specflag2

// Currently don't actually track widths, width prefixes seem to just make
// disasm distracting.
/* RL78 has 2 segment registers:
	CS
		only updated explicitly (or as memory)
		only used via `call rp` or `br ax`
	ES
		only updated explicitly (or as memory)
		`prefix` opcode indicates ES is used in memory ref done by insn
*/
/*
	#	Immediate data specification
	$	8-bit relative address specification
	$!	16-bit relative address specification
	!	16-bit absolute address specification
	!!	20-bit absolute address specification
	[ ]	Indirect address specification
	ES:	Extension address specification

	$addr20		1	rel		just relative
	$!addr20	2	rel		"
	!addr16		2	abs		implies segment 0 (code), or f (data) unless segreg-prefixed
	!!addr20	3	abs		seg taken from addr
	addr5	 in op  ind		only used by callt. dst pc.s is always 0
*/

static ea_t sfr_abs(uint8 rel) {
	return 0xfff00 + rel;
}

static ea_t saddr_abs(uint8 rel) {
	// this logic doesn't seem documented for rl78, but it's what binutils
	// does, and appears similar to 78k0. Renesas tools agree this is correct.
	ea_t addr = 0xffe00 + rel;
	if (rel < 0x20) {
		addr |= 1 << 8;
	}
	return addr;
}

// #val (constant in opcode)
static void operand_imm_val(insn_t *out, int op_idx, uval_t val) {
	auto &op = out->ops[op_idx];
	op.type = o_imm;
	// not really true...
	op.dtype = dt_byte;
	op.value = val;
}

// #byte
static void operand_imm8(insn_t *out, int op_idx) {
	auto &op = out->ops[op_idx];
	op.type = o_imm;
	op.dtype = dt_byte;
	op.value = out->get_next_byte();
}

// #word
static void operand_imm16(insn_t *out, int op_idx) {
	auto &op = out->ops[op_idx];
	op.type = o_imm;
	op.dtype = dt_word;
	op.value = out->get_next_word();
}

// saddr
static void operand_saddr(insn_t *out, int op_idx, op_dtype_t dtype = dt_byte) {
	auto &op = out->ops[op_idx];
	op.type = o_mem;
	op.dtype = dtype;
	op.addr = saddr_abs(out->get_next_byte());
}

// saddrp
static void operand_saddrp(insn_t *out, int op_idx) {
	operand_saddr(out, op_idx, dt_word);
}

// saddr.bit
static void operand_saddr_bit(insn_t *out, int op_idx, uval_t bit) {
	auto &op = out->ops[op_idx];
	op.type = o_bit;
	op.bit_base_type = o_mem;
	op.dtype = dt_byte;
	op.addr = saddr_abs(out->get_next_byte());
	op.value = bit;
}

// TODO dtype?
// r
static void operand_r(insn_t *out, int op_idx, RL78Register reg) {
	auto &op = out->ops[op_idx];
	op.type = o_reg;
	op.reg = reg;
}

// r.bit
static void operand_r_bit(insn_t *out, int op_idx, RL78Register reg, uval_t bit) {
	auto &op = out->ops[op_idx];
	op.type = o_bit;
	op.bit_base_type = o_reg;
	op.reg = reg;
	op.value = bit;
}

// [r]
static void operand_r_ind(insn_t *out, int op_idx, RL78Register reg,
	op_dtype_t dtype = dt_byte) {
	auto &op = out->ops[op_idx];
	op.specval = out->auxpref & kHasPrefix;
	op.type = o_displ;
	op.dtype = dtype;
	op.phrase = kReg;
	op.ind_reg = reg;
	op.addr = 0;
}

// [r] (16bit)
static void operand_r_ind_d16(insn_t *out, int op_idx, RL78Register reg) {
	operand_r_ind(out, op_idx, reg, dt_word);
}

// [r].bit
static void operand_r_ind_bit(insn_t *out, int op_idx, RL78Register reg, uval_t bit) {
	auto &op = out->ops[op_idx];
	op.specval = out->auxpref & kHasPrefix;
	op.type = o_bit;
	op.bit_base_type = o_reg;
	op.addr_mode = kIndirect;
	op.reg = reg;
	op.value = bit;
}

static bool ea_to_reg(ea_t ea, RL78Register *reg) {
	switch (ea) {
	case 0xffff8:
		*reg = rSP;
		return true;
	case 0xffffa:
		*reg = rPSW;
		return true;
	case 0xffffc:
		*reg = rCS;
		return true;
	case 0xffffd:
		*reg = rES;
		return true;
	default:
		return false;
	}
}

static void operand_convert_to_r(insn_t *out, int op_idx) {
	auto &op = out->ops[op_idx];
	RL78Register reg;
	if (!ea_to_reg(op.addr, &reg)) {
		return;
	}
	if (op.type == o_bit) {
		operand_r_bit(out, op_idx, reg, op.value);
	}
	else {
		operand_r(out, op_idx, reg);
	}
}

// sfr
static void operand_sfr(insn_t *out, int op_idx, op_dtype_t dtype = dt_byte) {
	auto &op = out->ops[op_idx];
	op.type = o_mem;
	op.dtype = dtype;
	op.addr = sfr_abs(out->get_next_byte());
	operand_convert_to_r(out, op_idx);
}

// sfrp
static void operand_sfrp(insn_t *out, int op_idx) {
	operand_sfr(out, op_idx, dt_word);
}

// sfr.bit
static void operand_sfr_bit(insn_t *out, int op_idx, uval_t bit) {
	auto &op = out->ops[op_idx];
	op.type = o_bit;
	op.bit_base_type = o_mem;
	op.dtype = dt_byte;
	op.addr = sfr_abs(out->get_next_byte());
	op.value = bit;
	operand_convert_to_r(out, op_idx);
}

/* Following ops may have 16bit dtype in forms besides sfrp/saddrp
movw			   !addr16, [hl+byte], [hl], [de+byte], [de], [sp+byte], word[b], word[c], word[bc]
addw, subw, cmpw   !addr16, [hl+byte]
incw, decw		   !addr16, [hl+byte]
*/

/* prefixable
	!addr16
	!addr16.bit
	[r]
	[r].bit
	[hl+r]
	[r+byte]
	word[r]
*/

// $addr20
// 1 byte, rel
// PC <- PC + 2 + jdisp8
// code only
static void operand_addr_rel(insn_t *out, int op_idx) {
	auto &op = out->ops[op_idx];
	op.type = o_near;
	op.offb = (uint8)out->size;
	op.addr = out->ip + (int8)out->get_next_byte();
	op.addr += out->size;
	op.value = op.addr;
}

// $!addr20
// 2 bytes, rel
// PC <- PC + 3 + jdisp16
// code only
static void operand_addr16_rel(insn_t *out, int op_idx) {
	auto &op = out->ops[op_idx];
	op.type = o_near;
	op.offb = (uint8)out->size;
	op.addr = out->ip + (int16)out->get_next_word();
	op.addr += out->size;
	op.value = op.addr;
}

// !addr16 (code)
// 2 bytes, abs
// PC <- 0000, addr16
static void operand_addr16_abs(insn_t *out, int op_idx) {
	auto &op = out->ops[op_idx];
	// for code, seg bits set to 0
	op.type = o_far;
	op.offb = (uint8)out->size;
	op.addr = out->get_next_word();
	op.value = op.addr;
}

// !addr16 (data)
static void operand_addr16_abs_d(insn_t *out, int op_idx,
	op_dtype_t dtype = dt_byte) {
	auto &op = out->ops[op_idx];
	op.specval = out->auxpref & kHasPrefix;
	op.type = o_mem;
	op.dtype = dtype;
	op.offb = (uint8)out->size;
	op.addr = out->get_next_word();
	if (!(op.specval & kHasPrefix)) {
		op.addr += 0xf << 16;
	}
	op.value = op.addr;
	operand_convert_to_r(out, op_idx);
}

// !addr16 (16bit data)
static void operand_addr16_abs_d16(insn_t *out, int op_idx) {
	operand_addr16_abs_d(out, op_idx, dt_word);
}

// !addr16.bit
// data only
static void operand_addr16_abs_bit(insn_t *out, int op_idx, uval_t bit) {
	auto &op = out->ops[op_idx];
	op.specval = out->auxpref & kHasPrefix;
	op.type = o_bit;
	op.bit_base_type = o_mem;
	op.offb = (uint8)out->size;
	op.addr = out->get_next_word();
	if (!(op.specval & kHasPrefix)) {
		op.addr += 0xf << 16;
	}
	op.value = bit;
	operand_convert_to_r(out, op_idx);
}

// !!addr20
// 3 bytes, abs
// PC <- addr20
// code only
static void operand_addr20_abs(insn_t *out, int op_idx) {
	auto &op = out->ops[op_idx];
	op.type = o_far;
	op.offb = (uint8)out->size;
	op.addr = out->get_next_word();
	op.addr |= ((ea_t)out->get_next_byte()) << 16;
	op.value = op.addr;
}

// [hl + r]
static void operand_hl_off_reg(insn_t *out, int op_idx, RL78Register reg) {
	auto &op = out->ops[op_idx];
	op.specval = out->auxpref & kHasPrefix;
	op.type = o_phrase;
	op.dtype = dt_byte;
	op.phrase = kHlReg;
	op.ind_reg = reg;
}

// [r + byte]
static void operand_r_off_imm8(insn_t *out, int op_idx, RL78Register reg,
	op_dtype_t dtype = dt_byte) {
	auto &op = out->ops[op_idx];
	op.specval = out->auxpref & kHasPrefix;
	op.type = o_displ;
	op.dtype = dtype;
	op.phrase = kReg8;
	op.ind_reg = reg;
	op.addr = out->get_next_byte();
}

// [r + byte] (16bit)
static void operand_r_off_imm8_d16(insn_t *out, int op_idx, RL78Register reg) {
	operand_r_off_imm8(out, op_idx, reg, dt_word);
}

// word[r]
static void operand_r_off_imm16(insn_t *out, int op_idx, RL78Register reg,
	op_dtype_t dtype = dt_byte) {
	auto &op = out->ops[op_idx];
	op.specval = out->auxpref & kHasPrefix;
	op.type = o_displ;
	op.dtype = dtype;
	op.phrase = kReg16;
	op.ind_reg = reg;
	op.addr = out->get_next_word();
}

// word[r] (16bit)
static void operand_r_off_imm16_d16(insn_t *out, int op_idx, RL78Register reg) {
	operand_r_off_imm16(out, op_idx, reg, dt_word);
}

static int opcode_31(insn_t *out) {
	uint8 code = out->get_next_byte();
	uint8 code_lo = code & 0xf;
	uint8 code_hi = (code >> 4) & 0xf;
	
	if (code_lo <= 5) {
		const uint16 itype_lut[] = {
			RL78_btclr, RL78_btclr,
			RL78_bt, RL78_bt,
			RL78_bf, RL78_bf,
		};
		out->itype = itype_lut[code_lo];
	}
	else if ((code_lo >= 7 && code_lo <= 0xb) && (code_hi >= 1 && code_hi <= 7)) {
		const uint16 itype_lut[] = {
			RL78_shl, RL78_shl, RL78_shl,
			RL78_shr,
			RL78_sar,
		};
		out->itype = itype_lut[code_lo - 7];
	}
	else if (code_lo >= 0xc && code_hi >= 1) {
		const uint16 itype_lut[] = {
			RL78_shlw, RL78_shlw,
			RL78_shrw,
			RL78_sarw,
		};
		out->itype = itype_lut[code_lo - 0xc];
	}
	else {
		return 0;
	}

	switch (out->itype) {
	case RL78_btclr:
	case RL78_bt:
	case RL78_bf: {
		uval_t bit = code_hi & 7;
		switch (code & 0x81) {
		case 0x00: // bX saddr.bit, $addr20
			operand_saddr_bit(out, 0, bit);
			break;
		case 0x01: // bX A.bit, $addr20
			operand_r_bit(out, 0, rA, bit);
			break;
		case 0x80: // bX sfr.bit, $addr20
			operand_sfr_bit(out, 0, bit);
			break;
		case 0x81: // bX [HL].bit, $addr20
			operand_r_ind_bit(out, 0, rHL, bit);
			break;
		}
		operand_addr_rel(out, 1);
	  } break;
	case RL78_shl: { // shl r, cnt
		const RL78Register reg_lut[] = { rC, rB, rA };
		auto reg = reg_lut[code_lo - 7];
		operand_r(out, 0, reg);
		operand_imm_val(out, 1, code_hi);
	  } break;
	case RL78_shr: // shr r, cnt
		operand_r(out, 0, rA);
		operand_imm_val(out, 1, code_hi);
		break;
	case RL78_sar: // sar A, cnt
		operand_r(out, 0, rA);
		operand_imm_val(out, 1, code_hi);
		break;
	case RL78_shlw: { // shlw rp, cnt
		const RL78Register reg_lut[] = { rBC, rAX };
		auto reg = reg_lut[code_lo - 0xc];
		operand_r(out, 0, reg);
		operand_imm_val(out, 1, code_hi);
	  } break;
	case RL78_shrw: // shrw rp, cnt
		operand_r(out, 0, rAX);
		operand_imm_val(out, 1, code_hi);
		break;
	case RL78_sarw: // sarw rp, cnt
		operand_r(out, 0, rAX);
		operand_imm_val(out, 1, code_hi);
		break;
	}
	return out->size;
}

static int opcode_61(insn_t *out) {
	uint8 code = out->get_next_byte();
	uint8 code_lo = code & 0xf;
	uint8 code_hi = (code >> 4) & 0xf;

	const uint16 itype_lut[] = {
		RL78_add, RL78_addc, RL78_sub, RL78_subc, RL78_cmp, RL78_and,
		RL78_or, RL78_xor, RL78_xch
	};

	if (code_hi <= 7 && code_lo <= 7) {
		out->itype = itype_lut[code_hi];
		operand_r(out, 0, (RL78Register)code_lo);
		operand_r(out, 1, rA);
	}
	else if ((code_hi <= 7 && code_lo == 8) || (code_hi <= 8 && code_lo >= 0xa)) {
		out->itype = itype_lut[code_hi];
		operand_r(out, 0, rA);
		operand_r(out, 1, (RL78Register)(rX + (code_lo & 7)));
	}
	else if (code_hi >= 8 && (code_lo >= 4 && code_lo <= 7)) {
		// TODO callt hasn't been seen, so not bothered making it nice
		out->itype = RL78_callt;
		// addr5_abs
		uint16 addr = 0x80 | ((code_lo & 3) << 4) | ((code_hi & 7) << 1);
		auto &op = out->ops[0];
		op.type = o_mem;
		op.value = addr;
		op.addr = addr;
		op.dtype = dt_word;
	}
	else {
		switch (code) {
		case 0x09: // addw ax, [hl+byte]
			out->itype = RL78_addw;
			operand_r(out, 0, rAX);
			operand_r_off_imm8_d16(out, 1, rHL);
			break;
		case 0x29: // subw ax, [hl+byte]
			out->itype = RL78_subw;
			operand_r(out, 0, rAX);
			operand_r_off_imm8_d16(out, 1, rHL);
			break;
		case 0x49: // cmpw ax, [hl+byte]
			out->itype = RL78_cmpw;
			operand_r(out, 0, rAX);
			operand_r_off_imm8_d16(out, 1, rHL);
			break;
		case 0x59: // inc [hl+byte]
			out->itype = RL78_inc;
			operand_r_off_imm8(out, 0, rHL);
			break;
		case 0x69: // dec [hl+byte]
			out->itype = RL78_dec;
			operand_r_off_imm8(out, 0, rHL);
			break;
		case 0x79: // incw [hl+byte]
			out->itype = RL78_incw;
			operand_r_off_imm8_d16(out, 0, rHL);
			break;
		case 0x89: // decw [hl+byte]
			out->itype = RL78_decw;
			operand_r_off_imm8_d16(out, 0, rHL);
			break;
		case 0x80:
		case 0x90:
		case 0xa0:
		case 0xb0:
		case 0xc0:
		case 0xd0:
		case 0xe0:
		case 0xf0:
			out->itype = itype_lut[code_hi & 7];
			operand_r(out, 0, rA);
			operand_hl_off_reg(out, 1, rB);
			break;
		case 0x82:
		case 0x92:
		case 0xa2:
		case 0xb2:
		case 0xc2:
		case 0xd2:
		case 0xe2:
		case 0xf2:
			out->itype = itype_lut[code_hi & 7];
			operand_r(out, 0, rA);
			operand_hl_off_reg(out, 1, rC);
			break;
		case 0xc3:
			out->itype = RL78_bh;
			operand_addr_rel(out, 0);
			break;
		case 0xd3:
			out->itype = RL78_bnh;
			operand_addr_rel(out, 0);
			break;
		case 0xe3:
			out->itype = RL78_skh;
			break;
		case 0xf3:
			out->itype = RL78_sknh;
			break;
		
		case 0xa8:
			out->itype = RL78_xch;
			operand_r(out, 0, rA);
			operand_saddr(out, 1);
			break;
		case 0xb8:
			out->itype = RL78_mov;
			operand_r(out, 0, rES);
			operand_saddr(out, 1);
			break;
		case 0xa9:
			out->itype = RL78_xch;
			operand_r(out, 0, rA);
			operand_hl_off_reg(out, 1, rC);
			break;
		case 0xb9:
			out->itype = RL78_xch;
			operand_r(out, 0, rA);
			operand_hl_off_reg(out, 1, rB);
			break;
		case 0xaa:
			out->itype = RL78_xch;
			operand_r(out, 0, rA);
			operand_addr16_abs_d(out, 1);
			break;
		case 0xab:
			out->itype = RL78_xch;
			operand_r(out, 0, rA);
			operand_sfr(out, 1);
			break;
		case 0xac: // xch a, [hl]
			out->itype = RL78_xch;
			operand_r(out, 0, rA);
			operand_r_ind(out, 1, rHL);
			break;
		case 0xad:
			out->itype = RL78_xch;
			operand_r(out, 0, rA);
			operand_r_off_imm8(out, 1, rHL);
			break;
		case 0xae: // xch a, [de]
			out->itype = RL78_xch;
			operand_r(out, 0, rA);
			operand_r_ind(out, 1, rDE);
			break;
		case 0xaf:
			out->itype = RL78_xch;
			operand_r(out, 0, rA);
			operand_r_off_imm8(out, 1, rDE);
			break;

		case 0xc8:
			out->itype = RL78_skc;
			break;
		case 0xd8:
			out->itype = RL78_sknc;
			break;
		case 0xe8:
			out->itype = RL78_skz;
			break;
		case 0xf8:
			out->itype = RL78_sknz;
			break;
		case 0xc9:
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_hl_off_reg(out, 1, rB);
			break;
		case 0xd9:
			out->itype = RL78_mov;
			operand_hl_off_reg(out, 0, rB);
			operand_r(out, 1, rA);
			break;
		case 0xe9:
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_hl_off_reg(out, 1, rC);
			break;
		case 0xf9:
			out->itype = RL78_mov;
			operand_hl_off_reg(out, 0, rC);
			operand_r(out, 1, rA);
			break;
		case 0xca:
		case 0xda:
		case 0xea:
		case 0xfa:
			out->itype = RL78_call;
			operand_r(out, 0, (RL78Register)(rAX + (code_hi & 3)));
			break;
		case 0xcb:
			out->itype = RL78_br;
			operand_r(out, 0, rAX);
			break;
		case 0xdb:
			out->itype = RL78_ror;
			operand_r(out, 0, rA);
			operand_imm_val(out, 1, 1);
			break;
		case 0xeb:
			out->itype = RL78_rol;
			operand_r(out, 0, rA);
			operand_imm_val(out, 1, 1);
			break;
		case 0xfb:
			out->itype = RL78_rorc;
			operand_r(out, 0, rA);
			operand_imm_val(out, 1, 1);
			break;
		case 0xcc:
			out->itype = RL78_brk;
			break;
		case 0xdc:
			out->itype = RL78_rolc;
			operand_r(out, 0, rA);
			operand_imm_val(out, 1, 1);
			break;
		case 0xec:
			out->itype = RL78_retb;
			break;
		case 0xfc:
			out->itype = RL78_reti;
			break;
		case 0xcd:
			out->itype = RL78_pop;
			operand_r(out, 0, rPSW);
			break;
		case 0xdd:
			out->itype = RL78_push;
			operand_r(out, 0, rPSW);
			break;
		case 0xed:
			out->itype = RL78_halt;
			break;
		case 0xfd:
			out->itype = RL78_stop;
			break;
		case 0xce:
			out->itype = RL78_movs;
			operand_r_off_imm8(out, 0, rHL);
			operand_r(out, 1, rX);
			break;
		case 0xde:
			out->itype = RL78_cmps;
			operand_r(out, 0, rX);
			operand_r_off_imm8(out, 1, rHL);
			break;
		case 0xee:
			out->itype = RL78_rolwc;
			operand_r(out, 0, rAX);
			operand_imm_val(out, 1, 1);
			break;
		case 0xfe:
			out->itype = RL78_rolwc;
			operand_r(out, 0, rBC);
			operand_imm_val(out, 1, 1);
			break;
		case 0xcf:
		case 0xdf:
		case 0xef:
		case 0xff:
			out->itype = RL78_sel;
			operand_r(out, 0, (RL78Register)(rRB0 + (code_hi & 3)));
			break;
		default:
			return 0;
		}
	}

	return out->size;
}

static int opcode_71(insn_t *out) {
	uint8 code = out->get_next_byte();
	uint8 code_lo = code & 0xf;
	uint8 code_hi = (code >> 4) & 0xf;

	if (code_hi >= 8 && code_lo == 0) {
		switch (code_hi) {
		case 8: // set1 cy
			out->itype = RL78_set1;
			operand_r(out, 0, rCY);
			break;
		case 0xc: // not1 cy
			out->itype = RL78_not1;
			operand_r(out, 0, rCY);
			break;
		default:
			return 0;
		}
		return out->size;
	}
	else if (code_hi >= 8 && code_lo == 8) {
		switch (code_hi) {
		case 8: // clr1 cy
			out->itype = RL78_clr1;
			operand_r(out, 0, rCY);
			break;
		default:
			return 0;
		}
		return out->size;
	}

	const uint16 itype_lut[] = {
		RL78_set1, RL78_mov1, RL78_set1, RL78_clr1, RL78_mov1, RL78_and1,
		RL78_or1, RL78_xor1, RL78_clr1, RL78_mov1, RL78_set1, RL78_clr1,
		RL78_mov1, RL78_and1, RL78_or1, RL78_xor1
	};
	out->itype = itype_lut[code_lo];

	uval_t bit = code_hi & 7;

	switch (code & 0x8f) {
	case 0x01: // mov1 saddr.bit, cy
		operand_saddr_bit(out, 0, bit);
		operand_r(out, 1, rCY);
		break;
	case 0x81: // mov1 [hl].bit, cy
		operand_r_ind_bit(out, 0, rHL, bit);
		operand_r(out, 1, rCY);
		break;
	case 0x02: // set1 saddr.bit
	case 0x03: // clr1 saddr.bit
		operand_saddr_bit(out, 0, bit);
		break;
	case 0x82: // set1 [hl].bit
	case 0x83: // clr1 [hl].bit
		operand_r_ind_bit(out, 0, rHL, bit);
		break;
	case 0x04: // mov1 cy, saddr.bit
	case 0x05: // and1 cy, saddr.bit
	case 0x06: // or1 cy, saddr.bit
	case 0x07: // xor1 cy, saddr.bit
		operand_r(out, 0, rCY);
		operand_saddr_bit(out, 1, bit);
		break;
	case 0x84: // mov1 cy, [hl].bit
	case 0x85: // and1 cy, [hl].bit
	case 0x86: // or1 cy, [hl].bit
	case 0x87: // xor1 cy, [hl].bit
		operand_r(out, 0, rCY);
		operand_r_ind_bit(out, 1, rHL, bit);
		break;
	case 0x00: // set1 !addr16.bit
	case 0x08: // clr1 !addr16.bit
		operand_addr16_abs_bit(out, 0, bit);
		break;
	case 0x09: // mov1 sfr.bit, cy
		operand_sfr_bit(out, 0, bit);
		operand_r(out, 1, rCY);
		break;
	case 0x89: // mov1 a.bit, cy
		operand_r_bit(out, 0, rA, bit);
		operand_r(out, 1, rCY);
		break;
	case 0x0a: // set1 sfr.bit
	case 0x0b: // clr1 sfr.bit
		operand_sfr_bit(out, 0, bit);
		break;
	case 0x8a: // set1 a.bit
	case 0x8b: // clr1 a.bit
		operand_r_bit(out, 0, rA, bit);
		break;
	case 0x0c: // mov1 cy, sfr.bit
	case 0x0d: // and1 cy, sfr.bit
	case 0x0e: // or1 cy, sfr.bit
	case 0x0f: // mov1 cy, sfr.bit
		operand_r(out, 0, rCY);
		operand_sfr_bit(out, 1, bit);
		break;
	case 0x8c: // mov1 cy, a.bit
	case 0x8d: // and1 cy, a.bit
	case 0x8e: // or1 cy, a.bit
	case 0x8f: // xor1 cy, a.bit
		operand_r(out, 0, rCY);
		operand_r_bit(out, 1, rA, bit);
		break;
	default:
		// shouldn't be reached
		msg("%s:unhandled opcode %02x\n", __func__, code);
		return 0;
	}

	return out->size;
}

int ana(insn_t *out) {
	uint8 code = out->get_next_byte();

	out->auxpref = 0;
	if (code == 0x11) {
		out->auxpref |= kHasPrefix;
		code = out->get_next_byte();
	}

	uint8 code_lo = code & 0xf;
	uint8 code_hi = (code >> 4) & 0xf;

	if (code_lo >= 0xa && code_hi <= 7) {
		const uint16 itype_lut[] = {
			RL78_add, RL78_addc, RL78_sub, RL78_subc, RL78_cmp, RL78_and, RL78_or,
			RL78_xor
		};
		out->itype = itype_lut[code_hi];
		if (code_lo == 0xa) {
			operand_saddr(out, 0);
		} else {
			operand_r(out, 0, rA);
		}
		switch (code_lo) {
		case 0xa:
		case 0xc: // #byte
			operand_imm8(out, 1);
			break;
		case 0xb: // saddr
			operand_saddr(out, 1);
			break;
		case 0xd: // [hl]
			operand_r_ind(out, 1, rHL);
			break;
		case 0xe: // [hl+byte]
			operand_r_off_imm8(out, 1, rHL);
			break;
		case 0xf: // !addr16
			operand_addr16_abs_d(out, 1);
			break;
		}
	}
	else {
		switch (code) {
		case 0x00: // nop
			out->itype = RL78_nop;
			break;
		case 0x31:
			// 4th map
			if (!opcode_31(out)) {
				return 0;
			}
			break;
		case 0x61:
			// 2nd map
			if (!opcode_61(out)) {
				return 0;
			}
			break;
		case 0x71:
			// 3rd map
			if (!opcode_71(out)) {
				return 0;
			}
			break;
		case 0x01: // addw ax, ax
			out->itype = RL78_addw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rAX);
			break;
		case 0x02: // addw ax, !addr16
			out->itype = RL78_addw;
			operand_r(out, 0, rAX);
			operand_addr16_abs_d16(out, 1);
			break;
		case 0x03: // addw ax, bc
			out->itype = RL78_addw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rBC);
			break;
		case 0x04: // addw ax, #word
			out->itype = RL78_addw;
			operand_r(out, 0, rAX);
			operand_imm16(out, 1);
			break;
		case 0x05: // addw ax, de
			out->itype = RL78_addw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rDE);
			break;
		case 0x06: // addw ax, saddrp
			out->itype = RL78_addw;
			operand_r(out, 0, rAX);
			operand_saddrp(out, 1);
			break;
		case 0x07: // addw ax, hl
			out->itype = RL78_addw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rHL);
			break;
		case 0x08: // xch a, x
			out->itype = RL78_xch;
			operand_r(out, 0, rA);
			operand_r(out, 1, rX);
			break;
		case 0x09: // mov a, word[b]
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_r_off_imm16(out, 1, rB);
			break;
		case 0x10: // addw sp, #byte
			out->itype = RL78_addw;
			operand_r(out, 0, rSP);
			operand_imm8(out, 1);
			break;
		case 0x12: // movw bc, ax
			out->itype = RL78_movw;
			operand_r(out, 0, rBC);
			operand_r(out, 1, rAX);
			break;
		case 0x13: // movw ax, bc
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rBC);
			break;
		case 0x14: // mov de, ax
			out->itype = RL78_movw;
			operand_r(out, 0, rDE);
			operand_r(out, 1, rAX);
			break;
		case 0x15: // movw ax, de
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rDE);
			break;
		case 0x16: // movw hl, ax
			out->itype = RL78_movw;
			operand_r(out, 0, rHL);
			operand_r(out, 1, rAX);
			break;
		case 0x17: // movw ax, hl
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rHL);
			break;
		case 0x18: // mov word[b], a
			out->itype = RL78_mov;
			operand_r_off_imm16(out, 0, rB);
			operand_r(out, 1, rA);
			break;
		case 0x19: // mov word[b], #byte
			out->itype = RL78_mov;
			operand_r_off_imm16(out, 0, rB);
			operand_imm8(out, 1);
			break;
		case 0x20: // subw sp, #byte
			out->itype = RL78_subw;
			operand_r(out, 0, rSP);
			operand_imm8(out, 1);
			break;
		case 0x22: // subw ax, !addr16
			out->itype = RL78_subw;
			operand_r(out, 0, rAX);
			operand_addr16_abs_d16(out, 1);
			break;
		case 0x23: // subw ax, bc
			out->itype = RL78_subw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rBC);
			break;
		case 0x24: // subw ax, #word
			out->itype = RL78_subw;
			operand_r(out, 0, rAX);
			operand_imm16(out, 1);
			break;
		case 0x25: // subw ax, de
			out->itype = RL78_subw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rDE);
			break;
		case 0x26: // subw ax, saddrp
			out->itype = RL78_subw;
			operand_r(out, 0, rAX);
			operand_saddrp(out, 1);
			break;
		case 0x27: // subw ax, hl
			out->itype = RL78_subw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rHL);
			break;
		case 0x28: // mov word[c], a
			out->itype = RL78_mov;
			operand_r_off_imm16(out, 0, rC);
			operand_r(out, 1, rA);
			break;
		case 0x29: // mov a, word[c]
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_r_off_imm16(out, 1, rC);
			break;
		case 0x30: // movw ax, #word
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_imm16(out, 1);
			break;
		case 0x32: // movw bc, #word
			out->itype = RL78_movw;
			operand_r(out, 0, rBC);
			operand_imm16(out, 1);
			break;
		case 0x33: // xchw ax, bc
			out->itype = RL78_xchw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rBC);
			break;
		case 0x34: // movw de, #word
			out->itype = RL78_movw;
			operand_r(out, 0, rDE);
			operand_imm16(out, 1);
			break;
		case 0x35: // xchw ax, de
			out->itype = RL78_xchw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rDE);
			break;
		case 0x36: // movw hl, #word
			out->itype = RL78_movw;
			operand_r(out, 0, rHL);
			operand_imm16(out, 1);
			break;
		case 0x37: // xchw ax, hl
			out->itype = RL78_xchw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rHL);
			break;
		case 0x38: // mov word[c], #byte
			out->itype = RL78_mov;
			operand_r_off_imm16(out, 0, rC);
			operand_imm8(out, 1);
			break;
		case 0x39: // mov word[bc], #byte
			out->itype = RL78_mov;
			operand_r_off_imm16(out, 0, rBC);
			operand_imm8(out, 1);
			break;
		case 0x40: // cmp !addr16, #byte
			out->itype = RL78_cmp;
			operand_addr16_abs_d(out, 0);
			operand_imm8(out, 1);
			break;
		case 0x41: // mov es, #byte
			out->itype = RL78_mov;
			operand_r(out, 0, rES);
			operand_imm8(out, 1);
			break;
		case 0x42: // cmpw ax, !addr16
			out->itype = RL78_cmpw;
			operand_r(out, 0, rAX);
			operand_addr16_abs_d16(out, 1);
			break;
		case 0x43: // cmpw ax, bc
			out->itype = RL78_cmpw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rBC);
			break;
		case 0x44: // cmpw ax, #word
			out->itype = RL78_cmpw;
			operand_r(out, 0, rAX);
			operand_imm16(out, 1);
			break;
		case 0x45: // cmpw ax, de
			out->itype = RL78_cmpw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rDE);
			break;
		case 0x46: // cmpw ax, saddrp
			out->itype = RL78_cmpw;
			operand_r(out, 0, rAX);
			operand_saddrp(out, 1);
			break;
		case 0x47: // cmpw ax, hl
			out->itype = RL78_cmpw;
			operand_r(out, 0, rAX);
			operand_r(out, 1, rHL);
			break;
		case 0x48: // mov word[bc], a
			out->itype = RL78_mov;
			operand_r_off_imm16(out, 0, rBC);
			operand_r(out, 1, rA);
			break;
		case 0x49: // mov a, word[bc]
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_r_off_imm16(out, 1, rBC);
			break;
		case 0x50: // mov r, #byte
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x56:
		case 0x57:
			out->itype = RL78_mov;
			operand_r(out, 0, (RL78Register)(rX + code_lo));
			operand_imm8(out, 1);
			break;
		case 0x58: // movw word[b], ax
			out->itype = RL78_movw;
			operand_r_off_imm16_d16(out, 0, rB);
			operand_r(out, 1, rAX);
			break;
		case 0x59: // movw ax, word[b]
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_r_off_imm16_d16(out, 1, rB);
			break;
		case 0x60: // mov A, r
		case 0x62:
		case 0x63:
		case 0x64:
		case 0x65:
		case 0x66:
		case 0x67:
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_r(out, 1, (RL78Register)(rX + code_lo));
			break;
		case 0x68: // movw word[c], ax
			out->itype = RL78_movw;
			operand_r_off_imm16_d16(out, 0, rC);
			operand_r(out, 1, rAX);
			break;
		case 0x69: // movw ax, word[c]
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_r_off_imm16_d16(out, 1, rC);
			break;
		case 0x70: // mov r, A
		case 0x72:
		case 0x73:
		case 0x74:
		case 0x75:
		case 0x76:
		case 0x77:
			out->itype = RL78_mov;
			operand_r(out, 0, (RL78Register)(rX + code_lo));
			operand_r(out, 1, rA);
			break;
		case 0x78: // movw word[bc], ax
			out->itype = RL78_movw;
			operand_r_off_imm16_d16(out, 0, rBC);
			operand_r(out, 1, rAX);
			break;
		case 0x79: // movw ax, word[bc]
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_r_off_imm16_d16(out, 1, rBC);
			break;
		case 0x80: // inc r
		case 0x81:
		case 0x82:
		case 0x83:
		case 0x84:
		case 0x85:
		case 0x86:
		case 0x87:
			out->itype = RL78_inc;
			operand_r(out, 0, (RL78Register)(rX + code_lo));
			break;
		case 0x88: // mov a, [sp+byte]
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_r_off_imm8(out, 1, rSP);
			break;
		case 0x89: // mov a, [de]
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_r_ind(out, 1, rDE);
			break;
		case 0x8a: // mov a, [de+byte]
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_r_off_imm8(out, 1, rDE);
			break;
		case 0x8b: // mov a, [hl]
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_r_ind(out, 1, rHL);
			break;
		case 0x8c: // mov a, [hl+byte]
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_r_off_imm8(out, 1, rHL);
			break;
		case 0x8d: // mov a, saddr
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_saddr(out, 1);
			break;
		case 0x8e: // mov a, sfr
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_sfr(out, 1);
			break;
		case 0x8f: // mov a, !add16
			out->itype = RL78_mov;
			operand_r(out, 0, rA);
			operand_addr16_abs_d(out, 1);
			break;
		case 0x90: // dec r
		case 0x91:
		case 0x92:
		case 0x93:
		case 0x94:
		case 0x95:
		case 0x96:
		case 0x97:
			out->itype = RL78_dec;
			operand_r(out, 0, (RL78Register)(rX + code_lo));
			break;
		case 0x98: // mov [sp+byte], a
			out->itype = RL78_mov;
			operand_r_off_imm8(out, 0, rSP);
			operand_r(out, 1, rA);
			break;
		case 0x99: // mov [de], a
			out->itype = RL78_mov;
			operand_r_ind(out, 0, rDE);
			operand_r(out, 1, rA);
			break;
		case 0x9a: // mov [de+byte], a
			out->itype = RL78_mov;
			operand_r_off_imm8(out, 0, rDE);
			operand_r(out, 1, rA);
			break;
		case 0x9b: // mov [hl], a
			out->itype = RL78_mov;
			operand_r_ind(out, 0, rHL);
			operand_r(out, 1, rA);
			break;
		case 0x9c: // mov [hl+byte], a
			out->itype = RL78_mov;
			operand_r_off_imm8(out, 0, rHL);
			operand_r(out, 1, rA);
			break;
		case 0x9d: // mov saddr, a
			out->itype = RL78_mov;
			operand_saddr(out, 0);
			operand_r(out, 1, rA);
			break;
		case 0x9e: // mov sfr, a
			out->itype = RL78_mov;
			operand_sfr(out, 0);
			operand_r(out, 1, rA);
			break;
		case 0x9f: // mov !addr16, a
			out->itype = RL78_mov;
			operand_addr16_abs_d(out, 0);
			operand_r(out, 1, rA);
			break;
		case 0xa0: // inc !add16
			out->itype = RL78_inc;
			operand_addr16_abs_d(out, 0);
			break;
		case 0xb0: // dec !add16
			out->itype = RL78_dec;
			operand_addr16_abs_d(out, 0);
			break;
		case 0xa1: // incw ax
			out->itype = RL78_incw;
			operand_r(out, 0, rAX);
			break;
		case 0xb1: // decw ax
			out->itype = RL78_decw;
			operand_r(out, 0, rAX);
			break;
		case 0xa2: // incw !addr16
			out->itype = RL78_incw;
			operand_addr16_abs_d16(out, 0);
			break;
		case 0xb2: // decw !addr16
			out->itype = RL78_decw;
			operand_addr16_abs_d16(out, 0);
			break;
		case 0xa3: // incw bc
			out->itype = RL78_incw;
			operand_r(out, 0, rBC);
			break;
		case 0xb3: // decw bc
			out->itype = RL78_decw;
			operand_r(out, 0, rBC);
			break;
		case 0xa4: // inc saddr
			out->itype = RL78_inc;
			operand_saddr(out, 0);
			break;
		case 0xb4: // dec saddr
			out->itype = RL78_dec;
			operand_saddr(out, 0);
			break;
		case 0xa5: // incw de
			out->itype = RL78_incw;
			operand_r(out, 0, rDE);
			break;
		case 0xb5: // decw de
			out->itype = RL78_decw;
			operand_r(out, 0, rDE);
			break;
		case 0xa6: // incw saddrp
			out->itype = RL78_incw;
			operand_saddrp(out, 0);
			break;
		case 0xb6: // decw saddrp
			out->itype = RL78_decw;
			operand_saddrp(out, 0);
			break;
		case 0xa7: // incw hl
			out->itype = RL78_incw;
			operand_r(out, 0, rHL);
			break;
		case 0xb7: // decw hl
			out->itype = RL78_decw;
			operand_r(out, 0, rHL);
			break;
		case 0xa8: // movw ax, [sp+byte]
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_r_off_imm8_d16(out, 1, rSP);
			break;
		case 0xb8: // movw [sp+byte], ax
			out->itype = RL78_movw;
			operand_r_off_imm8_d16(out, 0, rSP);
			operand_r(out, 1, rAX);
			break;
		case 0xa9: // movw ax, [de]
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_r_ind_d16(out, 1, rDE);
			break;
		case 0xb9: // movw [de], ax
			out->itype = RL78_movw;
			operand_r_ind_d16(out, 0, rDE);
			operand_r(out, 1, rAX);
			break;
		case 0xaa: // movw ax, [de+byte]
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_r_off_imm8_d16(out, 1, rDE);
			break;
		case 0xba: // movw [de+byte], ax
			out->itype = RL78_movw;
			operand_r_off_imm8_d16(out, 0, rDE);
			operand_r(out, 1, rAX);
			break;
		case 0xab: // movw ax, [hl]
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_r_ind_d16(out, 1, rHL);
			break;
		case 0xbb: // movw [hl], ax
			out->itype = RL78_movw;
			operand_r_ind_d16(out, 0, rHL);
			operand_r(out, 1, rAX);
			break;
		case 0xac: // movw ax, [hl+byte]
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_r_off_imm8_d16(out, 1, rHL);
			break;
		case 0xbc: // movw [hl+byte], ax
			out->itype = RL78_movw;
			operand_r_off_imm8_d16(out, 0, rHL);
			operand_r(out, 1, rAX);
			break;
		case 0xad: // movw ax, saddrp
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_saddrp(out, 1);
			break;
		case 0xbd: // movw saddrp, ax
			out->itype = RL78_movw;
			operand_saddrp(out, 0);
			operand_r(out, 1, rAX);
			break;
		case 0xae: // movw ax, sfrp
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_sfrp(out, 1);
			break;
		case 0xbe: // movw sfrp, ax
			out->itype = RL78_movw; 
			operand_sfrp(out, 0);
			operand_r(out, 1, rAX);
			break;
		case 0xaf: // movw ax, !addr16
			out->itype = RL78_movw;
			operand_r(out, 0, rAX);
			operand_addr16_abs_d16(out, 1);
			break;
		case 0xbf: // movw !addr16, ax
			out->itype = RL78_movw;
			operand_addr16_abs_d16(out, 0);
			operand_r(out, 1, rAX);
			break;
		case 0xc0: // pop ax
		case 0xc2: // pop bc
		case 0xc4: // pop de
		case 0xc6: // pop hl
			out->itype = RL78_pop;
			operand_r(out, 0, (RL78Register)(rAX + (code_lo >> 1)));
			break;
		case 0xc1: // push ax
		case 0xc3: // push bc
		case 0xc5: // push de
		case 0xc7: // push hl
			out->itype = RL78_push;
			operand_r(out, 0, (RL78Register)(rAX + (code_lo >> 1)));
			break;
		case 0xc8: // mov [sp+byte], #byte
			out->itype = RL78_mov;
			operand_r_off_imm8(out, 0, rSP);
			operand_imm8(out, 1);
			break;
		case 0xc9: // movw saddrp, #word
			out->itype = RL78_movw;
			operand_saddrp(out, 0);
			operand_imm16(out, 1);
			break;
		case 0xca: // mov [de+byte], #byte
			out->itype = RL78_mov;
			operand_r_off_imm8(out, 0, rDE);
			operand_imm8(out, 1);
			break;
		case 0xcb: // movw sfrp, #word
			out->itype = RL78_movw;
			operand_sfrp(out, 0);
			operand_imm16(out, 1);
			break;
		case 0xcc: // mov [hl+byte], #byte
			out->itype = RL78_mov;
			operand_r_off_imm8(out, 0, rHL);
			operand_imm8(out, 1);
			break;
		case 0xcd: // mov saddr, #byte
			out->itype = RL78_mov;
			operand_saddr(out, 0);
			operand_imm8(out, 1);
			break;
		case 0xce: // mov sfr, #byte
			out->itype = RL78_mov;
			operand_sfr(out, 0);
			operand_imm8(out, 1);
			break;
		case 0xcf: // mov !addr16, #byte
			out->itype = RL78_mov;
			operand_addr16_abs_d(out, 0);
			operand_imm8(out, 1);
			break;
		case 0xd0: // cmp0 r
		case 0xd1:
		case 0xd2:
		case 0xd3:
			out->itype = RL78_cmp0;
			operand_r(out, 0, (RL78Register)(rX + code_lo));
			break;
		case 0xd4: // cmp0 saddr
			out->itype = RL78_cmp0;
			operand_saddr(out, 0);
			break;
		case 0xd5: // cmp0 !addr16
			out->itype = RL78_cmp0;
			operand_addr16_abs_d(out, 0);
			break;
		case 0xd6: // mulu
			out->itype = RL78_mulu;
			operand_r(out, 0, rX);
			break;
		case 0xd7: // ret
			out->itype = RL78_ret;
			break;
		case 0xd8: // mov x, saddr
			out->itype = RL78_mov;
			operand_r(out, 0, rX);
			operand_saddr(out, 1);
			break;
		case 0xe8: // mov b, saddr
			out->itype = RL78_mov;
			operand_r(out, 0, rB);
			operand_saddr(out, 1);
			break;
		case 0xf8: // mov c, saddr
			out->itype = RL78_mov;
			operand_r(out, 0, rC);
			operand_saddr(out, 1);
			break;
		case 0xd9: // mov x, !addr16
			out->itype = RL78_mov;
			operand_r(out, 0, rX);
			operand_addr16_abs_d(out, 1);
			break;
		case 0xe9: // mov b, !addr16
			out->itype = RL78_mov;
			operand_r(out, 0, rB);
			operand_addr16_abs_d(out, 1);
			break;
		case 0xf9: // mov c, !addr16
			out->itype = RL78_mov;
			operand_r(out, 0, rC);
			operand_addr16_abs_d(out, 1);
			break;
		case 0xda: // movw bc, saddrp
			out->itype = RL78_movw;
			operand_r(out, 0, rBC);
			operand_saddrp(out, 1);
			break;
		case 0xea: // movw de, saddrp
			out->itype = RL78_movw;
			operand_r(out, 0, rDE);
			operand_saddrp(out, 1);
			break;
		case 0xfa: // movw hl, saddrp
			out->itype = RL78_movw;
			operand_r(out, 0, rHL);
			operand_saddrp(out, 1);
			break;
		case 0xdb: // movw bc, !addr16
			out->itype = RL78_movw;
			operand_r(out, 0, rBC);
			operand_addr16_abs_d16(out, 1);
			break;
		case 0xeb: // movw de, !addr16
			out->itype = RL78_movw;
			operand_r(out, 0, rDE);
			operand_addr16_abs_d16(out, 1);
			break;
		case 0xfb: // movw hl, !addr16
			out->itype = RL78_movw;
			operand_r(out, 0, rHL);
			operand_addr16_abs_d16(out, 1);
			break;
		case 0xdc: // bc $addr20
			out->itype = RL78_bc;
			operand_addr_rel(out, 0);
			break;
		case 0xdd: // bz $addr20
			out->itype = RL78_bz;
			operand_addr_rel(out, 0);
			break;
		case 0xde: // bnc $addr20
			out->itype = RL78_bnc;
			operand_addr_rel(out, 0);
			break;
		case 0xdf: // bnz $addr20
			out->itype = RL78_bnz;
			operand_addr_rel(out, 0);
			break;
		case 0xec: // br !!addr20	PC <- addr20
			out->itype = RL78_br;
			operand_addr20_abs(out, 0);
			break;
		case 0xed: // br !addr16	PC <- 0000, addr16
			out->itype = RL78_br;
			operand_addr16_abs(out, 0);
			break;
		case 0xee: // br $!addr20	PC <- PC + 3 + jdisp16
			out->itype = RL78_br;
			operand_addr16_rel(out, 0);
			break;
		case 0xef: // br $addr20	PC <- PC + 2 + jdisp8
			out->itype = RL78_br;
			operand_addr_rel(out, 0);
			break;
		case 0xe0: // oneb r
		case 0xe1:
		case 0xe2:
		case 0xe3:
			out->itype = RL78_oneb;
			operand_r(out, 0, (RL78Register)(rX + code_lo));
			break;
		case 0xe4: // oneb saddr
			out->itype = RL78_oneb;
			operand_saddr(out, 0);
			break;
		case 0xe5: // oneb !addr16
			out->itype = RL78_oneb;
			operand_addr16_abs_d(out, 0);
			break;
		case 0xe6: // onew ax
		case 0xe7: // onew bc
			out->itype = RL78_onew;
			operand_r(out, 0, (RL78Register)(rAX + (code_lo & 1)));
			break;
		case 0xf0: // clrb r
		case 0xf1:
		case 0xf2:
		case 0xf3:
			out->itype = RL78_clrb;
			operand_r(out, 0, (RL78Register)(rX + code_lo));
			break;
		case 0xf4: // clrb saddr
			out->itype = RL78_clrb;
			operand_saddr(out, 0);
			break;
		case 0xf5: // clrb !addr16
			out->itype = RL78_clrb;
			operand_addr16_abs_d(out, 0);
			break;
		case 0xf6: // clrw ax
		case 0xf7: // clrw bc
			out->itype = RL78_clrw;
			operand_r(out, 0, (RL78Register)(rAX + (code_lo & 1)));
			break;
		case 0xfc: // call !!addr20
			out->itype = RL78_call;
			operand_addr20_abs(out, 0);
			break;
		case 0xfd: // call !addr16
			out->itype = RL78_call;
			operand_addr16_abs(out, 0);
			break;
		case 0xfe: // call $!addr20
			out->itype = RL78_call;
			operand_addr16_rel(out, 0);
			break;
		case 0xff: // brk1 - are all "undefined" insns valid as "brk1"?
			out->itype = RL78_brk1;
			break;
		default:
			return 0;
		}
	}

	// TODO Not sure how hw would treat prefix before insn not referencing
	// memory? We'll treat it as invalid insn for now.
	if (out->auxpref & kHasPrefix) {
		bool prefix_applied = false;
		for (int i = 0; i < RL78_MAX_OPERANDS; i++) {
			auto &op = out->ops[i];
			if (op.type != o_void && (op.specval & kHasPrefix)) {
				prefix_applied = true;
				break;
			}
		}
		if (!prefix_applied) {
			//msg("%x prefix not valid for this insn\n", out->ea);
			return 0;
		}
	}

	return out->size;
}

bool has_prefix(const insn_t &insn) {
	return insn.auxpref & kHasPrefix;
}

bool has_prefix(const op_t &op) {
	return op.specval & kHasPrefix;
}

// Convert |addr| to a 20bit addr, taking into account value of ES at insn.ea
// Returns BADDADDR if ES is not known
// If |require_prefix|, returns BADADDR if |insn| does not use ES
static ea_t calc_data_ea(const insn_t &insn, ea_t addr,
	bool require_prefix = false) {
	if (has_prefix(insn)) {
		auto es = get_sreg(insn.ea, rES);
		if (es == BADSEL) {
			return BADADDR;
		}
		addr |= es << 16;
	}
	else if (require_prefix) {
		return BADADDR;
	}
	return addr;
}

static void handle_operand(const insn_t &insn, int op_idx, bool is_alt,
	bool is_load, bool *flow) {
	auto &op = insn.ops[op_idx];
	ea_t ea;
	switch (op.type) {
	case o_imm:
		set_immd(insn.ea);
		break;
	case o_displ:
	case o_mem:
		ea = calc_data_ea(insn, op.addr, op.type == o_displ);
		if (ea == BADADDR) {
			break;
		}
		insn.create_op_data(ea, op);
		insn.add_dref(ea, op.offb, is_load ? dr_R : dr_W);
		break;
	case o_bit:
		switch (op.bit_base_type) {
		case o_mem:
			ea = calc_data_ea(insn, op.addr);
			if (ea == BADADDR) {
				break;
			}
			insn.create_op_data(ea, op);
			insn.add_dref(ea, op.offb, is_load ? dr_R : dr_W);
			break;
		}
		break;
	case o_near:
	case o_far:
		// mark call/jump near/far
		ea = map_code_ea(insn, op);
		bool is_far = op.type == o_far;
		bool is_call = has_insn_feature(insn.itype, CF_CALL);
		insn.add_cref(ea, op.offb, is_far ? (is_call ? fl_CF : fl_JF) : (is_call ? fl_CN : fl_JN));
		if (*flow && is_call) {
			*flow = func_does_return(ea);
		}
		break;
	}

	flags_t F = get_flags(insn.ea);
	if (!has_prefix(op) && may_create_stkvars() && !is_defarg(F, op.n)) {
		if (op.type == o_displ && op.ind_reg == rHL) {
			func_t *pfn = get_func(insn.ea);
			if (!pfn || !(pfn->flags & FUNC_FRAME)) {
				return;
			}
			if (insn.create_stkvar(op, op.addr, STKVAR_VALID_SIZE)) {
				op_stkvar(insn.ea, op.n);
			}
		}
	}
}

// TODO could be tricky to catch segreg updates via mem writes through prefixed
// insns, but probably will never happen in compiler generated code?
static void handle_segreg_update(const insn_t &insn, RL78Register reg) {
	// mov es, (#byte, a, saddr)
	// only mov from immediate sets a concrete value, others set to BADSEL
	// same for cs
	if (insn.itype == RL78_mov && insn.Op1.type == o_reg && insn.Op1.reg == reg) {
		auto &src = insn.Op2;
		sel_t val = BADSEL;
		if (src.type == o_imm) {
			val = src.value;
		}
		split_sreg_range(insn.ea, reg, val, SR_auto);
	}
}

static bool is_skip_insn(const insn_t &insn) {
	return insn.itype == RL78_skc || insn.itype == RL78_sknc ||
		insn.itype == RL78_skz || insn.itype == RL78_sknz ||
		insn.itype == RL78_skh || insn.itype == RL78_sknh;
}

static void trace_sp(const insn_t &insn) {
	adiff_t delta = 0;
	bool fuzzy = false;

	switch (insn.itype) {
	case RL78_push:
	case RL78_pop:
		delta = (insn.itype == RL78_push) ? -2 : 2;
		break;
	case RL78_addw:
	case RL78_subw:
		// addw/subw with sp as dst implies src is #byte
		if (!insn.Op1.is_reg(rSP)) {
			return;
		}
		delta = insn.Op2.value;
		if (insn.itype == RL78_subw) {
			delta = -delta;
		}
		break;
	case RL78_movw:
		// treat any mov to sp as untraceable
		if (!insn.Op1.is_reg(rSP)) {
			return;
		}
		fuzzy = true;
		break;
	default:
		return;
	}

	func_t *pfn = get_func(insn.ea);
	if (!pfn) {
		return;
	}
	if (fuzzy) {
#if (IDA_SDK_VERSION >= 710)
		// TODO is this correct?
		pfn->flags |= FUNC_FUZZY_SP;
		update_func(pfn);
#endif
		return;
	}

	add_auto_stkpnt(pfn, insn.ea + insn.size, delta);
}

static void create_func_frame(func_t *pfn) {
	ea_t ea = pfn->start_ea;
	insn_t insn;
	sval_t frsize = 0;
	ushort frregs = 0;
	// Don't track functions which `push psw`
	// This convention seems to only be used by "OS" funcs, which don't setup
	// a stack frame with local vars, anyways.
	bool saves[4]{};

	for (int i = 0; i < 10 && ea < pfn->end_ea; i++) {
		if (!decode_insn(&insn, ea)) {
			break;
		}
		// push rp
		if (insn.itype == RL78_push && !insn.Op1.is_reg(rPSW)) {
			auto &reg_saved = saves[insn.Op1.reg - rAX];
			if (!reg_saved) {
				frregs += 2;
				reg_saved = true;
			}
			else {
				frsize += 2;
			}
		}
		// movw hl, sp
		else if (insn.itype == RL78_movw && insn.Op1.is_reg(rHL) &&
			insn.Op2.is_reg(rSP)) {
			pfn->flags |= FUNC_FRAME | FUNC_BOTTOMBP;
			// expected to be last stack-setup insn
			break;
		}
		// subw sp, #byte
		else if (insn.itype == RL78_subw && insn.Op1.is_reg(rSP)) {
			frsize += insn.Op2.value;
		}
		// prologue sequence ended without setting hl
		else {
			// stop now so frame doesn't include space pushed for calls
			break;
		}
		ea += insn.size;
	}

	if (frsize || frregs) {
		add_frame(pfn, frsize, frregs, 0);
	}
}

static void is_sp_based(int *mode, const insn_t &insn, const op_t &op) {
	*mode = OP_SP_ADD | (op.is_reg(rSP) ? OP_SP_BASED : OP_FP_BASED);
}

static void fuse_far_ptrs(const insn_t &insn) {
	// try to create dref from insn pattern:
	// movw rp, #word
	// mov r, #byte
	// ...where r:rp is valid addr
	// This won't catch all far ptrs (e.g. when each value is push'd, or insn
	// order is inverted, etc), but it works most of the time.
	if (insn.itype == RL78_mov && insn.Op1.type == o_reg &&
		insn.Op2.type == o_imm && (insn.Op2.value >> 4) == 0) {
		insn_t prev;
		if (decode_prev_insn(&prev, insn.ea) > 0 && prev.itype == RL78_movw &&
			insn.Op1.type == o_reg && prev.Op2.type == o_imm) {
			// last sanity check - check for reg overlap
			if (prev.Op1.reg == rAX + (insn.Op1.reg / 2)) {
				return;
			}

			ea_t seg_base = insn.Op2.value << 16;
			ea_t to = seg_base | prev.Op2.value;

			refinfo_t ri;
			ri.init(REF_OFF32 | REFINFO_NOBASE, seg_base);
			op_offset_ex(prev.ea, prev.Op2.n, &ri);

			prev.add_dref(to, prev.Op2.offb, dr_O);
		}
	}
}

int emu(const insn_t &insn) {
	uint32 feature = insn.get_canon_feature();
	bool flow = (feature & CF_STOP) == 0;

	bool flag1 = is_forced_operand(insn.ea, 0);
	bool flag2 = is_forced_operand(insn.ea, 1);

	if (feature & CF_USE1) {
		handle_operand(insn, 0, flag1, true, &flow);
	}
	if (feature & CF_USE2) {
		handle_operand(insn, 1, flag2, true, &flow);
	}
	if (feature & CF_CHG1) {
		handle_operand(insn, 0, flag1, false, &flow);
	}
	if (feature & CF_CHG2) {
		handle_operand(insn, 1, flag2, false, &flow);
	}

	if (is_skip_insn(insn)) {
		insn_t next_insn;
		if (decode_insn(&next_insn, insn.ea + insn.size)) {
			add_cref(insn.ea, next_insn.ea + next_insn.size, fl_JN);
		}
	}

	if (flow) {
		add_cref(insn.ea, insn.ea + insn.size, fl_F);
	}

	handle_segreg_update(insn, rES);
	handle_segreg_update(insn, rCS);

	fuse_far_ptrs(insn);

	// handle sp modifications
	if (may_trace_sp()) {
		if (!flow) {
			recalc_spd(insn.ea);
		}
		else {
			trace_sp(insn);
		}
	}

	return 1;
}

class out_rl78_t : public outctx_t {
	out_rl78_t(void) : outctx_t(BADADDR) {} // not used
public:
	bool out_operand(const op_t &x);
	void out_insn(void);
};
CASSERT(sizeof(out_rl78_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_rl78_t)

bool out_rl78_t::out_operand(const op_t &x) {
	if (x.specval & kHasPrefix) {
		out_register(reg_names[rES]);
		out_symbol(':');
	}
	switch (x.type) {
	case o_void:
		return false;
	case o_reg:
		out_register(reg_names[x.reg]);
		return true;
	case o_phrase:
		out_symbol('[');
		switch (x.phrase) {
		case kHlReg:
			out_register(reg_names[rHL]);
			out_symbol('+');
			out_register(reg_names[x.ind_reg]);
			break;
		default:
			warning("o_phrase:%d\n", x.phrase);
			break;
		}
		out_symbol(']');
		return true;
	case o_displ:
		switch (x.phrase) {
		case kReg:
			out_symbol('[');
			out_register(reg_names[x.ind_reg]);
			// special case for [hl] as frame pointer
			if (is_stkvar(get_flags(insn.ea), x.n)) {
				out_symbol('+');
				out_value(x, OOF_ADDR);
			}
			out_symbol(']');
			break;
		case kReg8:
			out_symbol('[');
			out_register(reg_names[x.ind_reg]);
			out_symbol('+');
			out_value(x, OOF_ADDR | OOFW_16);
			out_symbol(']');
			break;
		case kReg16: {
			ea_t ea = calc_data_ea(insn, x.addr, true);
			if (ea == BADADDR || !out_name_expr(x, ea)) {
				out_value(x, OOF_ADDR | OOFW_16);
			}
			out_symbol('[');
			out_register(reg_names[x.ind_reg]);
			out_symbol(']');
		  } break;
		default:
			warning("o_displ:%d\n", x.phrase);
			break;
		}
		return true;
	case o_imm:
		out_symbol('#');
		out_value(x, OOFW_IMM);
		return true;
	case o_mem: {
		ea_t ea = calc_data_ea(insn, x.addr);
		if (ea == BADADDR || !out_name_expr(x, ea)) {
			out_value(x, OOF_ADDR | OOFW_24);
		}
	  } return true;
	case o_bit:
		if (x.addr_mode == kIndirect) {
			out_symbol('[');
		}
		switch (x.bit_base_type) {
		case o_reg:
			out_register(reg_names[x.reg]);
			break;
		case o_mem: {
			ea_t ea = calc_data_ea(insn, x.addr);
			if (ea == BADADDR || !out_name_expr(x, ea)) {
				out_value(x, OOF_ADDR | OOFW_24);
			}
		  } break;
		default:
			warning("o_bit:%d\n", x.bit_base_type);
			break;
		}
		if (x.addr_mode == kIndirect) {
			out_symbol(']');
		}
		out_symbol('.');
		out_value(x, OOFW_IMM);
		return true;
	case o_near:
	case o_far: {
		ea_t v = to_ea(insn.cs, x.addr);
		if (!out_name_expr(x, v, x.addr)) {
			out_value(x, OOF_ADDR | OOF_NUMBER | OOFW_24);
		}
	  } return true;
	default:
		msg("%s:%d\n", __func__, x.type);
		return false;
	}
}

void out_rl78_t::out_insn(void) {
	out_mnemonic();

	out_one_operand(0);
	for (int i = 1; i < RL78_MAX_OPERANDS; i++) {
		if (insn.ops[i].type != o_void) {
			out_symbol(',');
			out_char(' ');
			out_one_operand(i);
		}
	}

	out_immchar_cmts();
	flush_outbuf();
}

idaman int ida_export is_align_insn(ea_t ea) {
	insn_t insn;
	if (decode_insn(&insn, ea) < 1) {
		return 0;
	}
	switch (insn.itype) {
	case RL78_brk1:
		break;
	default:
		return 0;
	}
	return insn.size;
}

static void newfile(char *fname) {
	// load config file or smth
	// TODO should respect device specific code/data flash + ram ranges
}

struct RegMap {
	const char *regname;
	const char *main_regname;
	bitrange_t bitrange;
};

static const RegMap reg_map[] = {
	{ reg_names[rX], reg_names[rAX], bitrange_t{ 0, 8 } },
	{ reg_names[rA], reg_names[rAX], bitrange_t{ 8, 8 } },
	{ reg_names[rC], reg_names[rBC], bitrange_t{ 0, 8 } },
	{ reg_names[rB], reg_names[rBC], bitrange_t{ 8, 8 } },
	{ reg_names[rE], reg_names[rDE], bitrange_t{ 0, 8 } },
	{ reg_names[rD], reg_names[rDE], bitrange_t{ 8, 8 } },
	{ reg_names[rL], reg_names[rHL], bitrange_t{ 0, 8 } },
	{ reg_names[rH], reg_names[rHL], bitrange_t{ 8, 8 } },
	{ reg_names[rAX], reg_names[rAX], },
	{ reg_names[rBC], reg_names[rBC], },
	{ reg_names[rDE], reg_names[rDE], },
	{ reg_names[rHL], reg_names[rHL], },
};

static RegMap cur_query = {
	"invalid", "invalid"
};

static bool bitrange_overlap(const bitrange_t &a, const bitrange_t &b) {
	if (a.empty() || b.empty()) {
		return true;
	}
	if (a.bitoff() >= b.bitoff()) {
		return a.bitoff() < b.bitoff() + b.bitsize();
	}
	if (a.bitoff() + a.bitsize() > b.bitoff()) {
		return true;
	}
	return false;
}

// This is supposedly not required, but eh?
static int get_reg_info(const char **main_regname, bitrange_t *bitrange,
	const char *regname) {
	for (auto &mapping : reg_map) {
		if (!strcmp(mapping.regname, regname)) {
			if (bitrange) {
				// reg to test against
				*main_regname = mapping.main_regname;
				*bitrange = mapping.bitrange;
				cur_query = mapping;
				return 1;
			}
			else if (!strcmp(mapping.main_regname, cur_query.main_regname) &&
				bitrange_overlap(mapping.bitrange, cur_query.bitrange)) {
				// overlaps target reg
				*main_regname = mapping.main_regname;
				return 1;
			}
			// no overlap
			return -1;
		}
	}
	// not a reg
	return -1;
}

// not sure why, but this doesn't seem to be called very often
static int may_be_func(const insn_t &insn, int state) {
	int prob = 0;
	if (insn.itype == RL78_push) {
		prob = 100;
	}
	return prob;
}

/*
2F0EE is more complex...

10 subw    ax, #X | sub a, #X	adj
10 shr      a, #X

9  cmpw    ax, #N | cmp a, #N	ncases

8  skc
7  br      default				default if adj(idx) >= ncases

7, 8 could be replaced with `bnc default` (closer target)

6  shrw    ax, #8				move a to x

common chunk
5  movw    bc, ax
   mov     es, #2				don't need to care since we track segregs
4  mov     a, es:byte_2CEE2[bc]
3  shlw    bc, #1
2  mov     cs, a
1  movw    ax, es:word_2CED8[bc]
0  br      ax
*/
//#define JUMP_DEBUG
#include <jptcmn.cpp>
static const char rl78_jmp_roots[] = { 1, 2, 0 };
static const char rl78_jmp_depends[][2] = {
	{ 1, 2 },	// 0: ax, cs
	{ 3 },		// 1: bc
	{ 4 },		// 2: cs
	{ 5 },		// 3: bc
	{ 5 },		// 4: bc
	{ -6 },	    // 5: ax
	{ },		// 6: optional shrw ax, #8
};
class rl78_jmp_pattern_t : public jump_pattern_t {
public:
	rl78_jmp_pattern_t(switch_info_t *si)
		: jump_pattern_t(si, rl78_jmp_roots, rl78_jmp_depends) {
	}
	bool jpi6() final;
	bool jpi5() final;
	bool jpi4() final;
	bool jpi3() final;
	bool jpi2() final;
	bool jpi1() final;
	bool jpi0() final;

	RL78Register table_reg;
	ea_t ax_table{ BADADDR };
	ea_t cs_table{ BADADDR };
};

bool rl78_jmp_pattern_t::jpi6() {
	msg("%x jpi6: %s\n", insn.ea, instructions[insn.itype].name);
	return true;
}

bool rl78_jmp_pattern_t::jpi5() {
	return insn.itype == RL78_movw && insn.Op1.is_reg(table_reg) && insn.Op2.is_reg(rAX);
}

bool rl78_jmp_pattern_t::jpi4() {
	// don't necessarily need to limit to rA here (could be immediate in jpi2)
	if (insn.itype == RL78_mov && insn.Op1.is_reg(rA) &&
		insn.Op2.type == o_displ && insn.Op2.phrase == kReg16 && insn.Op2.ind_reg == table_reg) {
		ea_t ea = calc_data_ea(insn, insn.Op2.addr, true);
		if (ea == BADADDR) {
			return false;
		}
		cs_table = ea;
		return true;
	}
	return false;
}

bool rl78_jmp_pattern_t::jpi3() {
	return insn.itype == RL78_shlw && insn.Op1.is_reg(table_reg) && insn.Op2.is_imm(1);
}

bool rl78_jmp_pattern_t::jpi2() {
	if (!(insn.itype == RL78_mov && insn.Op1.is_reg(rCS))) {
		return false;
	}
	bool src_is_a = insn.Op2.is_reg(rA);
	if (!src_is_a) {
		// would be simple to handle, just haven't seen it
		msg("jmptbl: cs not from reg\n");
	}
	return src_is_a;
}

bool rl78_jmp_pattern_t::jpi1() {
	if (insn.itype == RL78_movw && insn.Op1.is_reg(rAX) &&
		insn.Op2.type == o_displ && insn.Op2.phrase == kReg16) {
		ea_t ea = calc_data_ea(insn, insn.Op2.addr, true);
		if (ea == BADADDR) {
			return false;
		}
		ax_table = ea;
		table_reg = (RL78Register)insn.Op2.ind_reg;
		return true;
	}
	return false;
}

bool is_br_ax(const insn_t &insn) {
	return insn.itype == RL78_br && insn.Op1.is_reg(rAX);
}

bool rl78_jmp_pattern_t::jpi0() {
	return is_br_ax(insn);
}

static void create_table(switch_info_t *si, const insn_t &insn, jump_table_type_t jtt) {
	//msg("create table %d @ %x : %x %x %x %x\n", jtt, insn.ea, si->startea, si->defjump, si->elbase, si->expr_ea);
	//set_switch_info(insn.ea, *si);
}

static jump_table_type_t is_rl78_pattern(switch_info_t *si, const insn_t &insn) {
	rl78_jmp_pattern_t jp(si);
	return jp.match(insn) ? JT_FLAT32 : JT_NONE;
}

static int is_switch(switch_info_t *si, const insn_t &insn) {
	if (!is_br_ax(insn)) {
		return 0;
	}
	is_pattern_t *const patterns[] = {
		is_rl78_pattern,
	};
	return check_for_table_jump(si, insn, patterns, qnumber(patterns),
		create_table) ? 1 : 0;
}

static ssize_t idaapi notify(void *, int msgid, va_list va) {
	switch (msgid) {
	case processor_t::ev_newfile:
		newfile(va_arg(va, char *));
		break;
	case processor_t::ev_creating_segm:
		break;
	case processor_t::ev_ana_insn:
		return ana(va_arg(va, insn_t *));
	case processor_t::ev_emu_insn:
		return emu(*va_arg(va, insn_t *));
	case processor_t::ev_out_mnem:
		break;
	case processor_t::ev_out_insn: {
		auto ctx = va_arg(va, outctx_t *);
		out_insn(*ctx);
	  } break;
	case processor_t::ev_out_operand: {
		auto ctx = va_arg(va, outctx_t *);
		auto op = va_arg(va, const op_t *);
		return out_opnd(*ctx, *op) ? 1 : -1;
	  }
	case processor_t::ev_is_align_insn:
		return is_align_insn(va_arg(va, ea_t));
	case processor_t::ev_get_reg_info: {
		auto main_regname = va_arg(va, const char **);
		auto bitrange = va_arg(va, bitrange_t *);
		auto regname = va_arg(va, const char *);
		return get_reg_info(main_regname, bitrange, regname);
	  }
	case processor_t::ev_create_func_frame:
		create_func_frame(va_arg(va, func_t *));
		return 1;
	case processor_t::ev_is_sp_based: {
		auto mode = va_arg(va, int *);
		auto insn = va_arg(va, insn_t *);
		auto op = va_arg(va, op_t *);
		is_sp_based(mode, *insn, *op);
		return 1;
	  }
	case processor_t::ev_may_be_func: {
		auto insn = va_arg(va, const insn_t *);
		auto state = va_arg(va, int);
		return may_be_func(*insn, state);
	  }
	case processor_t::ev_is_switch: {
		auto si = va_arg(va, switch_info_t *);
		auto insn = va_arg(va, insn_t *);
		return is_switch(si, *insn);
	  }
	case processor_t::ev_calc_switch_cases: {
		auto casevec = va_arg(va, casevec_t *);
		auto targets = va_arg(va, eavec_t *);
		auto insn_ea = va_arg(va, ea_t);
		auto si = va_arg(va, switch_info_t *);
	  } break;
	case processor_t::ev_create_switch_xrefs: {
		auto insn_ea = va_arg(va, ea_t);
		auto si = va_arg(va, switch_info_t *);
	  } break;
	}
	return 0;
}


static const char *const short_names[] = {
	"rl78",
	nullptr
};

static const char *const long_names[] = {
	"Renesas RL78",
	nullptr
};

static const asm_t *const assemblers[] = {
	&assembler,
	nullptr
};

idaman processor_t ida_module_data LPH = {
	IDP_INTERFACE_VERSION,
	0x8000 + 0x78,
	PR_SEGS | PRN_HEX | PR_ALIGN_INSN |
	PR_USE32 | PR_DEFSEG32,
	0,
	8,
	8,
	short_names,
	long_names,
	assemblers,
	notify,
	reg_names,
	qnumber(reg_names),
	rVcs,
	rES,
	1,
	rVcs,
	rVds,
	nullptr,
	nullptr,
	0,
	RL78_itype_count,
	instructions,
	0,
	{},
	RL78_ret,
	nullptr
};
