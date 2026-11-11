#include <algorithm>
#include <cmath>
#include <cstring>
#include <mutex>

#include "Core/MemScan.h"
#include "Core/MemMap.h"
#include "Core/MIPS/MIPS.h"
#include "Core/MIPS/MIPSAnalyst.h"
#include "Core/MIPS/MIPSDebugInterface.h"
#include "Core/Debugger/Breakpoints.h"
#include "Core/Debugger/DisassemblyManager.h"
#include <map>
#include <atomic>
#include <cstdio>
#include <unordered_set>

static const uint32_t SCAN_START = 0x08800000;  // awal RAM user (8 MB pertama = kernel)
// Akhir RAM mengikuti ukuran RAM yang aktif: PSP-1000 = 32 MB -> 0x0A000000 (user 24 MB),
// PSP-2000+ = 64 MB -> 0x0C000000. (Pastikan nama Memory::g_MemorySize ada di versimu.)
static uint32_t ScanEnd() { return 0x08000000u + Memory::g_MemorySize; }
static const uint32_t BLOCK = 0x10000;
static const size_t MAX_HITS = 300000;

int MemScanner::SizeOf(ScanType t) {
	switch (t) {
	case ScanType::U8: return 1;
	case ScanType::U16: return 2;
	default: return 4;
	}
}

uint32_t MemScanner::ReadAt(uint32_t addr, int size) {
	if (!Memory::IsValidRange(addr, size))
		return 0;
	if (size == 1) return Memory::ReadUnchecked_U8(addr);
	if (size == 2) return Memory::ReadUnchecked_U16(addr);
	return Memory::ReadUnchecked_U32(addr);
}

bool MemScanner::WriteAt(uint32_t addr, int size, uint32_t value) {
	if (!Memory::IsValidRange(addr, size))
		return false;
	if (size == 1) Memory::WriteUnchecked_U8((uint8_t)value, addr);
	else if (size == 2) Memory::WriteUnchecked_U16((uint16_t)value, addr);
	else Memory::WriteUnchecked_U32(value, addr);
	if (currentMIPS)
		currentMIPS->InvalidateICacheRangeDeferred(addr & ~3u, 8);
	return true;
}

static float AsFloat(uint32_t raw) {
	float f;
	memcpy(&f, &raw, 4);
	return f;
}

static bool FloatNear(uint32_t a, uint32_t b) {
	float fa = AsFloat(a), fb = AsFloat(b);
	if (std::isnan(fa) || std::isnan(fb))
		return a == b;
	return std::fabs(fa - fb) <= 1e-5f * std::max(1.0f, std::fabs(fb));
}

static bool Matches(ScanType t, ScanCmp cmp, uint32_t cur, uint32_t prev, uint32_t target) {
	switch (cmp) {
	case ScanCmp::Equal:
		return t == ScanType::Float ? FloatNear(cur, target) : cur == target;
	case ScanCmp::Changed:
		return cur != prev;
	case ScanCmp::Unchanged:
		return cur == prev;
	case ScanCmp::Greater:
		return t == ScanType::Float ? AsFloat(cur) > AsFloat(prev) : cur > prev;
	case ScanCmp::Less:
		return t == ScanType::Float ? AsFloat(cur) < AsFloat(prev) : cur < prev;
	case ScanCmp::IncBy:
	case ScanCmp::DecBy: {
		const bool inc = cmp == ScanCmp::IncBy;
		if (t == ScanType::Float) {
			float e = inc ? AsFloat(prev) + AsFloat(target) : AsFloat(prev) - AsFloat(target);
			uint32_t bits;
			memcpy(&bits, &e, 4);
			return FloatNear(cur, bits);
		}
		const uint32_t mask = t == ScanType::U8 ? 0xFFu : (t == ScanType::U16 ? 0xFFFFu : 0xFFFFFFFFu);
		return cur == (((inc ? prev + target : prev - target)) & mask);
	}
	}
	return false;
}

void MemScanner::Reset() {
	hits_.clear();
	hits_.shrink_to_fit();
	truncated_ = false;
	wide_ = false;
	hasScan_ = false;
	unknown_ = false;
	unknownCount_ = 0;
	snap_.clear();
	snap_.shrink_to_fit();
	alive_.clear();
	alive_.shrink_to_fit();
}

void MemScanner::FirstUnknown(ScanType type) {
	Reset();
	type_ = type;
	const uint32_t start = SCAN_START, end = ScanEnd();
	if (end <= start || !Memory::IsActive() || !Memory::IsValidRange(start, end - start))
		return;
	const int size = SizeOf(type);
	const uint32_t len = end - start;
	snap_.resize(len);
	memcpy(snap_.data(), Memory::GetPointerUnchecked(start), len);
	alive_.assign(len / size, 1);
	unknownCount_ = len / size;
	unknown_ = true;
	hasScan_ = true;
}

void MemScanner::NextUnknown(ScanCmp cmp, uint32_t rawValue) {
	const uint32_t start = SCAN_START, end = ScanEnd(), len = end - start;
	if (snap_.size() != len || !Memory::IsActive() || !Memory::IsValidRange(start, len))
		return;
	const uint8_t *ram = Memory::GetPointerUnchecked(start);
	const int size = SizeOf(type_);
	uint32_t count = 0;
	for (uint32_t i = 0; i < (uint32_t)alive_.size(); i++) {
		if (!alive_[i])
			continue;
		const uint32_t off = i * (uint32_t)size;
		uint32_t cur = 0, prev = 0;
		memcpy(&cur, ram + off, size);  // host little-endian, sama dengan Memory::ReadUnchecked
		memcpy(&prev, snap_.data() + off, size);
		if (Matches(type_, cmp, cur, prev, rawValue)) {
			count++;
			memcpy(snap_.data() + off, &cur, size);  // pembanding berikutnya = nilai terbaru
		} else {
			alive_[i] = 0;
		}
	}
	unknownCount_ = count;
	if (count <= MAX_HITS) {
		// Sudah cukup sedikit: ubah jadi daftar hasil biasa.
		hits_.clear();
		hits_.reserve(count);
		for (uint32_t i = 0; i < (uint32_t)alive_.size(); i++) {
			if (!alive_[i])
				continue;
			const uint32_t off = i * (uint32_t)size;
			uint32_t cur = 0;
			memcpy(&cur, ram + off, size);
			hits_.push_back({ start + off, cur, size, HitKind::Value, nullptr });
		}
		unknown_ = false;
		snap_.clear();
		snap_.shrink_to_fit();
		alive_.clear();
		alive_.shrink_to_fit();
	}
}

void MemScanner::First(ScanType type, uint32_t rawValue) {
	Reset();
	type_ = type;
	hasScan_ = true;
	const int size = SizeOf(type);
	for (uint64_t base = SCAN_START; base < ScanEnd() && !truncated_; base += BLOCK) {
		if (!Memory::IsValidRange((uint32_t)base, BLOCK))
			continue;
		for (uint32_t off = 0; off < BLOCK; off += size) {
			uint32_t addr = (uint32_t)base + off;
			uint32_t cur = ReadAt(addr, size);
			if (Matches(type, ScanCmp::Equal, cur, 0, rawValue)) {
				hits_.push_back({ addr, cur, size, HitKind::Value, nullptr });
				if (hits_.size() >= MAX_HITS) {
					truncated_ = true;
					break;
				}
			}
		}
	}
}

void MemScanner::Next(ScanCmp cmp, uint32_t rawValue) {
	if (!hasScan_ || wide_)
		return;
	if (unknown_) {
		NextUnknown(cmp, rawValue);
		return;
	}
	std::vector<ScanHit> kept;
	kept.reserve(hits_.size());
	for (ScanHit h : hits_) {
		uint32_t cur = ReadAt(h.addr, h.size);
		if (Matches(type_, cmp, cur, h.value, rawValue)) {
			h.value = cur;
			kept.push_back(h);
		}
	}
	hits_.swap(kept);
}

struct WideConst {
	uint32_t bits;
	uint16_t lui;
	const char *tag;
};

// Konstanta rasio layar yang umum dipatch untuk widescreen.
static const WideConst kWideConsts[] = {
	{ 0x3FAAAAAB, 0x3FAB, "4:3 (1.3333)" },
	{ 0x3FAAAAAB, 0x3FAA, "4:3 (1.3333)" },
	{ 0x3F400000, 0x3F40, "3/4 (0.75)" },
	{ 0x3F100000, 0x3F10, "9/16 (0.5625)" },
	{ 0x3FE38E39, 0x3FE3, "16:9 (1.7778)" },
	{ 0x3FE1E1E2, 0x3FE1, "480/272 (1.7647)" },
};

void MemScanner::ScanWidescreen() {
	Reset();
	hasScan_ = true;
	wide_ = true;
	type_ = ScanType::U32;
	for (uint64_t base = SCAN_START; base < ScanEnd() && !truncated_; base += BLOCK) {
		if (!Memory::IsValidRange((uint32_t)base, BLOCK))
			continue;
		for (uint32_t off = 0; off < BLOCK; off += 4) {
			uint32_t addr = (uint32_t)base + off;
			uint32_t w = Memory::ReadUnchecked_U32(addr);
			// 1) float data mentah
			for (const WideConst &c : kWideConsts) {
				if (w == c.bits) {
					hits_.push_back({ addr, w, 4, HitKind::Value, c.tag });
					break;
				}
			}
			// 2) instruksi "lui rt, imm" (opcode 001111, rs = 0)
			if ((w & 0xFFE00000u) == 0x3C000000u) {
				uint16_t imm = (uint16_t)(w & 0xFFFF);
				for (const WideConst &c : kWideConsts) {
					if (imm == c.lui) {
						hits_.push_back({ addr, w, 2, HitKind::Lui, c.tag });
						break;
					}
				}
			}
			if (hits_.size() >= MAX_HITS) {
				truncated_ = true;
				break;
			}
		}
	}
}

// ===========================================================================
// MemFreezer
// ===========================================================================
static std::mutex g_freezeLock;
static std::vector<FreezeEntry> g_freezes;
static const int SIG_BEFORE = 16;
static const int SIG_AFTER = 16;

// Ambil byte di sekitar alamat. Byte target sendiri dijadikan wildcard (-1) karena nilainya berubah.
static void CaptureSig(FreezeEntry &e) {
	e.sig.clear();
	for (int i = -SIG_BEFORE; i < e.size + SIG_AFTER; i++) {
		uint32_t a = e.addr + i;
		bool isTarget = i >= 0 && i < e.size;
		if (isTarget || a < SCAN_START || !Memory::IsValidRange(a, 1))
			e.sig.push_back(-1);
		else
			e.sig.push_back((int16_t)Memory::ReadUnchecked_U8(a));
	}
}

int MemFreezer::Add(uint32_t addr, int size, HitKind kind, uint32_t value, const std::string &label) {
	FreezeEntry e;
	e.addr = addr;
	e.size = size;
	e.kind = kind;
	e.value = value;
	e.label = label;
	e.enabled = true;
	CaptureSig(e);
	std::lock_guard<std::mutex> guard(g_freezeLock);
	// Alamat sama -> perbarui entri lama, jangan dobel.
	for (size_t i = 0; i < g_freezes.size(); i++) {
		if (g_freezes[i].addr == addr && g_freezes[i].size == size) {
			g_freezes[i] = e;
			return (int)i;
		}
	}
	g_freezes.push_back(e);
	return (int)g_freezes.size() - 1;
}

void MemFreezer::Remove(int idx) {
	std::lock_guard<std::mutex> guard(g_freezeLock);
	if (idx >= 0 && idx < (int)g_freezes.size())
		g_freezes.erase(g_freezes.begin() + idx);
}

void MemFreezer::ClearAll() {
	std::lock_guard<std::mutex> guard(g_freezeLock);
	g_freezes.clear();
}

void MemFreezer::SetEnabled(int idx, bool on) {
	std::lock_guard<std::mutex> guard(g_freezeLock);
	if (idx >= 0 && idx < (int)g_freezes.size())
		g_freezes[idx].enabled = on;
}

void MemFreezer::SetValue(int idx, uint32_t value) {
	std::lock_guard<std::mutex> guard(g_freezeLock);
	if (idx >= 0 && idx < (int)g_freezes.size())
		g_freezes[idx].value = value;
}

int MemFreezer::Count() {
	std::lock_guard<std::mutex> guard(g_freezeLock);
	return (int)g_freezes.size();
}

bool MemFreezer::Get(int idx, FreezeEntry *out) {
	std::lock_guard<std::mutex> guard(g_freezeLock);
	if (idx < 0 || idx >= (int)g_freezes.size())
		return false;
	*out = g_freezes[idx];
	return true;
}

void MemFreezer::Apply() {
	MemPatcher::Apply();  // patch instruksi aktif ikut dijaga di sini
	std::lock_guard<std::mutex> guard(g_freezeLock);
	if (g_freezes.empty() || !Memory::IsActive())
		return;
	for (const FreezeEntry &e : g_freezes) {
		if (!e.enabled || !Memory::IsValidRange(e.addr, e.size))
			continue;
		// Tulis hanya jika berbeda (hemat, dan tidak membatalkan cache JIT terus-menerus).
		if (MemScanner::ReadAt(e.addr, e.size) == e.value)
			continue;
		if (e.kind == HitKind::Lui)
			MemScanner::WriteAt(e.addr, e.size, e.value);  // dengan invalidate JIT
		else if (e.size == 1)
			Memory::WriteUnchecked_U8((uint8_t)e.value, e.addr);
		else if (e.size == 2)
			Memory::WriteUnchecked_U16((uint16_t)e.value, e.addr);
		else
			Memory::WriteUnchecked_U32(e.value, e.addr);
	}
}

// Cari lokasi yang byte sekitarnya paling mirip dengan signature.
// Toleransi 25% byte berbeda (struktur di sekitar data biasanya ikut berubah sedikit).
static bool FindBySig(const FreezeEntry &e, uint32_t *bestAddr, int *bestMiss) {
	const uint32_t start = SCAN_START, end = ScanEnd();
	if (e.sig.empty() || !Memory::IsActive() || !Memory::IsValidRange(start, end - start))
		return false;
	const uint8_t *ram = Memory::GetPointerUnchecked(start);
	const int n = (int)e.sig.size();
	int fixedCount = 0;
	for (int16_t b : e.sig)
		if (b >= 0) fixedCount++;
	if (fixedCount < 8)
		return false;  // terlalu sedikit info, hasil pasti ngawur
	const int allowed = fixedCount / 4;

	bool found = false;
	int bMiss = allowed + 1;
	uint32_t bAddr = 0;
	uint32_t bDist = 0xFFFFFFFFu;
	const uint32_t lo = start + SIG_BEFORE;
	const uint32_t hi = end - e.size - SIG_AFTER;
	for (uint32_t a = (lo + e.size - 1) & ~(uint32_t)(e.size - 1); a <= hi; a += e.size) {
		const uint8_t *p = ram + (a - start) - SIG_BEFORE;
		int miss = 0;
		for (int i = 0; i < n; i++) {
			if (e.sig[i] >= 0 && p[i] != (uint8_t)e.sig[i]) {
				if (++miss > bMiss)  // sudah lebih buruk dari kandidat terbaik
					break;
			}
		}
		if (miss > bMiss || miss > allowed)
			continue;
		uint32_t dist = a > e.addr ? a - e.addr : e.addr - a;
		if (!found || miss < bMiss || (miss == bMiss && dist < bDist)) {
			found = true;
			bMiss = miss;
			bAddr = a;
			bDist = dist;
		}
	}
	if (found) {
		*bestAddr = bAddr;
		*bestMiss = bMiss;
	}
	return found;
}

bool MemFreezer::Relocate(int idx, int *outMisses, uint32_t *outOld, uint32_t *outNew) {
	FreezeEntry e;
	if (!Get(idx, &e))
		return false;
	uint32_t newAddr = 0;
	int miss = 0;
	if (!FindBySig(e, &newAddr, &miss))
		return false;
	if (outMisses) *outMisses = miss;
	if (outOld) *outOld = e.addr;
	if (outNew) *outNew = newAddr;
	e.addr = newAddr;
	CaptureSig(e);  // segarkan signature di lokasi baru supaya bisa ikut berpindah lagi
	std::lock_guard<std::mutex> guard(g_freezeLock);
	if (idx < (int)g_freezes.size()) {
		bool wasEnabled = g_freezes[idx].enabled;
		g_freezes[idx] = e;
		g_freezes[idx].enabled = wasEnabled;
	}
	return true;
}

int MemFreezer::RelocateAll() {
	int ok = 0;
	for (int i = 0, n = Count(); i < n; i++) {
		if (Relocate(i, nullptr, nullptr, nullptr))
			ok++;
	}
	return ok;
}

// ===========================================================================
// MemWatch
// ===========================================================================
static std::mutex g_watchLock;
static std::atomic<bool> g_watchActive{ false };
static uint32_t g_watchStart = 0, g_watchEnd = 0;
static std::atomic<uint32_t> g_rawCalls{ 0 }, g_matchCalls{ 0 };
static std::map<uint64_t, AccessRecord> g_records;  // kunci: (pc << 1) | write
static const size_t MAX_RECORDS = 2000;

bool MemWatch::Start(uint32_t addr, int size) {
	if (size <= 0 || !Memory::IsValidRange(addr, size))
		return false;
	Stop();
	{
		std::lock_guard<std::mutex> guard(g_watchLock);
		g_watchStart = addr;
		g_watchEnd = addr + size;
		g_records.clear();
		g_rawCalls = 0;
		g_matchCalls = 0;
		g_watchActive = true;
	}
	// BREAK_ACTION_NONE: tidak pause dan tidak menulis log; kita hanya butuh hook di MemCheck::Apply.
	// (Jika log kosong padahal alamat jelas diakses, coba ganti ke BREAK_ACTION_LOG.)
	g_breakpoints.AddMemCheck(g_watchStart, g_watchEnd, MEMCHECK_READWRITE, BREAK_ACTION_NONE);
	g_breakpoints.Frame();  // segarkan cache rentang memcheck sekarang, jangan menunggu frame berikutnya
	return true;
}

void MemWatch::Stop() {
	uint32_t s, e;
	{
		std::lock_guard<std::mutex> guard(g_watchLock);
		if (!g_watchActive)
			return;
		g_watchActive = false;
		s = g_watchStart;
		e = g_watchEnd;
	}
	g_breakpoints.RemoveMemCheck(s, e);
}

bool MemWatch::Active() { return g_watchActive; }

uint32_t MemWatch::WatchAddr() {
	std::lock_guard<std::mutex> guard(g_watchLock);
	return g_watchStart;
}

int MemWatch::WatchSize() {
	std::lock_guard<std::mutex> guard(g_watchLock);
	return (int)(g_watchEnd - g_watchStart);
}

void MemWatch::Clear() {
	std::lock_guard<std::mutex> guard(g_watchLock);
	g_records.clear();
}

const char *MemWatch::RegName(int r) {
	static const char *const names[32] = {
		"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
		"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
	};
	return (r >= 0 && r < 32) ? names[r] : "?";
}

void MemWatch::Record(uint32_t start, uint32_t end, uint32_t addr, bool write, int size, uint32_t pc) {
	if (!g_watchActive)
		return;
	g_rawCalls++;
	std::lock_guard<std::mutex> guard(g_watchLock);
	if (start != g_watchStart || end != g_watchEnd)
		return;  // memcheck milik orang lain (debugger), bukan pantauan kita
	g_matchCalls++;

	// Cari instruksi yang benar-benar mengakses (sama dengan ExecOpMemCheck: kasus delay slot).
	uint32_t ipc = pc;
	int asz = 0;
	if (Memory::IsValidRange(ipc, 4)) {
		asz = MIPSAnalyst::OpMemoryAccessSize(ipc);
		if (asz == 0 && MIPSAnalyst::OpHasDelaySlot(ipc) && Memory::IsValidRange(ipc + 4, 4)) {
			ipc += 4;
			asz = MIPSAnalyst::OpMemoryAccessSize(ipc);
		}
	}

	const uint64_t key = ((uint64_t)ipc << 1) | (write ? 1 : 0);
	auto it = g_records.find(key);
	if (it != g_records.end()) {
		it->second.count++;
		it->second.addr = addr;
		return;
	}
	if (g_records.size() >= MAX_RECORDS)
		return;

	AccessRecord r;
	r.pc = ipc;
	r.addr = addr;
	r.size = asz;
	r.write = write;
	r.count = 1;
	if (asz > 0) {
		const uint32_t op = Memory::ReadUnchecked_U32(ipc);
		const uint32_t opc = op >> 26;
		r.baseReg = (int)((op >> 21) & 31);
		// VFPU lv.s/sv.s/lv.q/sv.q memakai offset 14 bit << 2; lainnya 16 bit bertanda.
		if (opc == 0x32 || opc == 0x3A || opc == 0x36 || opc == 0x3E)
			r.offset = (int16_t)(op & 0xFFFC);
		else
			r.offset = (int16_t)(op & 0xFFFF);
		r.baseValue = addr - (uint32_t)r.offset;
	}
	g_records[key] = r;
}

std::vector<AccessRecord> MemWatch::Snapshot() {
	std::vector<AccessRecord> out;
	{
		std::lock_guard<std::mutex> guard(g_watchLock);
		out.reserve(g_records.size());
		for (auto &kv : g_records)
			out.push_back(kv.second);
	}
	// Disassembly di thread UI (DisassemblyManager tidak dipakai thread emulasi).
	for (AccessRecord &r : out) {
		DisassemblyLineInfo line;
		g_disassemblyManager.getLine(r.pc, true, line, currentDebugMIPS);
		r.text = line.name + (line.params.empty() ? "" : " " + line.params);
	}
	std::sort(out.begin(), out.end(), [](const AccessRecord &a, const AccessRecord &b) {
		return a.count > b.count;
	});
	return out;
}

std::string MemWatch::DebugInfo() {
	uint32_t s, e;
	{
		std::lock_guard<std::mutex> guard(g_watchLock);
		s = g_watchStart;
		e = g_watchEnd;
	}
	bool found = false;
	uint32_t numHits = 0;
	if (g_watchActive) {
		for (const MemCheck &m : g_breakpoints.GetMemChecks()) {
			if (m.start == s && m.end == e) {
				found = true;
				numHits = (uint32_t)m.numHits;
			}
		}
	}
	char buf[220];
	snprintf(buf, sizeof(buf), "Diagnosis: memcheck %s, hit memcheck=%u, Record dipanggil=%u, cocok=%u, HasMemChecks=%d",
		found ? "terdaftar" : "TIDAK ada", numHits, (unsigned)g_rawCalls, (unsigned)g_matchCalls, g_breakpoints.HasMemChecks() ? 1 : 0);
	return buf;
}

std::string MemDisasm(uint32_t pc) {
	DisassemblyLineInfo line;
	g_disassemblyManager.getLine(pc, true, line, currentDebugMIPS);
	return line.name + (line.params.empty() ? "" : " " + line.params);
}

// ===========================================================================
// MemPatcher
// ===========================================================================
static std::mutex g_patchLock;
static std::vector<PatchEntry> g_patches;

int MemPatcher::Add(uint32_t addr, uint32_t newOp, const std::string &label) {
	if ((addr & 3) != 0 || !Memory::IsActive() || !Memory::IsValidRange(addr, 4))
		return -1;
	PatchEntry e;
	e.addr = addr;
	e.value = newOp;
	e.label = label;
	e.enabled = true;
	{
		std::lock_guard<std::mutex> guard(g_patchLock);
		for (size_t i = 0; i < g_patches.size(); i++) {
			if (g_patches[i].addr == addr) {
				// Alamat sama: ganti opcode baru, pertahankan instruksi asli.
				g_patches[i].value = newOp;
				g_patches[i].label = label;
				g_patches[i].enabled = true;
				MemScanner::WriteAt(addr, 4, newOp);
				return (int)i;
			}
		}
	}
	e.orig = Memory::ReadUnchecked_U32(addr);
	e.origText = MemDisasm(addr);  // sebelum ditimpa
	MemScanner::WriteAt(addr, 4, newOp);
	std::lock_guard<std::mutex> guard(g_patchLock);
	g_patches.push_back(e);
	return (int)g_patches.size() - 1;
}

void MemPatcher::Remove(int idx) {
	std::lock_guard<std::mutex> guard(g_patchLock);
	if (idx < 0 || idx >= (int)g_patches.size())
		return;
	const PatchEntry &e = g_patches[idx];
	if (Memory::IsActive() && Memory::IsValidRange(e.addr, 4) && Memory::ReadUnchecked_U32(e.addr) == e.value)
		MemScanner::WriteAt(e.addr, 4, e.orig);
	g_patches.erase(g_patches.begin() + idx);
}

void MemPatcher::SetEnabled(int idx, bool on) {
	std::lock_guard<std::mutex> guard(g_patchLock);
	if (idx < 0 || idx >= (int)g_patches.size())
		return;
	PatchEntry &e = g_patches[idx];
	e.enabled = on;
	MemScanner::WriteAt(e.addr, 4, on ? e.value : e.orig);
}

int MemPatcher::Count() {
	std::lock_guard<std::mutex> guard(g_patchLock);
	return (int)g_patches.size();
}

bool MemPatcher::Get(int idx, PatchEntry *out) {
	std::lock_guard<std::mutex> guard(g_patchLock);
	if (idx < 0 || idx >= (int)g_patches.size())
		return false;
	*out = g_patches[idx];
	return true;
}

void MemPatcher::Apply() {
	std::lock_guard<std::mutex> guard(g_patchLock);
	if (g_patches.empty() || !Memory::IsActive())
		return;
	for (const PatchEntry &e : g_patches) {
		if (!e.enabled || !Memory::IsValidRange(e.addr, 4))
			continue;
		// Hanya tulis ulang jika kode di situ kembali ke aslinya (mis. dimuat ulang).
		// Jika berisi hal lain (overlay berbeda), biarkan.
		if (Memory::ReadUnchecked_U32(e.addr) == e.orig && e.value != e.orig)
			MemScanner::WriteAt(e.addr, 4, e.value);
	}
}

// ===========================================================================
// PointerScanner
// ===========================================================================
static std::vector<PtrChain> g_chains;
static uint32_t g_chainTarget = 0;
static int g_chainTargetSize = 4;
static const size_t MAX_CHAINS = 5000;
static const size_t LEVEL_CAP = 3000;     // maksimum simpul baru per tingkat
static const int PER_TARGET_CAP = 32;     // maksimum pemegang pointer per target

const std::vector<PtrChain> &PointerScanner::Results() { return g_chains; }
uint32_t PointerScanner::Target() { return g_chainTarget; }
int PointerScanner::TargetSize() { return g_chainTargetSize; }
void PointerScanner::Clear() { g_chains.clear(); g_chains.shrink_to_fit(); }

bool PointerScanner::Resolve(const PtrChain &c, uint32_t *out) {
	if (c.offsets.empty() || !Memory::IsActive() || !Memory::IsValidRange(c.base, 4))
		return false;
	uint32_t p = Memory::ReadUnchecked_U32(c.base);
	for (size_t i = 0; i + 1 < c.offsets.size(); i++) {
		const uint32_t a = p + (uint32_t)c.offsets[i];
		if (!Memory::IsValidRange(a, 4))
			return false;
		p = Memory::ReadUnchecked_U32(a);
	}
	*out = p + (uint32_t)c.offsets.back();
	return true;
}

std::string PointerScanner::Describe(const PtrChain &c) {
	char buf[64];
	snprintf(buf, sizeof(buf), "[0x%08X]", c.base);
	std::string s = buf;
	for (size_t i = 0; i < c.offsets.size(); i++) {
		snprintf(buf, sizeof(buf), "+0x%X", (unsigned)c.offsets[i]);
		if (i + 1 < c.offsets.size())
			s = "[" + s + buf + "]";
		else
			s += buf;
	}
	return s;
}

int PointerScanner::Scan(uint32_t target, int targetSize, int maxDepth, uint32_t maxOffset) {
	g_chains.clear();
	g_chainTarget = target;
	g_chainTargetSize = targetSize;
	const uint32_t start = SCAN_START, end = ScanEnd(), len = end - start;
	if (!Memory::IsActive() || !Memory::IsValidRange(start, len))
		return 0;
	if (maxDepth < 1) maxDepth = 1;
	if (maxDepth > 4) maxDepth = 4;
	const uint8_t *ram = Memory::GetPointerUnchecked(start);

	// 1) Kumpulkan semua kata 32-bit yang tampak seperti pointer ke RAM user.
	struct PW { uint32_t value, holder; };
	std::vector<PW> pw;
	pw.reserve(len / 16);
	for (uint32_t off = 0; off + 4 <= len; off += 4) {
		uint32_t v;
		memcpy(&v, ram + off, 4);
		if (v >= start && v < end)
			pw.push_back({ v, start + off });
	}
	std::sort(pw.begin(), pw.end(), [](const PW &a, const PW &b) {
		return a.value != b.value ? a.value < b.value : a.holder < b.holder;
	});

	// 2) Telusuri mundur level demi level: siapa yang menunjuk ke target, siapa yang menunjuk ke penunjuk itu, dst.
	struct Node { uint32_t holder; int32_t off; int parent; };
	std::vector<Node> nodes;
	std::unordered_set<uint32_t> seen;
	std::vector<std::pair<uint32_t, int>> frontier = { { target, -1 } };
	for (int depth = 1; depth <= maxDepth && !frontier.empty(); depth++) {
		std::vector<Node> cand;
		for (const auto &f : frontier) {
			const uint32_t X = f.first;
			auto hi = std::upper_bound(pw.begin(), pw.end(), X, [](uint32_t x, const PW &p) { return x < p.value; });
			int taken = 0;
			for (auto it = hi; it != pw.begin() && taken < PER_TARGET_CAP;) {
				--it;
				if (X - it->value > maxOffset)
					break;
				if (it->holder == X || seen.count(it->holder))
					continue;
				cand.push_back({ it->holder, (int32_t)(X - it->value), f.second });
				taken++;
			}
		}
		// Prioritaskan alamat rendah (area data statis lebih mungkin di sana) dan buang duplikat.
		std::sort(cand.begin(), cand.end(), [](const Node &a, const Node &b) { return a.holder < b.holder; });
		cand.erase(std::unique(cand.begin(), cand.end(), [](const Node &a, const Node &b) { return a.holder == b.holder; }), cand.end());
		if (cand.size() > LEVEL_CAP)
			cand.resize(LEVEL_CAP);
		frontier.clear();
		for (const Node &n : cand) {
			nodes.push_back(n);
			seen.insert(n.holder);
			frontier.push_back({ n.holder, (int)nodes.size() - 1 });
		}
	}

	// 3) Ubah tiap simpul jadi chain: base = penyimpan terluar, offset dari luar ke dalam.
	g_chains.reserve(std::min(nodes.size(), MAX_CHAINS * 2));
	for (size_t i = 0; i < nodes.size(); i++) {
		PtrChain c;
		c.base = nodes[i].holder;
		for (int idx = (int)i; idx >= 0; idx = nodes[idx].parent)
			c.offsets.push_back(nodes[idx].off);
		g_chains.push_back(std::move(c));
	}
	std::sort(g_chains.begin(), g_chains.end(), [](const PtrChain &a, const PtrChain &b) {
		if (a.base != b.base)
			return a.base < b.base;
		return a.offsets.size() < b.offsets.size();
	});
	if (g_chains.size() > MAX_CHAINS)
		g_chains.resize(MAX_CHAINS);
	return (int)g_chains.size();
}

int PointerScanner::FilterFor(uint32_t newTarget) {
	std::vector<PtrChain> kept;
	for (const PtrChain &c : g_chains) {
		uint32_t out = 0;
		if (Resolve(c, &out) && out == newTarget)
			kept.push_back(c);
	}
	g_chains.swap(kept);
	g_chainTarget = newTarget;
	return (int)g_chains.size();
}
