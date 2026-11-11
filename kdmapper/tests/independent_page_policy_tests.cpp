#include <Windows.h>

namespace trampoline_fixture {
HMODULE ModuleHandle(LPCSTR name);
FARPROC Procedure(HMODULE module, LPCSTR name);
}

// Redirect lookup only in the production template. No real syscall or helper
// transport is reachable from this executable.
#define GetModuleHandleA trampoline_fixture::ModuleHandle
#define GetProcAddress trampoline_fixture::Procedure
#include "intel_driver.hpp"
#undef GetProcAddress
#undef GetModuleHandleA

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <vector>

namespace {
int failures = 0;
unsigned checks = 0;
void check(bool condition, const char* message) {
	++checks;
	if (!condition) {
		std::cerr << "FAIL: " << message << '\n';
		++failures;
	}
}
}

namespace trampoline_fixture {
constexpr uint64_t default_entry = 0xfffff80000000ff0ull;
constexpr uint64_t target = 0xfffff80100001000ull;
uint64_t entry = default_entry;
std::array<uint8_t, 32> bytes{};
std::array<uint8_t, 32> original{};
std::mutex call_mutex;
bool intact = true;
bool preserved_landing_pad = false;
unsigned invoked = 0;
unsigned restores = 0;
unsigned reads = 0;
bool restore_completed = false;
bool source_has_pad = false;
bool fail_first_read = false;
bool fail_snapshot_read = false;
bool change_snapshot_prefix = false;
bool fail_install = false;
bool fail_install_readback = false;
bool mismatch_install_readback = false;
bool change_prefix_on_install = false;
bool change_prefix_on_invoke = false;
bool fail_restore = false;
bool skip_restore = false;
bool fail_final_readback = false;
bool fail_lookup = false;
bool restore_original_prefix = false;
unsigned partial_install = 0;
bool invalid_lookup = false;
struct write_range { uint64_t address; uint32_t size; };
std::vector<write_range> writes;
std::vector<write_range> restore_ranges;
std::array<uint64_t, 4> arguments_seen{};
enum class signature { u64, u32, u16, u8, i64, i32, none, zero32, four64 } current_signature = signature::u64;

uint64_t observe_call(uint64_t argument) {
	++invoked;
	preserved_landing_pad = std::memcmp(bytes.data(), original.data(), 4) == 0;
	auto const offset = source_has_pad ? 4u : 0u;
	uint64_t encoded_target = 0;
	std::memcpy(&encoded_target, bytes.data() + offset + 2, sizeof(encoded_target));
	check(bytes[offset] == 0x48 && bytes[offset + 1] == 0xb8 &&
		bytes[offset + 10] == 0xff && bytes[offset + 11] == 0xe0 && encoded_target == target,
		"original mov rax/indirect jmp transport and its exact target are retained");
	if (change_prefix_on_invoke) bytes[0] ^= 1;
	return argument + 1;
}

template<typename A> uint64_t __stdcall KernelCall(A argument) { return observe_call(argument); }
uint64_t __stdcall KernelCallNoArguments() { return observe_call(41); }
uint32_t __stdcall KernelCallNoArguments32() { return static_cast<uint32_t>(observe_call(41)); }
uint64_t __stdcall KernelCallFour(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
	arguments_seen = {a, b, c, d};
	(void)observe_call(a);
	return a ^ b ^ c ^ d;
}

HMODULE ModuleHandle(LPCSTR name) {
	invalid_lookup = invalid_lookup || std::strcmp(name, "ntdll.dll") != 0;
	if (fail_lookup) return nullptr;
	return reinterpret_cast<HMODULE>(1);
}

FARPROC Procedure(HMODULE module, LPCSTR name) {
	invalid_lookup = invalid_lookup || module != reinterpret_cast<HMODULE>(1) ||
		std::strcmp(name, "NtAddAtom") != 0;
	switch (current_signature) {
	case signature::u64: return reinterpret_cast<FARPROC>(&KernelCall<uint64_t>);
	case signature::u32: return reinterpret_cast<FARPROC>(&KernelCall<uint32_t>);
	case signature::u16: return reinterpret_cast<FARPROC>(&KernelCall<uint16_t>);
	case signature::u8: return reinterpret_cast<FARPROC>(&KernelCall<uint8_t>);
	case signature::i64: return reinterpret_cast<FARPROC>(&KernelCall<int64_t>);
	case signature::i32: return reinterpret_cast<FARPROC>(&KernelCall<int32_t>);
	case signature::none: return reinterpret_cast<FARPROC>(&KernelCallNoArguments);
	case signature::zero32: return reinterpret_cast<FARPROC>(&KernelCallNoArguments32);
	case signature::four64: return reinterpret_cast<FARPROC>(&KernelCallFour);
	}
	return nullptr;
}

void reset(bool endbr, uint64_t address = default_entry) {
	entry = address;
	for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<uint8_t>(0x80 + i);
	if (endbr) {
		bytes[0] = 0xf3; bytes[1] = 0x0f; bytes[2] = 0x1e; bytes[3] = 0xfa;
	}
	original = bytes;
	intact = true;
	preserved_landing_pad = false;
	invoked = restores = reads = 0;
	restore_completed = false;
	source_has_pad = endbr;
	fail_first_read = change_snapshot_prefix = fail_install = false;
	fail_snapshot_read = restore_original_prefix = false;
	fail_install_readback = mismatch_install_readback = false;
	change_prefix_on_install = change_prefix_on_invoke = false;
	fail_restore = skip_restore = fail_final_readback = fail_lookup = false;
	partial_install = 0;
	invalid_lookup = false;
	writes.clear();
	restore_ranges.clear();
	current_signature = signature::u64;
	arguments_seen = {};
}

void check_write_ranges(uint64_t expected) {
	for (auto const range : writes) {
		check(range.address == expected && range.size == 12,
			"every patch and restoration write uses exactly the selected 12-byte suffix");
		check((range.address & 0xfff) + range.size <= 0x1000,
			"physical-write helper never receives a cross-page span");
	}
	for (auto const range : restore_ranges)
		check(range.address == expected && range.size == 12,
			"restoration receives the selected original suffix and its full size");
}

intel_driver::kernel_call_result call() {
	uint64_t result = 0;
	auto const outcome = intel_driver::CallKernelFunctionDetailed(&result, target, uint64_t{41});
	if (outcome.target_invoked) check(result == 42, "mock target return value is preserved");
	check(!invalid_lookup, "production lookup remains confined to the fake NtAddAtom syscall");
	return outcome;
}

void check_latched() {
	auto const old_reads = reads;
	auto const old_writes = writes.size();
	auto const old_invoked = invoked;
	auto const outcome = call();
	check(!outcome.target_invoked && !outcome.trampoline_intact,
		"unverified trampoline blocks a subsequent kernel call");
	check(reads == old_reads && writes.size() == old_writes && invoked == old_invoked,
		"unverified ownership stops before any further memory access or syscall");
}

void check_successful_forms() {
	for (bool endbr : {false, true}) {
		reset(endbr);
		auto const outcome = call();
		check(outcome.target_invoked && outcome.trampoline_intact && outcome.trampoline_restored,
		"mocked kernel target returns with verified restoration");
		check(invoked == 1 && restores == 1, "production template invokes only the mock syscall");
		if (endbr) check(preserved_landing_pad, "ENDBR64 stays present while the mock target executes");
		check_write_ranges(entry + (endbr ? 4 : 0));
		check(bytes == original, "complete original entry bytes are restored");
	}
	reset(false);
	bytes[0] = 0xf3; bytes[1] = 0x0f; bytes[2] = 0x1e; bytes[3] = 0xfb;
	original = bytes;
	check(call().target_invoked, "ENDBR32 is not mistaken for a 64-bit kernel landing pad");
	check_write_ranges(entry);

	reset(true);
	current_signature = signature::zero32;
	uint32_t result32 = 0;
	auto outcome = intel_driver::CallKernelFunctionDetailed(&result32, target);
	check(outcome.target_invoked && outcome.trampoline_intact && result32 == 42,
		"zero-argument target and its 32-bit return value retain the original call contract");
	check_write_ranges(entry + 4);

	reset(true);
	current_signature = signature::four64;
	constexpr std::array<uint64_t, 4> expected_arguments{0x1122334455667788ull,
		0xffffffffffffffffull, 0x8877665544332211ull, 0x1020304050607080ull};
	uint64_t result64 = 0;
	outcome = intel_driver::CallKernelFunctionDetailed(&result64, target,
		expected_arguments[0], expected_arguments[1], expected_arguments[2], expected_arguments[3]);
	check(outcome.target_invoked && outcome.trampoline_intact && arguments_seen == expected_arguments &&
		result64 == (expected_arguments[0] ^ expected_arguments[1] ^ expected_arguments[2] ^ expected_arguments[3]),
		"all four full-width arguments and target result retain the original call contract");
	check_write_ranges(entry + 4);
}

void check_failures() {
	for (bool endbr : {false, true}) {
		reset(endbr);
		fail_first_read = true;
		auto outcome = call();
		check(!outcome.target_invoked && outcome.trampoline_intact && writes.empty(),
			"initial read failure refuses without acquiring mutation ownership");

		reset(endbr);
		fail_snapshot_read = true;
		outcome = call();
		check(!outcome.target_invoked && outcome.trampoline_intact && writes.empty(),
			"complete original-byte snapshot failure refuses before any patch");

		reset(endbr);
		fail_install = true;
		partial_install = 7;
		outcome = call();
		check(!outcome.target_invoked && outcome.trampoline_intact && restores == 1 && bytes == original,
			"partial failed patch is restored before returning a safe refusal");
		check_write_ranges(entry + (endbr ? 4 : 0));

		reset(endbr);
		fail_install_readback = true;
		outcome = call();
		check(!outcome.target_invoked && outcome.trampoline_intact && restores == 1 && bytes == original,
			"failed installation readback restores without invoking the target");

		reset(endbr);
		mismatch_install_readback = true;
		outcome = call();
		check(!outcome.target_invoked && outcome.trampoline_intact && restores == 1 && bytes == original,
			"mismatching installation readback restores without invoking the target");

		reset(endbr);
		fail_restore = true;
		outcome = call();
		check(outcome.target_invoked && !outcome.trampoline_intact && !outcome.trampoline_restored,
			"unconfirmed restore retains ownership after a completed target call");
		check_latched();

		reset(endbr);
		skip_restore = true;
		outcome = call();
		check(outcome.target_invoked && !outcome.trampoline_intact && !outcome.trampoline_restored,
			"successful restore report cannot replace exact original-byte readback");
		check_latched();

		reset(endbr);
		fail_final_readback = true;
		outcome = call();
		check(outcome.target_invoked && !outcome.trampoline_intact && !outcome.trampoline_restored,
			"final readback failure retains ownership even when original bytes were written");
		check_latched();

		reset(endbr);
		fail_install = fail_restore = true;
		partial_install = 7;
		outcome = call();
		check(!outcome.target_invoked && !outcome.trampoline_intact,
			"partial patch plus failed restoration retains ownership before invocation");
		check_latched();

		reset(endbr);
		auto const offset = endbr ? 4u : 0u;
		bytes[offset] = 0x48; bytes[offset + 1] = 0xb8;
		bytes[offset + 10] = 0xff; bytes[offset + 11] = 0xe0;
		outcome = call();
		check(!outcome.target_invoked && !outcome.trampoline_intact && writes.empty(),
			"existing movabs trampoline is rejected at the selected suffix");
		check_latched();
	}

	reset(true);
	change_snapshot_prefix = true;
	auto outcome = call();
	check(!outcome.target_invoked && !outcome.trampoline_intact && writes.empty(),
		"prefix change between probe and snapshot refuses before mutation");
	check_latched();

	reset(true);
	change_prefix_on_install = true;
	outcome = call();
	check(!outcome.target_invoked && !outcome.trampoline_intact && restores == 1,
		"changed preserved prefix prevents invocation and retains ownership");
	check_write_ranges(entry + 4);
	check_latched();

	reset(true);
	change_prefix_on_install = restore_original_prefix = true;
	outcome = call();
	check(!outcome.target_invoked && !outcome.trampoline_intact && bytes == original,
		"observed prefix corruption stays unverified even if another actor later restores the prefix");
	check_latched();

	reset(true);
	change_prefix_on_invoke = true;
	outcome = call();
	check(outcome.target_invoked && !outcome.trampoline_intact && !outcome.trampoline_restored,
		"post-call prefix mismatch retains ownership after suffix restoration");
	check_write_ranges(entry + 4);
	check_latched();

	reset(false);
	fail_lookup = true;
	outcome = call();
	check(!outcome.target_invoked && outcome.trampoline_intact && !reads && writes.empty(),
		"missing syscall lookup refuses before any kernel-memory access");

	reset(false);
	outcome = intel_driver::CallKernelFunctionDetailed<uint64_t>(nullptr, target, uint64_t{41});
	check(!outcome.target_invoked && outcome.trampoline_intact && !reads && writes.empty() && !invoked,
		"null result pointer refuses before any memory access or syscall");
	uint64_t result = 0;
	outcome = intel_driver::CallKernelFunctionDetailed(&result, 0, uint64_t{41});
	check(!outcome.target_invoked && outcome.trampoline_intact && !reads && writes.empty() && !invoked,
		"null target refuses before any memory access or syscall");
}

void check_page_boundaries() {
	// The production export cache belongs to each exact T/A... instantiation.
	// Each address below therefore uses a distinct scalar signature, and
	// Procedure selects a mock with that exact signature. No mock executes the
	// synthetic source or target addresses as code.
	uint64_t result = 0;
	reset(true, 0xfffff80000000ff1ull);
	current_signature = signature::u32;
	auto outcome = intel_driver::CallKernelFunctionDetailed(&result, target, uint32_t{41});
	check(!outcome.target_invoked && outcome.trampoline_intact && writes.empty(),
		"ENDBR suffix crossing a physical page refuses before any write");

	reset(true, 0xfffff80000000ffCull);
	current_signature = signature::u16;
	outcome = intel_driver::CallKernelFunctionDetailed(&result, target, uint16_t{41});
	check(outcome.target_invoked && outcome.trampoline_intact && bytes == original,
		"ENDBR at the end of one page permits a suffix wholly in the next page");
	check_write_ranges(entry + 4);

	reset(false, 0xfffff80000000ff4ull);
	current_signature = signature::u8;
	outcome = intel_driver::CallKernelFunctionDetailed(&result, target, uint8_t{41});
	check(outcome.target_invoked && outcome.trampoline_intact && bytes == original,
		"legacy 12-byte patch ending exactly at a page boundary remains supported");
	check_write_ranges(entry);

	reset(false, 0xfffff80000000ff5ull);
	current_signature = signature::none;
	outcome = intel_driver::CallKernelFunctionDetailed(&result, target);
	check(!outcome.target_invoked && outcome.trampoline_intact && writes.empty(),
		"legacy patch crossing a physical page still refuses before writing");

	reset(false, (std::numeric_limits<uint64_t>::max)() - 2);
	current_signature = signature::i64;
	outcome = intel_driver::CallKernelFunctionDetailed(&result, target, int64_t{41});
	check(!outcome.target_invoked && outcome.trampoline_intact && !reads && writes.empty(),
		"overflowing prefix-read range refuses before any transport access");

	reset(false, (std::numeric_limits<uint64_t>::max)() - 3);
	current_signature = signature::i32;
	outcome = intel_driver::CallKernelFunctionDetailed(&result, target, int32_t{41});
	check(!outcome.target_invoked && outcome.trampoline_intact && reads == 1 && writes.empty(),
		"last valid prefix-read range refuses an overflowing patch before snapshot or write");
}

void check_production_restore_helper() {
	constexpr uint64_t address = 0xfffff80000001000ull;
	std::array<uint8_t, 32> expected{};
	std::array<uint8_t, 32> observed{};
	for (size_t i = 0; i < expected.size(); ++i) expected[i] = static_cast<uint8_t>(0x20 + i);
	unsigned read_calls = 0;
	unsigned write_calls = 0;
	unsigned partial_first_write = 0;
	bool report_failed_write = false;
	bool reject_writes = false;
	bool reject_reads = false;
	auto read = [&](uint64_t at, void* buffer, uint64_t size) {
		++read_calls;
		check(at == address && size <= observed.size(), "restore helper reads the exact bounded span");
		if (reject_reads) return false;
		std::memcpy(buffer, observed.data(), static_cast<size_t>(size));
		return true;
	};
	auto write = [&](uint64_t at, void* buffer, uint32_t size) {
		++write_calls;
		check(at == address && size <= observed.size(), "restore helper writes the exact bounded span");
		if (reject_writes) return false;
		auto const count = write_calls == 1 && partial_first_write
			? (std::min)(size, partial_first_write) : size;
		std::memcpy(observed.data(), buffer, count);
		return !report_failed_write && count == size;
	};
	auto restore = [&](uint32_t size) {
		return intel_driver::detail::RestoreKernelCallTrampolineWith(
			address, expected.data(), size, read, write);
	};

	observed = expected;
	check(restore(32) && read_calls == 1 && !write_calls,
		"already-restored bytes avoid an unnecessary physical write");

	for (uint32_t size : {1u, 12u, 16u, 32u}) {
		observed = expected;
		observed[size - 1] ^= 1;
		read_calls = write_calls = 0;
		check(restore(size) && observed == expected && read_calls == 2 && write_calls == 1,
			"restore validates every byte including the last byte of each supported span");
	}

	observed.fill(0);
	read_calls = write_calls = 0;
	partial_first_write = 7;
	check(restore(32) && observed == expected && read_calls == 3 && write_calls == 2,
		"partial first restore is retried once and accepted only after exact readback");
	partial_first_write = 0;

	observed.fill(0);
	read_calls = write_calls = 0;
	report_failed_write = true;
	check(restore(32) && read_calls == 2 && write_calls == 1,
		"failed write report with exact completed bytes is resolved by readback");
	report_failed_write = false;

	observed.fill(0);
	read_calls = write_calls = 0;
	reject_writes = true;
	check(!restore(32) && read_calls == 3 && write_calls == 2,
		"two unconfirmed restore attempts return failure with ownership unresolved");
	reject_writes = false;

	observed.fill(0);
	read_calls = write_calls = 0;
	reject_reads = true;
	check(!restore(32) && observed == expected && read_calls == 3 && write_calls == 2,
		"successful writes cannot prove restoration when every readback fails");
	reject_reads = false;

	read_calls = write_calls = 0;
	check(!restore(0) && !restore(33) &&
		!intel_driver::detail::RestoreKernelCallTrampolineWith(address,
			static_cast<const uint8_t*>(nullptr), 12, read, write) &&
		!intel_driver::detail::RestoreKernelCallTrampolineWith(0, expected.data(), 12, read, write) &&
		!read_calls && !write_calls,
		"invalid restore arguments refuse before any transport callback");
}
}

namespace intel_driver {
ULONG64 ntoskrnlAddr = 0xfffff80000000000ull;
std::mutex& KernelCallMutex() { return trampoline_fixture::call_mutex; }
bool IsKernelCallTrampolineIntact() { return trampoline_fixture::intact; }
void MarkKernelCallTrampolineUnverified() { trampoline_fixture::intact = false; }
uint64_t GetKernelModuleExport(uint64_t, const std::string&) { return trampoline_fixture::entry; }
bool ReadMemory(uint64_t address, void* buffer, uint64_t size) {
	using namespace trampoline_fixture;
	++reads;
	if (fail_first_read && reads == 1) return false;
	if (fail_snapshot_read && reads == 2) return false;
	if (change_snapshot_prefix && reads == 2) bytes[0] ^= 1;
	if (!writes.empty() && !restores && fail_install_readback) return false;
	if (!writes.empty() && !restores && mismatch_install_readback) {
		bytes[source_has_pad ? 4 : 0] ^= 1;
		mismatch_install_readback = false;
	}
	if (restore_completed && fail_final_readback) return false;
	if (address < entry || address - entry > bytes.size() || size > bytes.size() - (address - entry))
		return false;
	std::memcpy(buffer, bytes.data() + (address - entry), static_cast<size_t>(size));
	return true;
}
bool WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size) {
	using namespace trampoline_fixture;
	if (address < entry || address - entry > bytes.size() || size > bytes.size() - (address - entry))
		return false;
	writes.push_back({address, size});
	if (writes.size() == 1 && fail_install) {
		std::memcpy(bytes.data() + (address - entry), buffer, (std::min)(partial_install, size));
		return false;
	}
	std::memcpy(bytes.data() + (address - entry), buffer, size);
	if (writes.size() == 1 && change_prefix_on_install) bytes[0] ^= 1;
	return true;
}
bool RestoreKernelCallTrampoline(uint64_t address, const uint8_t* source, uint32_t size) {
	using namespace trampoline_fixture;
	++restores;
	restore_ranges.push_back({address, size});
	if (restore_original_prefix) std::memcpy(bytes.data(), original.data(), 4);
	if (skip_restore) {
		restore_completed = true;
		return true;
	}
	auto write = [](uint64_t at, void* buffer, uint32_t count) {
		if (trampoline_fixture::fail_restore) return false;
		return WriteToReadOnlyMemory(at, buffer, count);
	};
	auto const restored = detail::RestoreKernelCallTrampolineWith(address, source, size, ReadMemory, write);
	restore_completed = true;
	return restored;
}
}

int main() {
	using intel_driver::independent_page_rvas;
	using intel_driver::detail::CompleteIndependentPageRvas;
	using intel_driver::detail::independent_page_api;
	using intel_driver::detail::SelectIndependentPageTarget;

	constexpr uint64_t base = 0xfffff80000000000ull;
	constexpr independent_page_rvas complete{0x1000, 0x2000, 0x3000};
	check(CompleteIndependentPageRvas(complete), "all exact-image RVAs are required");
	check(!SelectIndependentPageTarget(false, base, complete,
		independent_page_api::allocate).has_value(),
		"standalone mode may use its existing guarded fallback");
	check(SelectIndependentPageTarget(true, base, complete,
		independent_page_api::allocate) == base + 0x1000,
		"strict allocation uses its exact-image RVA");
	check(SelectIndependentPageTarget(true, base, complete,
		independent_page_api::protect) == base + 0x2000,
		"strict protection uses its exact-image RVA");
	check(SelectIndependentPageTarget(true, base, complete,
		independent_page_api::free) == base + 0x3000,
		"strict deallocation uses its exact-image RVA");

	for (auto missing : {independent_page_rvas{0, 0x2000, 0x3000},
		independent_page_rvas{0x1000, 0, 0x3000},
		independent_page_rvas{0x1000, 0x2000, 0}}) {
		check(!CompleteIndependentPageRvas(missing),
			"partial exact-image symbol set is rejected");
		for (auto api : {independent_page_api::allocate,
			independent_page_api::protect, independent_page_api::free}) {
			auto const target = SelectIndependentPageTarget(true, base, missing, api);
			check(target.has_value(), "strict mode never selects signature fallback");
		}
	}
	check(SelectIndependentPageTarget(true, base, {},
		independent_page_api::free) == 0,
		"strict missing target fails closed");
	check(SelectIndependentPageTarget(true, 0, complete,
		independent_page_api::free) == 0,
		"strict missing image base fails closed");
	check(SelectIndependentPageTarget(true, (std::numeric_limits<uint64_t>::max)() - 1,
		complete, independent_page_api::allocate) == 0,
		"image-base arithmetic overflow fails closed");
	trampoline_fixture::check_successful_forms();
	trampoline_fixture::check_failures();
	trampoline_fixture::check_page_boundaries();
	trampoline_fixture::check_production_restore_helper();

	if (failures) return 1;
	std::cout << "independent-page policy and mocked trampoline checks passed: " << checks << '\n';
}
