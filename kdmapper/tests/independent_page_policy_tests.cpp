#include "intel_driver.hpp"

#include <cstdint>
#include <iostream>
#include <limits>

namespace {
int failures = 0;
void check(bool condition, const char* message) {
	if (!condition) {
		std::cerr << "FAIL: " << message << '\n';
		++failures;
	}
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

	if (failures) return 1;
	std::cout << "independent-page policy checks passed\n";
}
