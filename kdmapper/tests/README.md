# Mapper policy and trampoline fixture

The independent page policy fixture checks that a verified three-symbol set
selects the requested exact-image RVA, while missing symbols, zero base, and
address overflow fail closed in strict mode. It also checks that only standalone
mode can select the existing guarded signature fallback.

The same fixture instantiates the production kernel-call template with fake
module/export lookup, memory transport and syscall functions. It checks the
original 12-byte indirect transfer at legacy entries and after an untouched
ENDBR64 prefix, exact argument/result transport, written-page boundaries,
existing-hook rejection, partial writes, full-span readback and retained
ownership after an unverified restoration. A source ENDBR64 in the final four
bytes of a page is supported when the writable suffix fits wholly in the next
page. Boundary cases use distinct, exactly matched scalar function signatures
to account for the template's per-instantiation cached export address.

The production restoration helper is also exercised with fake read/write
callbacks, including its initial no-write check, partial-write retry, failed
write reports resolved by readback and bounded failure paths. No fake syscall
executes the synthetic kernel source or destination addresses as code. The
fixture does not load a driver, contact the mapping helper or execute a real
kernel call.

The ENDBR preservation regression failed against the previous production
template before the fix. The updated fixture passes 253 checks with MSVC C++17
and `/W4 /WX`. These user-mode mocks do not establish active supervisor IBT,
shadow-stack operation, Windows driver-policy acceptance or native loading.

From a Visual Studio 2022 x64 developer shell in kdmapper/:

    New-Item -ItemType Directory -Force -Path build | Out-Null
    cl /nologo /std:c++17 /EHsc /W4 /WX /Iinclude tests\independent_page_policy_tests.cpp /Febuild\independent_page_policy_tests.exe /Fobuild\
    build\independent_page_policy_tests.exe

The executable and object file stay under the ignored build/ directory.
