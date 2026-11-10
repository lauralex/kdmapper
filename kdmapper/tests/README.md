# Mapper policy fixture

The independent page policy fixture checks that a verified three-symbol set
selects the requested exact-image RVA, while missing symbols, zero base, and
address overflow fail closed in strict mode. It also checks that only standalone
mode can select the existing guarded signature fallback. The test does not
load a driver or execute any kernel calls.

From a Visual Studio 2022 x64 developer shell in kdmapper/:

    New-Item -ItemType Directory -Force -Path build | Out-Null
    cl /nologo /std:c++17 /EHsc /W4 /WX /Iinclude tests\independent_page_policy_tests.cpp /Febuild\independent_page_policy_tests.exe /Fobuild\
    build\independent_page_policy_tests.exe

The executable and object file stay under the ignored build/ directory.
