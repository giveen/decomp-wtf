"""Library/CRT functions are not the program's own code: don't hand them to agents."""

from decompnet.rom import library


def test_crt_and_runtime_names():
    assert library.kind("_start") == "CRT"
    assert library.kind("mainCRTStartup") == "CRT"
    assert library.kind("__scrt_common_main_seh") == "CRT"
    assert library.kind("__security_check_cookie") == "CRT"
    assert library.kind("operator new(unsigned long long)") == "C++ runtime"
    assert library.kind("std::vector<int>::push_back") == "C++ runtime"
    assert library.kind("??_7Player@@6B@") == "C++ runtime"
    assert library.kind("libgcc_s.so.1") == "static library"


def test_auto_names_and_user_code_stay_open():
    assert library.kind("sub_140001020") is None
    assert library.kind("func_80001000") is None
    assert library.kind("player_update") is None
    assert library.kind("add") is None
    assert library.kind("main") is None
