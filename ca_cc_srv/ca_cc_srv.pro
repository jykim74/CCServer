TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        cc_proc.c \
        cc_srv.c \
        cc_tools.c \
        cc_work.c \
        main.c

HEADERS += \
    cc_proc.h \
    cc_tools.h \
    cc_work.h


INCLUDEPATH += "../../PKILib"

mac {
    INCLUDEPATH += "../../PKILib/lib/mac/debug/cmpossl/include"
    INCLUDEPATH += "/usr/local/include"
    LIBS += -L"/usr/local/lib" -lltdl

    LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/mac/debug/cmpossl/lib" -lcrypto -lssl
    LIBS += -L"/usr/local/lib" -lltdl
    LIBS += -lldap -llber
    LIBS += -lsqlite3
}

win32 {
    INCLUDEPATH += "../../PKILib/lib/win32/cmpossl/include"
    INCLUDEPATH += "C:\msys64\mingw32\include"
    INCLUDEPATH += "C:/Program Files (x86)/Visual Leak Detector/include"

    Debug {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug/debug" -lPKILib
        LIBS += -L"../../PKILib/lib/win32/debug/cmpossl/lib" -lcrypto -lssl
        LIBS += "C:/Program Files (x86)/Visual Leak Detector/lib/Win32/vld.lib"
        LIBS += "C:/Program Files (x86)/Visual Leak Detector/bin/Win32/vld_x86.dll"
    } else {
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release/release" -lPKILib
        LIBS += -L"../../PKILib/lib/win32/cmpossl/lib" -lcrypto -lssl
    }

    LIBS += -L"C:\msys64\mingw32\lib" -lltdl -lldap -llber -lsqlite3 -lws2_32
}

DISTFILES += \
    ../ca_cc_srv.cfg
