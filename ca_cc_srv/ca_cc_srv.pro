TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        cc_proc.c \
        cc_srv.c \
        cc_tools.c \
        cc_work.c

HEADERS += \
    cc_proc.h \
    cc_tools.h \
    cc_work.h


INCLUDEPATH += "../../PKILib"

mac {
    INCLUDEPATH += "../../PKILib/lib/mac/debug/openssl3/include"
    INCLUDEPATH += "/usr/local/include"
    LIBS += -L"/usr/local/lib" -lltdl

    LIBS += -L"../../build-PKILib-Desktop_Qt_5_15_2_clang_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/mac/debug/openssl3/lib" -lcrypto -lssl
    LIBS += -L"/usr/local/lib" -lltdl
    LIBS += -lldap -llber
    LIBS += -lsqlite3
}

win32 {
    contains(QT_ARCH, i386) {
        message( "ca_cc_srv 32bit" )

        INCLUDEPATH += "../../PKILib/lib/win32/openssl3/include"
        INCLUDEPATH += "C:\msys64\mingw32\include"

        Debug {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug/debug" -lPKILib
            LIBS += -L"../../PKILib/lib/win32/debug/openssl3/lib" -lcrypto -lssl
        } else {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release/release" -lPKILib
            LIBS += -L"../../PKILib/lib/win32/openssl3/lib" -lcrypto -lssl
        }

        LIBS += -L"C:\msys64\mingw32\lib" -lltdl -lldap -llber -lsqlite3 -lws2_32
    } else {
        message( "ca_cc_srv 64bit" )

        INCLUDEPATH += "../../PKILib/lib/win64/openssl3/include"
        INCLUDEPATH += "C:\msys64\mingw64\include"

        Debug {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug/debug" -lPKILib
            LIBS += -L"../../PKILib/lib/win64/debug/openssl3/lib64" -lcrypto -lssl
        } else {
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release/release" -lPKILib
            LIBS += -L"../../PKILib/lib/win64/openssl3/lib64" -lcrypto -lssl
        }

        LIBS += -L"C:\msys64\mingw64\lib" -lltdl -lldap -llber -lsqlite3 -lws2_32
    }
}

DISTFILES += \
    ../ca_cc_srv.cfg
