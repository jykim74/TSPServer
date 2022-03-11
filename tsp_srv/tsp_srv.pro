TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.c \
        tsp_proc.c \
        tsp_srv.c

HEADERS += \
    tsp_srv.h


INCLUDEPATH += "../../PKILib"

mac {
    INCLUDEPATH += "../../PKILib/lib/mac/debug/openssl3/include"
    LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/mac/debug/openssl3/lib" -lcrypto -lssl
}

win32 {
    contains(QT_ARCH, i386) {
        message( "tsp_srv 32bit" )

        Debug {
            INCLUDEPATH += "../../PKILib/lib/win32/debug/openssl3/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug/debug" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win32/debug/openssl3/lib" -lcrypto -lssl
        } else {
            INCLUDEPATH += "../../PKILib/lib/win32/openssl3/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release/release" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win32/openssl3/lib" -lcrypto -lssl
        }

        INCLUDEPATH += "C:\msys64\mingw32\include"
        LIBS += -L"C:\msys64\mingw32\lib" -lltdl -lsqlite3
    } else {
        message( "tsp_srv 64bit" )

        Debug {
            INCLUDEPATH += "../../PKILib/lib/win64/debug/openssl3/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug/debug" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win64/debug/openssl3/lib64" -lcrypto -lssl
        } else {
            INCLUDEPATH += "../../PKILib/lib/win64/openssl3/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release/release" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win64/openssl3/lib64" -lcrypto -lssl
        }

        INCLUDEPATH += "C:\msys64\mingw64\include"
        LIBS += -L"C:\msys64\mingw64\lib" -lltdl -lsqlite3
    }
}

DISTFILES += \
    ../tsp_srv.cfg
