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
    INCLUDEPATH += "../../PKILib/lib/mac/debug/cmpossl/include"
    LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/mac/debug/cmpossl/lib" -lcrypto -lssl
}

win32 {
    Debug {
        INCLUDEPATH += "../../PKILib/lib/win32/debug/cmpossl/include"
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug/debug" -lPKILib -lws2_32
        LIBS += -L"../../PKILib/lib/win32/debug/cmpossl/lib" -lcrypto -lssl


    } else {
        INCLUDEPATH += "../../PKILib/lib/win32/cmpossl/include"
        LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release/release" -lPKILib -lws2_32
        LIBS += -L"../../PKILib/lib/win32/cmpossl/lib" -lcrypto -lssl
    }

    INCLUDEPATH += "C:\msys64\mingw32\include"
    LIBS += -L"C:\msys64\mingw32\lib" -lltdl -lsqlite3
}
