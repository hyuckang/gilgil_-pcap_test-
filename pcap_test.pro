TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
    main.cpp

HEADERS += \
    ether_header.h \
    init.h \
    ipv4_header.h \
    parse_packet.h \
    print_function.h \
    tcp_header.h \
    udp_header.h

PRECOMPILED_HEADER += init.h
