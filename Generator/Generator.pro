#-------------------------------------------------
#
# Project created by QtCreator 2016-10-09T18:52:26
#
#-------------------------------------------------

QT       += core gui network

LIBS += -lws2_32
LIBS += -liphlpapi

DEFINES += __print="\"qDebug()<<__FILE__<<__LINE__<<Q_FUNC_INFO\""

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Generator
TEMPLATE = app


SOURCES += main.cpp\
        interface.cpp \
    icmpgenerator.cpp

HEADERS  += interface.h \
    icmpgenerator.h

FORMS    += interface.ui

QMAKE_CXXFLAGS += -std=c++11
