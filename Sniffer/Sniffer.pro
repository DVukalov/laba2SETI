#-------------------------------------------------
#
# Project created by QtCreator 2016-10-09T19:15:53
#
#-------------------------------------------------

QT       += core gui


DEFINES += __print="\"qDebug()<< __FILE__ << __LINE__ <<  Q_FUNC_INFO\""

LIBS +=  -lws2_32
LIBS += -liphlpapi

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Sniffer
TEMPLATE = app


SOURCES += main.cpp\
        interface.cpp \
    sniffer.cpp

HEADERS  += interface.h \
    sniffer.h

FORMS    += interface.ui

QMAKE_CXXFLAGS += -std=c++11
