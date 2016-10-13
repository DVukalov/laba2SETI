#ifndef SNIFFER
#define SNIFFER

#pragma once

#include <QObject>
#include "conio.h"
#include <QDebug>
#include "winsock2.h"
#include "iphlpapi.h"
#include "icmpapi.h"
#include "mstcpip.h"
#include <QFile>
#include <QTextStream>
#include <QIODevice>
#include <QString>
#include <QByteArray>
class Sniffer : public QObject
{
    Q_OBJECT

public:
    explicit Sniffer(QObject* parent = 0);
    ~Sniffer();
private slots:
    bool initialization();
    bool createSocket();
    bool determIP_PC();
    bool bindSocket();
    bool promiscuousModeON();
    bool startSniffer();
    void parseIP();
    void printMSG();
    void parseICMP();
    void parseTCP();
    void parseUDP();


private:
    char name[128];
    SOCKET sock;
    SOCKADDR_IN * adrPC;
    HOSTENT * informHost;
    char * buffer;
    QFile file;
    QTextStream out;
};

#endif // SNIFFER

