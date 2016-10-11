#ifndef SNIFFER
#define SNIFFER

#pragma once

#include <QObject>
#include "conio.h"

#include "winsock2.h"
#include "iphlpapi.h"
#include "icmpapi.h"
#include "mstcpip.h"


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
    void parseIСMP();
    void parseTCP();
    void parseUDP();

private:
    char name[128];
    SOCKET sock;
    SOCKADDR_IN * adrPC;
    HOSTENT * informHost;
    char * buffer;

};

#endif // SNIFFER

