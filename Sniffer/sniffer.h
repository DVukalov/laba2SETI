#ifndef SNIFFER
#define SNIFFER

//#pragma once
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
#include <QTime>
#include <QByteArray>
#include <QThread>
class Sniffer : public QObject
{
    Q_OBJECT

public:
    explicit Sniffer(QObject* parent = 0);
    ~Sniffer();
public slots:
    bool startSniffer();

private slots:
    bool initialization();
    bool createSocket();
    bool determIP_PC();
    bool bindSocket();
    bool promiscuousModeON();
    void parseIP(int fileId);
    void parseICMP();
    void parseTCP();
    void parseUDP();
    void stopReceive();
    void checkUDP(int flag);
    void checkTCP(int flag);
    void checkICMP(int flag);

private:
    char name[128];
    SOCKET sock;
    SOCKADDR_IN * adrPC;
    HOSTENT * informHost;
    char * buffer;
    QFile fileTCP;
    QFile fileUDP;
    QFile fileICMP;
    QFile file;
    bool receive;
    bool mUDP;
    bool mTCP;
    bool mICMP;

};

#endif // SNIFFER

