#ifndef ICMPGENERATOR
#define ICMPGENERATOR

#include <QFile>
#include <QDebug>
#include <QObject>
#include <QString>
#include <QIODevice>
#include <QByteArray>

#include "conio.h"
#include "winsock2.h"
#include "iphlpapi.h"
#include "icmpapi.h"
#include "mstcpip.h"

class ICMPGenerator : public QObject
{
    Q_OBJECT

public:
    ICMPGenerator(QObject* parent = 0);
    ~ICMPGenerator();

public slots:
    int sendDatagram(QByteArray data);
    int init(int v_major, int v_minor);
    ushort getCRC (ushort* buffer, int length);

    int sendIP (SOCKET s, struct ip_header iph,
                uchar* data, int data_length,
                ushort dst_port_raw);
    int sendICMP (SOCKET s, struct ip_header iph,
                  struct icmp_header icmph,
                  uchar* data, int data_length);

private:
    SOCKET socket;
};

#endif // ICMPGENERATOR

