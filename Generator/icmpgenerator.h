#ifndef ICMPGENERATOR
#define ICMPGENERATOR

#include <QObject>

#include "winsock2.h"
#include "iphlpapi.h"
#include "icmpapi.h"

class ICMPGenerator : public QObject
{
    Q_OBJECT

public:
    ICMPGenerator(QObject* parent = 0);
    ~ICMPGenerator();

public slots:
    void sendPacket();
};

#endif // ICMPGENERATOR

