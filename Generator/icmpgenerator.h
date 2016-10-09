#ifndef ICMPGENERATOR
#define ICMPGENERATOR

#include <QObject>

#include <windows.h>
#include <icmpapi.h> // ???

class ICMPGenerator : public QObject
{
    Q_OBJECT

public:
    ICMPGenerator(QObject* parent = 0);
    ~ICMPGenerator();
};

#endif // ICMPGENERATOR

