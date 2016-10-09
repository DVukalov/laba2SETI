#ifndef SNIFFER
#define SNIFFER

#include <QObject>

class Sniffer : public QObject
{
    Q_OBJECT

public:
    Sniffer(QObject* parent = 0);
    ~Sniffer();
};

#endif // SNIFFER

