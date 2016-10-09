#ifndef INTERFACE_H
#define INTERFACE_H

#include <QWidget>

#include "icmpgenerator.h"

namespace Ui {
class Interface;
}

class Interface : public QWidget
{
    Q_OBJECT

public:
    explicit Interface(QWidget *parent = 0);
    ~Interface();

private:
    Ui::Interface *ui;
    ICMPGenerator* mGenerator;
};

#endif // INTERFACE_H
