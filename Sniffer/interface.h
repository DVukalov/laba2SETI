#ifndef INTERFACE_H
#define INTERFACE_H

#include "sniffer.h"
#include <QWidget>
#include <QLayout>
#include <QPushButton>
#include <QScrollArea>
#include <QCheckBox>
#include <QThread>
namespace Ui {
class Interface;
}

class Interface : public QWidget
{
    Q_OBJECT

public:
    explicit Interface(QWidget *parent = 0);
    ~Interface();
public slots:
    void startSniffer();
private:
    Ui::Interface *ui;
    Sniffer * mSniffer;
public:
    QPushButton *mStartBut;
    QPushButton *mStopBut;
    QScrollArea *mArea;
    QCheckBox *mFilterUDP;
    QCheckBox *mFilterTCP;
    QCheckBox *mFilterICMP;
};

#endif // INTERFACE_H
