#ifndef INTERFACE_H
#define INTERFACE_H

#include <QWidget>
#include <QLayout>
#include <QPushButton>
#include "sniffer.h"
#include <QScrollArea>
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
    QPushButton *mStartBut;
    QPushButton *mStopBut;
    QScrollArea *mArea;
    Sniffer * mSniffer;
};

#endif // INTERFACE_H
