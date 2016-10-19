#ifndef INTERFACE_H
#define INTERFACE_H

#include <QWidget>
#include <QLabel>
#include <QLayout>
#include <QTextEdit>
#include <QLineEdit>
#include <QByteArray>
#include <QPushButton>
#include <QHostAddress>

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

public slots:
    void send();

private:
    Ui::Interface *ui;

    QPushButton* mSendBut;
    QTextEdit* mMessageEdit;
    ICMPGenerator* mGenerator;
    QLineEdit* srcHostLine;
    QLabel* srcHostL;
    QLineEdit* dstHostLine;
    QLabel* dstHostL;
    QLineEdit* ICMPtype;
    QLabel* ICMPtypeL;
    QLineEdit* ICMPcode;
    QLabel* ICMPcodeL;
};

#endif // INTERFACE_H
