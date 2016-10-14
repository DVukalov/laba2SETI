#ifndef INTERFACE_H
#define INTERFACE_H

#include <QWidget>
#include <QLayout>
#include <QTextEdit>
#include <QByteArray>
#include <QPushButton>

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
};

#endif // INTERFACE_H
