#include "interface.h"
#include "ui_interface.h"

Interface::Interface(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Interface)
{
    ui->setupUi(this);
    mStartBut = new QPushButton ("Start", this);
    mStopBut = new QPushButton("Stop", this);
    mSniffer = new Sniffer(this);
    QHBoxLayout *butLayaout = new QHBoxLayout();
    butLayaout->addWidget(mStartBut);
    butLayaout->addWidget(mStopBut);
    this->setLayout(butLayaout);
    connect(mStartBut, SIGNAL(clicked()), this, SLOT(startSniffer()));

}
Interface::~Interface()
{
    delete ui;
}
void Interface::startSniffer()
{
    mSniffer->startSniffer();
    mStartBut->setDisabled(TRUE);
}
