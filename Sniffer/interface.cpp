#include "interface.h"
#include "ui_interface.h"

Interface::Interface(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Interface)
{
    ui->setupUi(this);
    this->setWindowFlags(Qt::CustomizeWindowHint|
                         Qt::WindowTitleHint);
    this->setFixedSize(300, 200);
    mStartBut = new QPushButton ("Start", this);
    mStopBut = new QPushButton("Stop", this);
    mSniffer = new Sniffer(this);

//    QThread thread;
//    mSniffer->moveToThread(&thread);
//    thread.start();

    mFilterUDP = new QCheckBox("UDP");
    mFilterUDP->setChecked(true);

    mFilterTCP = new QCheckBox("TCP");
    mFilterTCP->setChecked(true);

    mFilterICMP = new QCheckBox("ICMP");
    mFilterICMP->setChecked(true);

    QVBoxLayout *comboLayout = new QVBoxLayout();
    comboLayout->addWidget(mFilterUDP);
    comboLayout->addWidget(mFilterTCP);
    comboLayout->addWidget(mFilterICMP);

    QHBoxLayout *butLayaout = new QHBoxLayout();
    butLayaout->addWidget(mStartBut);
    butLayaout->addWidget(mStopBut);

    QVBoxLayout *mainLayout = new QVBoxLayout();
    mainLayout->addLayout(comboLayout);
    mainLayout->addLayout(butLayaout);

    this->setLayout(mainLayout);

    connect(mStopBut, SIGNAL(clicked()), this, SLOT(close()));
    connect(mStartBut, SIGNAL(clicked()), this, SLOT(startSniffer()));
    ;

}
Interface::~Interface()
{
    __print;
    delete mStartBut;
    delete mStopBut;
    delete mFilterTCP;
    delete mFilterUDP;
    delete mFilterICMP;
    delete mSniffer;
    delete ui;
}
void Interface::startSniffer()
{
    mStartBut->setDisabled(TRUE);
    mSniffer->startSniffer();

}
