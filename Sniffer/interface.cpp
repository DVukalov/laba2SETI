#include "interface.h"
#include "ui_interface.h"

Interface::Interface(QWidget *parent) :
    QWidget(parent),
   ui(new Ui::Interface)
{
    ui->setupUi(this);
    this->setWindowFlags(Qt::CustomizeWindowHint|
                         Qt::WindowTitleHint);
    this->setWindowTitle("SNIFFER");
    this->setFixedSize(300, 200);


    mStartBut = new QPushButton ("Start", this);
    mStartBut->setFont(QFont("Courier", 12, QFont::Bold));

    mStopBut = new QPushButton("Stop", this);
    mStopBut->setFont(QFont("Courier", 12, QFont::Bold));
    mSniffer = new Sniffer;

    connect(&mThread, &QThread::started, mSniffer, &Sniffer::startSniffer);
    mSniffer->moveToThread(&mThread);


    mFilterUDP = new QCheckBox("UDP");
    mFilterUDP->setFont(QFont("Courier", 12, QFont::Bold));
    mFilterUDP->setStyleSheet("color: rgb(255,255,255)");
    mFilterUDP->setChecked(true);

    mFilterTCP = new QCheckBox("TCP");
    mFilterTCP->setFont(QFont("Courier", 12, QFont::Bold));
    mFilterTCP->setStyleSheet("color: rgb(255,255,255)");
    mFilterTCP->setChecked(true);

    mFilterICMP = new QCheckBox("ICMP");
    mFilterICMP->setFont(QFont("Courier", 12, QFont::Bold));
    mFilterICMP->setStyleSheet("color: rgb(255,255,255)");
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
    connect(mStopBut, SIGNAL(clicked()), mSniffer, SLOT(stopReceive()),
            Qt::DirectConnection);
    connect(mStartBut, SIGNAL(clicked()), this, SLOT(startSniffer()));

    connect(mFilterUDP, SIGNAL(stateChanged(int)), mSniffer, SLOT(checkUDP(int)),
            Qt::DirectConnection);
    connect(mFilterTCP, SIGNAL(stateChanged(int)), mSniffer, SLOT(checkTCP(int)),
            Qt::DirectConnection);
    connect(mFilterICMP, SIGNAL(stateChanged(int)), mSniffer, SLOT(checkICMP(int)),
            Qt::DirectConnection);

    QPalette pal;
    pal.setBrush(this->backgroundRole(),QBrush(QPixmap("7.jpg")));
    this->setPalette(pal);
    this->setAutoFillBackground(true);

}
Interface::~Interface()
{

    if (mThread.isRunning())
        mThread.exit();
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
    mThread.start();
}
