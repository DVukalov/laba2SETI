#include "interface.h"
#include "ui_interface.h"

Interface::Interface(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Interface)
{
    ui->setupUi(this);
    mSendBut = new QPushButton("Send", this);
    mMessageEdit = new QTextEdit(this);    
    mGenerator = new ICMPGenerator(this);

    srcHostLine = new QLineEdit(this);
    dstHostLine = new QLineEdit(this);\
    ICMPtype = new QLineEdit(this);
    ICMPcode = new QLineEdit(this);

    srcHostL = new QLabel("Source host:         ", this);
    dstHostL = new QLabel("Destination host: ", this);
    ICMPtypeL = new QLabel("Packet type:         ", this);
    ICMPcodeL = new QLabel("Packet code:      ", this);

    QHBoxLayout* hostLayout = new QHBoxLayout();
    hostLayout->addWidget(srcHostL);
    hostLayout->addWidget(srcHostLine);
    hostLayout->addWidget(dstHostL);
    hostLayout->addWidget(dstHostLine);

    QHBoxLayout* TCLayout = new QHBoxLayout();
    TCLayout->addWidget(ICMPtypeL);
    TCLayout->addWidget(ICMPtype);
    TCLayout->addWidget(ICMPcodeL);
    TCLayout->addWidget(ICMPcode);

    QHBoxLayout* interLayout = new QHBoxLayout();
    interLayout->addWidget(mMessageEdit);
    interLayout->addWidget(mSendBut);

    QVBoxLayout* mainLayout = new QVBoxLayout();
    mainLayout->addLayout(hostLayout);
    mainLayout->addLayout(TCLayout);
    mainLayout->addLayout(interLayout);

    this->setLayout(mainLayout);
    this->setFixedSize(600, 200);

    connect(mSendBut, SIGNAL(clicked()), this, SLOT(send()));
}

Interface::~Interface()
{
    delete ui;
}

void Interface::send()
{
    bool ok;
    int res;
    if(QHostAddress(srcHostLine->text()).isNull())
    {
        srcHostLine->setText("Wrong address format");
        return;
    }
    if(QHostAddress(dstHostLine->text()).isNull())
    {
        dstHostLine->setText("Wrong address format");
        return;
    }
    res = ICMPtype->text().toInt(&ok, 10);
    if(res < 0 || !ok)
    {
        ICMPtype->setText("Wrong type format");
        return;
    }
    res = ICMPcode->text().toInt(&ok, 10);
    if(res < 0 || !ok)
    {
        ICMPcode->setText("Wrong code format");
        return;
    }

    mGenerator->setDST(dstHostLine->text());
    mGenerator->setCODE(ICMPcode->text());
    mGenerator->setSRC(srcHostLine->text());
    mGenerator->setTYPE(ICMPtype->text());
    mGenerator->sendDatagram(QByteArray(mMessageEdit->toPlainText()
                             .toStdString().c_str()));
}
