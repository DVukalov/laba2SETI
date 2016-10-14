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

    QHBoxLayout* mainLayout = new QHBoxLayout();
    mainLayout->addWidget(mMessageEdit);
    mainLayout->addWidget(mSendBut);

    this->setLayout(mainLayout);

    connect(mSendBut, SIGNAL(clicked()), this, SLOT(send()));
}

Interface::~Interface()
{
    delete ui;
}

void Interface::send()
{
    mGenerator->sendDatagram(QByteArray(mMessageEdit->toPlainText()
                             .toStdString().c_str()));
}
