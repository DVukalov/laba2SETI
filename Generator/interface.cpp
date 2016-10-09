#include "interface.h"
#include "ui_interface.h"

Interface::Interface(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Interface)
{
    ui->setupUi(this);
    mGenerator = new ICMPGenerator(this);
    mGenerator->sendPacket();
}

Interface::~Interface()
{
    delete ui;
}
