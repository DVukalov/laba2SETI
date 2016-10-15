#include "interface.h"
#include "sniffer.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Interface w;
    w.show();
//    Sniffer sw;
    return a.exec();
}
