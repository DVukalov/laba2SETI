#include <QDebug>
#include "icmpgenerator.h"

namespace
{
    struct icmp_header
    {
    uchar   type;			// тип ICMP- пакета
    uchar   code;			// код ICMP- пакета
    ushort  crc ;			// контрольная сумма
    union {
        struct { uchar	uc1, uc2, uc3, uc4; } s_uc;
        struct { ushort	us1, us2; } s_us;
        ulong s_ul;
        } s_icmp;				// зависит от типа
    };
    //Определим вспомогательные макроопределения:
    // тип ICMP пакета
    #define ICMP_ECHO_REPLY			0
    #define ICMP_UNREACHABLE		3
    #define ICMP_QUENCH				4
    #define ICMP_REDIRECT			5
    #define ICMP_ECHO				8
    #define ICMP_TIME				11
    #define ICMP_PARAMETER			12
    #define ICMP_TIMESTAMP			13
    #define ICMP_TIMESTAMP_REPLY	14
    #define ICMP_INFORMATION		15
    #define ICMP_INFORMATION_REPLY	16

    // ICMP коды для ICMP типа ICMP_UNREACHABLE
    #define ICMP_UNREACHABLE_NET			0
    #define ICMP_UNREACHABLE_HOST			1
    #define ICMP_UNREACHABLE_PROTOCOL		2
    #define ICMP_UNREACHABLE_PORT			3
    #define ICMP_UNREACHABLE_FRAGMENTATION	4
    #define ICMP_UNREACHABLE_SOURCE         5
    #define ICMP_UNREACHABLE_SIZE			8

    // ICMP коды для ICMP типа ICMP_TIME
    #define ICMP_TIME_TRANSIT			0
    #define ICMP_TIME_FRAGMENT			1

    // ICMP коды для ICMP типа ICMP_REDIRECT
    #define ICMP_REDIRECT_NETWORK			0
    #define ICMP_REDIRECT_HOST              1
    #define ICMP_REDIRECT_SERVICE_NETWORK	2
    #define ICMP_REDIRECT_SERVICE_HOST		3
}

ICMPGenerator::ICMPGenerator(QObject* parent)
    : QObject(parent)
{
    __print;
}

ICMPGenerator::~ICMPGenerator()
{
    __print;
}

void ICMPGenerator::sendPacket()
{
    __print;
    // Объявляем переменные
    HANDLE hIcmpFile;                       // Обработчик
    unsigned long ipaddr = INADDR_NONE;     // Адрес назначения
    DWORD dwRetVal = 0;                     // Количество ответов
    char SendData[32] = "Data Buffer";      // Буффер отсылаемых данных
    LPVOID ReplyBuffer = NULL;              // Буффер ответов
    DWORD ReplySize = 0;                    // Размер буффера ответов

    // Устанавливаем IP-адрес из поля lineEdit
    ipaddr = inet_addr("192.168.1.65"/*ui->lineEdit->text().toStdString().c_str()*/);
    hIcmpFile = IcmpCreateFile();   // Создаём обработчик

    // Выделяем память под буффер ответов
    ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
    ReplyBuffer = (VOID*) malloc(ReplySize);

    // Вызываем функцию ICMP эхо запроса
    dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, SendData, sizeof(SendData),
                NULL, ReplyBuffer, ReplySize, 1000);

    // создаём строку, в которою запишем сообщения ответа
    QString strMessage = "";

    if (dwRetVal != 0)
    {
        // Структура эхо ответа
        PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
        struct in_addr ReplyAddr;
        ReplyAddr.S_un.S_addr = pEchoReply->Address;

        strMessage += "Sent icmp message to 1\n"/* + ui->lineEdit->text() + "\n"*/;
        if (dwRetVal > 1) {
            strMessage += "Received " + QString::number(dwRetVal) + " icmp message responses \n";
            strMessage += "Information from the first response: ";
        }
        else {
            strMessage += "Received " + QString::number(dwRetVal) + " icmp message response \n";
            strMessage += "Information from the first response: ";
        }
            strMessage += "Received from ";
            strMessage += inet_ntoa( ReplyAddr );
            strMessage += "\n";
            strMessage += "Status = " + pEchoReply->Status;
            strMessage += "Roundtrip time = " + QString::number(pEchoReply->RoundTripTime) + " milliseconds \n";
    }
    else
    {
        strMessage += "Call to IcmpSendEcho failed.\n";
        strMessage += "IcmpSendEcho returned error: ";
        strMessage += QString::number(GetLastError());
    }
    __print << dwRetVal << strMessage;
    //ui->textEdit->setText(strMessage); // Отображаем информацию о полученных данных
    free(ReplyBuffer); // Освобождаем память
}
