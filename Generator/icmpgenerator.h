#ifndef ICMPGENERATOR
#define ICMPGENERATOR

#pragma once

#include <QDebug>
#include <QObject>
#include <QByteArray>

#include "conio.h"
#include "winsock2.h"
#include "iphlpapi.h"
#include "icmpapi.h"
#include "mstcpip.h"

struct ip_header
{
    //uchar ver_ihl;      // Длина заголовка (4 бита)
                        // (измеряется в словах по 32 бита) +
                        // + Номер версии протокола (4 бита)
    uchar hdrlen:4,
          version:4;
    uchar tos;          // Тип сервиса
    ushort tlen;        // Общая длина пакета
    ushort id;          // Идентификатор пакета
    ushort flags_fo;    // Управляющие флаги (3 бита)
                        // + Смещение фрагмента (13 бит)
    uchar ttl;          // Время жизни пакета
    uchar proto;        // Протокол верхнего уровня
    ushort crc;         // CRC заголовка
    uint src_addr;      // IP-адрес отправителя
    uint dst_addr;      // IP-адрес получателя
};

struct icmp_header
{
    uchar type;   // тип ICMP- пакета
    uchar code;   // код ICMP- пакета
    ushort crc;   // контрольная сумма
    union
    {
        struct
        {
            uchar uc1;
            uchar uc2;
            uchar uc3;
            uchar uc4;
        } s_uc;
        struct
        {
            ushort us1;
            ushort us2;
        } s_us;

        ulong s_ul;

    } s_icmp;   // зависит от типа
};

class ICMPGenerator : public QObject
{
    Q_OBJECT

public:
    ICMPGenerator(QObject* parent = 0);
    ~ICMPGenerator();


public slots:
    int rs_exit(void);
    int sendDatagram(QByteArray message);
    void setSRC(QString str);
    void setDST(QString str);
    void setTYPE(QString str);
    void setCODE(QString str);

private slots:
    int rs_init (int v_major, int v_minor);
    unsigned short rs_crc (unsigned short * buffer, int length);

private:
    SOCKET mSocket;
    struct ip_header mIPH;
    struct icmp_header mICMPH;
};

#endif // ICMPGENERATOR

