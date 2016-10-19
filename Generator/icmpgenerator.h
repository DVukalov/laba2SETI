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
unsigned char	ver_ihl;	// Длина заголовка (4 бита)
                // (измеряется в словах по 32 бита) +
                // + Номер версии протокола (4 бита)
unsigned char	tos;		// Тип сервиса
unsigned short	tlen;		// Общая длина пакета
unsigned short	id;		// Идентификатор пакета
unsigned short	flags_fo;	// Управляющие флаги (3 бита)
                    // + Смещение фрагмента (13 бит)
unsigned char	ttl;		// Время жизни пакета
unsigned char	proto;		// Протокол верхнего уровня
unsigned short	crc;		// CRC заголовка
unsigned int	src_addr;	// IP-адрес отправителя
unsigned int	dst_addr;	// IP-адрес получателя
};

struct icmp_header
{
unsigned char   type;			// тип ICMP- пакета
unsigned char   code;			// код ICMP- пакета
unsigned short  crc ;			// контрольная сумма
union {
    struct { unsigned char	uc1, uc2, uc3, uc4; } s_uc;
    struct { unsigned short	us1, us2; } s_us;
    unsigned long s_ul;
    } s_icmp;				// зависит от типа
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
    int rs_send_ip(SOCKET s, struct ip_header iph, unsigned char * data,
                   int data_length, unsigned short dst_port_raw);
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

