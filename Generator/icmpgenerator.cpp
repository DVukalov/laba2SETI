#include "icmpgenerator.h"

namespace
{
const uint max_buf_len = 64 * 1024;
ushort packetID = 0;
}

ICMPGenerator::ICMPGenerator(QObject* parent)
    : QObject(parent)
{
    // Заполнение полей заголовка IP
    mIPH.ver_ihl = 0x20;
    mIPH.tos = 0xFC; // все требования без ECN
    mIPH.id = packetID++;
    mIPH.flags_fo = 0x0;
    mIPH.ttl = 0x40; // 64 (default)
    mIPH.proto = 0x01; // ICMP
    mIPH.src_addr = 0xC0A80001; // 192.168.0.1
    mIPH.dst_addr = 0xC0A80002; // 192.168.0.2

    // Заполнение полей заголовка ICMP
    mICMPH.type = 0x8; // ICMP_ECHO
    mICMPH.code = 0x0;
    // Идентификатор
    mICMPH.s_icmp.s_uc.uc1 = 0xC1;
    mICMPH.s_icmp.s_uc.uc2 = 0xC2;
    mICMPH.s_icmp.s_uc.uc3 = 0xC3;
    mICMPH.s_icmp.s_uc.uc4 = 0xC4;
    // Номер последовательности
    mICMPH.s_icmp.s_us.us1 = 0xA1;
    mICMPH.s_icmp.s_us.us1 = 0xA2;
    // Данные
    mICMPH.s_icmp.s_ul = 0xE0A55;

    init(2, 2);
    mSocket = socket(AF_INET, SOCK_RAW,IPPROTO_ICMP);
//    mSocket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0,
//                        WSA_FLAG_OVERLAPPED);

    __print << mSocket;
}

ICMPGenerator::~ICMPGenerator()
{
//    __print;
    closesocket(mSocket);
    WSACleanup();
}

int ICMPGenerator::init (int v_major, int v_minor)
{
    WSADATA wsadata;
    // Инициализация WinSock заданной версии
    if (WSAStartup(MAKEWORD(v_major, v_minor), &wsadata))
    {
        return WSAGetLastError();
    }
    // Проверка версии WinSock
    if(LOBYTE(wsadata.wVersion) != v_minor ||
        HIBYTE(wsadata.wVersion) != v_major)
    {        
        WSACleanup();
        return WSAGetLastError();
    }
    return 0;
}

ushort ICMPGenerator::getCRC (ushort* buffer, int length)
{
    ulong crc = 0;
    // Вычисление CRC
    while (length > 1)
    {
        crc += *buffer++;
        length -= sizeof (ushort);
    }
    if (length) crc += *(uchar*)buffer;
    // Закончить вычисления
    crc = (crc >> 16) + (crc & 0xffff);
    crc += (crc >> 16);
    // Возвращаем инвертированное значение
    return (ushort)(~crc);
}

int ICMPGenerator::sendDatagram(QByteArray message)
{
    int result;
    char* buffer;
    uint DATAlen = message.size();
    uint IPlen = sizeof(struct ip_header);
    uint ICMPlen = sizeof(struct icmp_header);
    // Вычисление длины и заголовка пакета
    uint PACKlen = /*IPlen +*/ ICMPlen + DATAlen;
    sockaddr_in target;

    memset(&target, 0, sizeof (target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = mIPH.dst_addr;
    target.sin_port = 0;
//    mIPH.tlen = PACKlen;
    buffer = new char[ICMPlen + DATAlen];

    // Копирование заголовка пакета в буфер ( CRC равно 0).
    memcpy(buffer, &mICMPH, ICMPlen);

    // Копирование данных в буфер
    memcpy (buffer + ICMPlen, message.data(), DATAlen);

    // Вычисление CRC.
    mICMPH.crc = getCRC((ushort *)buffer, ICMPlen + DATAlen);

    // Копирование заголовка пакета в буфер (CRC посчитана).
    memcpy(buffer, &mICMPH, ICMPlen);

    // Установка CRC.
    mIPH.crc = 0;

    // Если длина пакета не задана, то длина пакета
    // приравнивается к длине заголовка
//    if (!(mIPH.ver_ihl & 0x0F))
//        mIPH.ver_ihl |= 0x0F & (IPlen / 4);

    delete buffer;
    buffer = new char[PACKlen];

    // Копирование заголовка пакета в буфер ( CRC равно 0).
//    memcpy(buffer, &mIPH, IPlen);

    // Копирование данных в буфер
    memcpy (buffer /*+ IPlen*/, message.data(), ICMPlen + DATAlen);

    // Вычисление CRC.
//    mIPH.crc = getCRC((ushort *)buffer, PACKlen);

    // Копирование заголовка пакета в буфер (CRC посчитана).
//    memcpy (buffer, &mIPH, IPlen);

    // Копирование заголовка пакета в буфер (CRC посчитана).
//    memcpy (buffer, &mIPH, sizeof (struct ip_header));

    // Отправка IP пакета в сеть.
    result = sendto (mSocket, buffer, PACKlen, 0,
                (struct sockaddr *)&target, sizeof(target));

    return result;
}
