#include "icmpgenerator.h"

namespace
{
const uint max_buf_len = 64 * 1024;
ushort packetID = 0;
}

ICMPGenerator::ICMPGenerator(QObject* parent)
    : QObject(parent)
{
    ZeroMemory(&mICMPH, sizeof(icmp_header));
    ZeroMemory(&mIPH, sizeof(ip_header));
    // Заполнение полей заголовка IP
    mIPH.ver_ihl |= sizeof(ip_header) << 4;
    mIPH.tos = 0xFC; // все требования без ECN
    mIPH.id = packetID++;
    mIPH.flags_fo = 0x0;
    mIPH.ttl = 0x40; // 64 (default)
    mIPH.proto = 0x01; // ICMP
    //mIPH.src_addr = inet_addr("192.168.112.23"); // 192.168.0.1
    //mIPH.dst_addr = inet_addr("192.168.112.22"); // 192.168.0.2

    // Заполнение полей заголовка ICMP
//    mICMPH.type = ; // ICMP_ECHO
//    mICMPH.code = 0x0;
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

    rs_init(2, 2);

    mSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    uint use_own_header = 1;
    setsockopt(mSocket, IPPROTO_RAW, 2, (char*)&use_own_header,
                    sizeof(use_own_header));

    int tos = 0;
    int tos_len = sizeof (tos);
    setsockopt(mSocket, IPPROTO_IP, 3, (char *)&tos,
                 tos_len);
    __print << mSocket;
}

ICMPGenerator::~ICMPGenerator()
{
//    __print;
    closesocket(mSocket);
    WSACleanup();
}

int ICMPGenerator::rs_exit(void)
{
    // Закрытие библиотеки Winsock
    WSACleanup ();
    return 0;
}

int ICMPGenerator::sendDatagram(QByteArray message)
{

    int result;
    QByteArray buffer , mainBuffer;
    uint DATAlen = message.size();
    uint IPlen = sizeof(struct ip_header);
    uint ICMPlen = sizeof(struct icmp_header);
    // Р’С‹С‡РёСЃР»РµРЅРёРµ РґР»РёРЅС‹ Рё Р·Р°РіРѕР»РѕРІРєР° РїР°РєРµС‚Р°
    uint PACKlen = IPlen + ICMPlen + DATAlen;
    sockaddr_in target;

    memset(&target, 0, sizeof (target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = mIPH.dst_addr;
    target.sin_port = 0;
    mIPH.tlen = PACKlen;

    mainBuffer.resize(PACKlen);
    buffer.resize(ICMPlen + DATAlen);
    buffer.append((char *)&mICMPH);

    buffer.append(message);

    mICMPH.crc = rs_crc((ushort *)buffer.data(), buffer.size());
    __print <<QByteArray::number(mICMPH.crc,16);
    mainBuffer.append((char *)&mIPH);
    mainBuffer.append((char *)&mICMPH);
    mainBuffer.append(message);

//    if (!(mIPH.ver_ihl & 0x0F))
//        mIPH.ver_ihl |= 0x0F & (IPlen / 4);

//    mIPH.ver_ihl = IPlen / 4 + (unsigned char)atoi("4")*16;

    mIPH.crc = rs_crc((ushort *)mainBuffer.data(), mainBuffer.size());
    mainBuffer.clear();
    mainBuffer.append((char *)&mIPH);
    mainBuffer.append((char *)&mICMPH);
    mainBuffer.append(message);

    ip_header* LOL = (ip_header *)mainBuffer.data();

    __print << LOL->ver_ihl << LOL->crc << LOL->dst_addr << LOL->tlen;

    result = sendto (mSocket, mainBuffer.data(), PACKlen, 0,
                (struct sockaddr *)&target, sizeof(target));
    __print <<WSAGetLastError() << mainBuffer << result << PACKlen;


    return result;
}


int ICMPGenerator::rs_init (int v_major, int v_minor)
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
        rs_exit();
        return WSAGetLastError();
    }
    return 0;
}

unsigned short ICMPGenerator::rs_crc (unsigned short * buffer, int length)
{
    unsigned long crc = 0;
    // Вычисление CRC
    while (length > 1)
    {
        crc += *buffer++;
        length -= sizeof (unsigned short);
    }
    if (length) crc += *(unsigned char*) buffer;
    // Закончить вычисления
    crc = (crc >> 16) + (crc & 0xffff);
    crc += (crc >> 16);
    // Возвращаем инвертированное значение
    return (unsigned short)(~crc);
}


int ICMPGenerator::rs_send_ip(SOCKET s, struct ip_header iph,
                               unsigned char * data,
                               int data_length,
                               unsigned short dst_port_raw)
{
    char * buffer;
    int result;
    sockaddr_in target;
    unsigned char header_length;
    unsigned int packet_length;
    memset (&target, 0, sizeof (target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = iph.dst_addr;
    target.sin_port = dst_port_raw;

    // Вычисление длины и заголовка пакета
    header_length = sizeof (struct ip_header);
    packet_length = header_length + data_length;

    // Установка CRC.
    iph.crc = 0;

    // Заполнение некоторых полей заголовка IP
//    iph.ver_ihl = RS_IP_VERSION;
    iph.ver_ihl = 0;

    // Если длина пакета не задана, то длина пакета
    // приравнивается к длине заголовка
    if (!(iph.ver_ihl & 0x0F))
      iph.ver_ihl |= 0x0F & (header_length / 4);
    buffer =(char *) calloc (packet_length, sizeof (char));

    // Копирование заголовка пакета в буфер ( CRC равно 0).
    memcpy (buffer, &iph, sizeof (struct ip_header));

    // Копирование данных в буфер
    if (data) memcpy (buffer + header_length, data,
              data_length);

    // Вычисление CRC.
    iph.crc = rs_crc((unsigned short *) buffer,
              packet_length);

    // Копирование заголовка пакета в буфер (CRC посчитана).
    memcpy (buffer, &iph, sizeof (struct ip_header));

    // Отправка IP пакета в сеть.
    result = sendto ( s, buffer, packet_length, 0,
              (struct sockaddr *)&target,
              sizeof (target));
    free (buffer);

    return result;
}

void ICMPGenerator::setSRC(QString str)
{
    mIPH.src_addr = inet_addr(str.toStdString().c_str());
}

void ICMPGenerator::setDST(QString str)
{
    mIPH.dst_addr = inet_addr(str.toStdString().c_str());
}

void ICMPGenerator::setTYPE(QString str)
{
    mICMPH.type = (unsigned char)str.toInt();
    __print << mICMPH.type;
}

void ICMPGenerator::setCODE(QString str)
{
    mICMPH.code = (unsigned char)str.toInt();
    __print << mICMPH.code;
}

