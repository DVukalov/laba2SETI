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
    mIPH.tos = 0xFC; // все требования без ECN
    mIPH.id = packetID++;
    mIPH.flags_fo = 0x0;
    mIPH.ttl = 0x40; // 64 (default)
    mIPH.proto = 0x01; // ICMP

    // Заполнение полей заголовка ICMP
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

    mSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

    __print << mSocket << WSAGetLastError();

    uint use_own_header = 1;
    setsockopt(mSocket, IPPROTO_IP, 2, (char*)&use_own_header,
                    sizeof(use_own_header));

    int tos = 0;
    int tos_len = sizeof (tos);
    setsockopt(mSocket, IPPROTO_IP, 3, (char *)&tos,
                 tos_len);
    __print << mSocket << WSAGetLastError();
}

ICMPGenerator::~ICMPGenerator()
{
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
    uint PACKlen = IPlen + ICMPlen + DATAlen;
    sockaddr_in target;

    memset(&target, 0, sizeof (target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = mIPH.dst_addr;
    target.sin_port = 0;
    mIPH.tlen = PACKlen;

    mainBuffer.resize(0);
    buffer.resize(0);
    buffer.append((char *)&mICMPH, ICMPlen);
    buffer.append(message, DATAlen);
    mICMPH.crc = rs_crc((ushort *)buffer.data(), buffer.size());

    mIPH.hdrlen = IPlen / 4;
    mIPH.version = (uchar)atoi("4");

    mainBuffer.append((char *)&mIPH, IPlen);
    mainBuffer.append((char *)&mICMPH, ICMPlen);
    mainBuffer.append(message, DATAlen);


    mIPH.crc = rs_crc((ushort *)mainBuffer.data(), mainBuffer.size());

    mainBuffer.clear();
    mainBuffer.resize(0);
    mainBuffer.append((char *)&mIPH, IPlen);
    mainBuffer.append((char *)&mICMPH, ICMPlen);
    mainBuffer.append(message, DATAlen);

    ip_header* LOL = (ip_header *)mainBuffer.data();
    icmp_header* LOL2 = (icmp_header *)(mainBuffer.data() + IPlen);



    result = sendto (mSocket, mainBuffer.data(), PACKlen, 0,
                (struct sockaddr *)&target, sizeof(target));

    //__print << WSAGetLastError() << result << mainBuffer.length() << PACKlen;

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

ushort ICMPGenerator::rs_crc (unsigned short * buffer, int length)
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
}

void ICMPGenerator::setCODE(QString str)
{
    mICMPH.code = (unsigned char)str.toInt();
}
