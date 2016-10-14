#include "icmpgenerator.h"

namespace
{

const uint max_buf_len = 64 * 1024;

struct ip_header
{
uchar ver_ihl;      // Длина заголовка (4 бита)
                    // (измеряется в словах по 32 бита) +
                    // + Номер версии протокола (4 бита)
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
    const uchar type = 0;	// тип ICMP- пакета
    const uchar code = 0;	// код ICMP- пакета
    ushort crc;             // контрольная сумма
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

    } s_icmp;				// зависит от типа
};

// Версия IP пакета
#define RS_IP_VERSION		0x40

}

ICMPGenerator::ICMPGenerator(QObject* parent)
    : QObject(parent)
{
    __print << init(2, 2);
    socket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_RAW, NULL, 0,
                       WSA_FLAG_OVERLAPPED);

}

ICMPGenerator::~ICMPGenerator()
{
    __print;
    close(socket);
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
        rs_exit();
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

int ICMPGenerator::sendIP(SOCKET s, struct ip_header iph,
            uchar* data, int data_length,
            ushort dst_port_raw)
{
    int result;
    char* buffer;
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
    iph.ver_ihl = RS_IP_VERSION;

    // Если длина пакета не задана, то длина пакета
    // приравнивается к длине заголовка
    if (!(iph.ver_ihl & 0x0F))
        iph.ver_ihl |= 0x0F & (header_length / 4);
    buffer =(char *)calloc(packet_length, sizeof (char));

    // Копирование заголовка пакета в буфер ( CRC равно 0).
    memcpy(buffer, &iph, sizeof (struct ip_header));

    // Копирование данных в буфер
    if (data)
        memcpy (buffer + header_length, data, data_length);

    // Вычисление CRC.
    iph.crc = getCRC((unsigned short *) buffer, packet_length);

    // Копирование заголовка пакета в буфер (CRC посчитана).
    memcpy (buffer, &iph, sizeof (struct ip_header));

    // Отправка IP пакета в сеть.
    result = sendto ( s, buffer, packet_length, 0,
                (struct sockaddr *)&target,
                sizeof (target));
    free (buffer);
    return result;
}

int ICMPGenerator::sendICMP(SOCKET s, struct ip_header iph,
              struct icmp_header icmph,
              uchar* data, int data_length)
{
    char* buffer;
    int result;
    uchar header_length;
    uint packet_length;

    // Вычисление длин пакета и заголовка.
    header_length = sizeof (struct icmp_header);
    packet_length = header_length + data_length;
    icmph.crc = 0;
    buffer = new char[packet_length];

    // Копирование заголовка пакета в буфер ( CRC равно 0).
    memcpy(buffer, &icmph, sizeof(struct icmp_header));

    // Копирование данных в буфер
    if (data)
        memcpy (buffer + header_length, data, data_length);

    // Вычисление CRC.
    icmph.crc = getCRC ((unsigned short *) buffer,
                  packet_length);

    // Копирование заголовка пакета в буфер (CRC посчитана).
    memcpy (buffer, &icmph, sizeof (struct icmp_header));

    // Отправка IP пакета с вложенным ICMP пакетом.
    result = sendIP (s, iph, buffer, packet_length, 0);

    delete buffer;
    buffer = nullptr;
    return result;
}

int ICMPGenerator::sendDatagram(QByteArray data)
{
    int result;
    ip_header IPH;
    icmp_header ICMPH;
    // TODO забить хэдэры

    // Отправка ICMP пакета с вложенным пакетом данных.
    result = sendICMP(socket, IPH, ICMPH, data.data(), data.length());

    delete buffer;
    buffer = nullptr;
    return result;
}
