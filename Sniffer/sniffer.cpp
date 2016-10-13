#include "sniffer.h"


namespace
{
    const uint max_buf_len = 64 * 1024;

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

    struct tcp_header
    {
    unsigned short	src_port;	// Порт отправителя
    unsigned short	dst_port;	// Порт получателя
    unsigned int	seq_n;		// Номер очереди
    unsigned int	ack_n;		// Номер подтверждения
    unsigned char	offset;		// Смещение данных (4 бита)
                        // + Зарезервировано (4 бита)
    unsigned char	flags;		// Зарезервировано (2 бита)
                        // + Флаги (6 бит)
    unsigned short	win;		// Размер окна
    unsigned short	crc;		// Контрольная сумма заголовка
    unsigned short	padding;	// Дополнение до 20 байт
    };


    struct udp_header
    {
    unsigned short   src_port ;	// номер порта отправителя
    unsigned short   dst_port ;	// номер порта получателя
    unsigned short   length;	// длина датаграммы
    unsigned short   crc;		// контрольная сумма заголовка
    };



}

Sniffer::Sniffer(QObject* parent)
    : QObject(parent)
{
    adrPC = new sockaddr_in;
    informHost = new HOSTENT;
    buffer = new char[max_buf_len];
    file.setFileName("log.txt");
    file.open(QIODevice::WriteOnly);
    file.flush();
    out.setDevice(&file);
    startSniffer();
    __print;

}

Sniffer::~Sniffer()
{
    delete buffer;
    delete adrPC;
    delete informHost;
    file.close();
}

bool Sniffer::initialization()
{
    __print;
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData))
    {
        __print <<"WSA_INIT";
        return false;
    }
    return true;
}

bool Sniffer::createSocket()
{
    __print;
   sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (INVALID_SOCKET == sock)
    {
        __print<<"SOCKET";
        WSACleanup();
        return false;
    }
    return true;
}

bool Sniffer::determIP_PC()
{
    __print;
    if(gethostname(name, sizeof(name)))
    {
        __print<<"GETHOSTNAME";
        closesocket(sock);
        WSACleanup();
        return false;
    }

    informHost = gethostbyname(name);
//    ZeroMemory(&adrPC, sizeof(adrPC));
//    adrPC = new sockaddr_in;
    adrPC->sin_family = AF_INET;
    adrPC->sin_addr.S_un.S_addr = ((struct in_addr *)
                                   informHost->h_addr_list[0])->S_un.S_addr;
//    adrPC->sin_port = htons(27015);
    return true;
}

bool Sniffer::bindSocket()
{
    __print;
    if (bind (sock, (SOCKADDR *)adrPC, sizeof(SOCKADDR)))
    {
        __print<<"BIND";
        closesocket(sock);
        WSACleanup();
        return false;
    }
    return true;
}

bool Sniffer::promiscuousModeON()
{
    __print;
    unsigned long flag = 1;
    if (ioctlsocket(sock, SIO_RCVALL, &flag))
    {
        __print<<"ioctlsocket";
        closesocket(sock);
        WSACleanup();
        return false;
    }
    return true;

}
bool Sniffer::startSniffer()
{
    __print;

    if (!(initialization() && createSocket() && determIP_PC()
          && bindSocket() && promiscuousModeON()))
        return false;
    else
    {
        while(!kbhit())
        {
            memset(buffer, 0, max_buf_len);

            uint count = recv(sock, buffer, max_buf_len,0);
            if (count >= sizeof(ip_header))
            {
                ip_header *ip = (ip_header *)buffer;
                if (count >=sizeof(ip_header))
                {
                    if (ip->proto == IPPROTO_TCP)
                    {
                        __print << "TCP";
                        parseTCP();
                    }
                    if (ip->proto == IPPROTO_UDP)
                    {
                        __print << "UDP";
                        parseUDP();
                    }
                    if (ip->proto == IPPROTO_ICMP)
                    {
                        __print << "ICMP";
                    }
                }



            }
        }

    }
    return true;
}

void Sniffer::parseIP()
{
    uint iplen;
    ip_header *ip = (ip_header *)buffer;
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->src_addr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->dst_addr;
    QByteArray data;
    data = "\n          IP Header \n |-IP Version          : " + QByteArray::number(0xF & ip->ver_ihl)
            + "\n |-Type Of Service     : " + QByteArray::number(ip->tos)
            + "\n |-IP Header Length    : " + QByteArray::number(0xF0 & ip->ver_ihl)
            + "\n |-IP Total Length     : " + QByteArray::number(ip->tlen)
            + "\n |-Identification      : " + QByteArray::number(ip->id)
            + "\n |-TTL                 : " + QByteArray::number(ip->ttl)
            + "\n |-Protocol            : " + QByteArray::number(ip->proto)
            + "\n |-Checksum            : " + QByteArray::number(ip->crc, 16)
            + "\n |-Source IP           : " + inet_ntoa(source.sin_addr)
            + "\n |-Destination IP      : " + inet_ntoa(dest.sin_addr);

    file.write(data.data());

    delete ip;
    ip = nullptr;
}

void Sniffer::printMSG()
{
//    ip_header * ip = (struct ip_header * )buffer;
//    iplen = (0xF0 & ip->ver_ihl) * 4;
//    udp_header *udp = (udp_header *)(buffer + iplen);

}

void Sniffer::parseICMP()
{
    parseIP();
    icmp_header * icmp = (icmp_header *)buffer;






}

void Sniffer::parseTCP()
{
    parseIP();
    unsigned short iplen;
    ip_header * ip = (struct ip_header * )buffer;
    iplen = (0xF0 & ip->ver_ihl) * 4;
    tcp_header * tcp = (tcp_header *)(buffer + iplen);
    QByteArray data;
    data = "\n\n          TCP Header \n    |-Source Port        : " + QByteArray::number(tcp->src_port)
            + "\n    |-Destination Port    : " + QByteArray::number(tcp->dst_port)
            + "\n    |-Sequence Number     : " + QByteArray::number(tcp->seq_n)
            + "\n    |-Acknowledge Number  : " + QByteArray::number(tcp->ack_n)
            + "\n    |-Window              : " + QByteArray::number(tcp->win)
            + "\n    |-Checksum            : " + QByteArray::number(tcp->crc,16)
            + "\n";
    file.write(data.data());
    delete ip;
    ip = nullptr;
    delete tcp;
    tcp = nullptr;
}

void Sniffer::parseUDP()
{
    parseIP();
    unsigned short iplen;
    ip_header * ip = (struct ip_header * )buffer;
    iplen = (0xF0 & ip->ver_ihl) * 4;
    udp_header *udp = (udp_header *)(buffer + iplen);
    QByteArray data;
    data = "\n\n          UDP Header \n    |-Source Port         : " + QByteArray::number(udp->src_port)
            + "\n    |-Destination Port    : " + QByteArray::number(udp->dst_port)
            + "\n    |-UDP Length          : " + QByteArray::number(udp->length)
            + "\n    |-UDP Checksum        : " + QByteArray::number(udp->crc, 16)
            + "\n";
    file.write(data.data());
//    delete ip;
//    __print;
//    ip =nullptr;
//    __print;
//    delete udp;
//    __print;
//    udp = nullptr;
}
