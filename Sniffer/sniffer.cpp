#include "sniffer.h"


namespace
{
    const uint max_buf_len = 64 * 1024;

    enum fileTypes
    {
        eUDP = 1,
        eTCP = 2,
        eICMP = 3
    };

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
    receive = true;
    mUDP = true;
    mTCP = true;
    mICMP = true;

    fileTCP.setFileName("logTCP.txt");
    fileTCP.open(QIODevice::WriteOnly);
    fileTCP.flush();

    fileUDP.setFileName("logUDP.txt");
    fileUDP.open(QIODevice::WriteOnly);
    fileUDP.flush();

    fileICMP.setFileName("logICMP.txt");
    fileICMP.open(QIODevice::WriteOnly);
    fileICMP.flush();
}

Sniffer::~Sniffer()
{
    __print;
    delete buffer;
    delete adrPC;
    delete informHost;
    fileTCP.close();
    fileUDP.close();
    fileICMP.close();
    file.close();
}

bool Sniffer::initialization()
{
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
    if(gethostname(name, sizeof(name)))
    {
        __print<<"GETHOSTNAME";
        closesocket(sock);
        WSACleanup();
        return false;
    }

    informHost = gethostbyname(name);
    adrPC->sin_family = AF_INET;
    adrPC->sin_addr.S_un.S_addr = ((struct in_addr *)
                                   informHost->h_addr_list[0])->S_un.S_addr;
    return true;
}

bool Sniffer::bindSocket()
{
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
    if (!(initialization() && createSocket() && determIP_PC()
          && bindSocket() && promiscuousModeON()))
        return false;
    else
    {
        while(receive)
        {
            memset(buffer, 0, max_buf_len);

            uint count = recv(sock, buffer, max_buf_len,0);
            if (count >= sizeof(ip_header))
            {
                ip_header *ip = (ip_header *)buffer;
                if (count >=sizeof(ip_header))
                {
                    if ((ip->proto == IPPROTO_TCP)
                            && mTCP)
                    {
//                        __print << "TCP";
                        parseTCP();
                    }
                    else if ((ip->proto == IPPROTO_UDP)
                            && mUDP)
                    {
//                        __print << "UDP";
//                        parseUDP();
                    }
                    else if ((ip->proto == IPPROTO_ICMP)
                            && mICMP)
                    {
                        __print << "ICMP-------------------------------------------";
                        parseICMP();
                    }
                    else
                        __print << "GOVNO" << ip->proto;
                }
            }
        }
    }
    return true;
}

void Sniffer::parseIP(int fileId)
{
    ip_header *ip = (ip_header *)buffer;
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->src_addr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->dst_addr;
    QByteArray data;
    data ="\n"
            + QByteArray(QTime::currentTime().toString("hh:mm:ss")
                         .toStdString().c_str())
            + " IP Header \n |-IP Version          : " + QByteArray::number(0xF & ip->ver_ihl)
            + "\n |-Type Of Service     : " + QByteArray::number(ip->tos)
            + "\n |-IP Header Length    : " + QByteArray::number(0xF0 & ip->ver_ihl)
            + "\n |-IP Total Length     : " + QByteArray::number(ip->tlen)
            + "\n |-Identification      : " + QByteArray::number(ip->id)
            + "\n |-TTL                 : " + QByteArray::number(ip->ttl)
            + "\n |-Protocol            : " + QByteArray::number(ip->proto)
            + "\n |-Checksum            : " + QByteArray::number(ip->crc, 16)
            + "\n |-Source IP           : " + QByteArray(inet_ntoa(source.sin_addr))
            + "\n |-Destination IP      : " + QByteArray(inet_ntoa(dest.sin_addr));
    switch(fileId)
    {
    case eUDP:
        fileUDP.write(data.data());
        break;
    case eTCP:
        fileTCP.write(data.data());
        break;
    case eICMP:
        fileICMP.write(data.data());
        break;
    }
}

void Sniffer::parseICMP()
{

    parseIP(eICMP);
    unsigned short iplen;
    ip_header * ip = (struct ip_header * )buffer;
    iplen = (0xF0 & ip->ver_ihl) * 4;
    icmp_header * icmp = (icmp_header *)(buffer + iplen);

    QByteArray data;
    data = "\n\n          ICMP Header \n    |-Type        : " + QByteArray::number(icmp->type)
            + "\n    |-Code        : " + QByteArray::number(icmp->code)
            + "\n    |-Checksum        : " + QByteArray::number(icmp->crc,16)
            + "\n";
    fileICMP.write(data.data());

    QByteArray MSG = QByteArray(buffer + iplen + sizeof(icmp_header));
    if (!MSG.isEmpty())
    {
        MSG = MSG + "\n";

        fileICMP.write(MSG.data());
    }
    else
        fileICMP.write("        EMPTY \n");
}

void Sniffer::parseTCP()
{

    parseIP(eTCP);
    unsigned short iplen;
    ip_header * ip = (struct ip_header * )buffer;
    iplen = (0xF0 & ip->ver_ihl) * 4;
    tcp_header * tcp = (tcp_header *)(buffer + iplen);

    QByteArray data;
    data = "\n\n          TCP Header \n    |-Source Port         : " + QByteArray::number(tcp->src_port)
            + "\n    |-Destination Port    : " + QByteArray::number(tcp->dst_port)
            + "\n    |-Sequence Number     : " + QByteArray::number(tcp->seq_n)
            + "\n    |-Acknowledge Number  : " + QByteArray::number(tcp->ack_n)
            + "\n    |-Window              : " + QByteArray::number(tcp->win)
            + "\n    |-Checksum            : " + QByteArray::number(tcp->crc,16)
            + "\n";
    fileTCP.write(data.data());

    QByteArray MSG = QByteArray(buffer + iplen + sizeof(tcp));
    if (!MSG.isEmpty())
    {
        MSG = MSG + "\n";

        fileTCP.write(MSG.data());
    }
    else
        fileTCP.write("        EMPTY \n");
}

void Sniffer::parseUDP()
{

    parseIP(eUDP);

    unsigned short iplen, tlen;
    ip_header * ip = (struct ip_header * )buffer;
    iplen = (0xF0 & ip->ver_ihl) * 4;
    tlen = ip->tlen;
    udp_header *udp = (udp_header *)(buffer + iplen);

    QByteArray data;
    data = "\n\n          UDP Header \n    |-Source Port         : " + QByteArray::number(udp->src_port)
            + "\n    |-Destination Port    : " + QByteArray::number(udp->dst_port)
            + "\n    |-UDP Length          : " + QByteArray::number(udp->length)
            + "\n    |-UDP Checksum        : " + QByteArray::number(udp->crc,16)
            + "\n";
    fileUDP.write(data.data());

    if (udp->length != 0)
    {
        QByteArray  MSG = QByteArray((buffer + iplen + tlen));
        MSG = MSG + "\n";
        fileUDP.write(MSG.data());
    }
    else
        fileUDP.write("            EMPTY \n");
}

void Sniffer::stopReceive()
{
    receive = false;
}

void Sniffer::checkUDP(int flag)
{
    mUDP = (bool)flag;
}

void Sniffer::checkTCP(int flag)
{
    mTCP = (bool)flag;
}

void Sniffer::checkICMP(int flag)
{
    mICMP = (bool)flag;
}
