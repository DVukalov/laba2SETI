#include "sniffer.h"

namespace
{
    const uint max_buf_len = 0x1000000;
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

}

Sniffer::Sniffer(QObject* parent)
    : QObject(parent)
{
    adrPC = new SOCKADDR_IN;
    informHost = new HOSTENT;
    buffer = new char(max_buf_len);

}

Sniffer::~Sniffer()
{
    delete buffer;
    delete adrPC;
    delete informHost;

}

bool Sniffer::initialization()
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData))
    {
//        __print <<"WSA_INIT";
        return false;
    }
    return true;
}

bool Sniffer::createSocket()
{
   sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (INVALID_SOCKET == sock)
    {
//        __print<<"SOCKET";
        WSACleanup();
        return false;
    }
    return true;
}

bool Sniffer::determIP_PC()
{
    if(gethostname(name, sizeof(name)))
    {
//        __print<<"GETHOSTNAME";
        closesocket(sock);
        WSACleanup();
        return false;
    }

    informHost = gethostbyname(name);
    ZeroMemory(&adrPC, sizeof(adrPC));
    adrPC->sin_family = AF_INET;
    adrPC->sin_addr.S_un.S_addr = ((struct in_addr *)
                                   informHost->h_addr_list[0])->S_un.S_addr;
    return true;
}

bool Sniffer::bindSocket()
{
    if (bind (sock, (SOCKADDR *)&adrPC, sizeof(SOCKADDR)))
    {
//        __print<<"BIND";
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
//        __print<<"ioctlsocket";
        closesocket(sock);
        WSACleanup();
        return false;
    }
    return true;

}
bool Sniffer::startSniffer()
{

    if (!(initialization() && createSocket()
            && determIP_PC() && bindSocket() && promiscuousModeON()))
        return false;
    else
    {
        while(!kbhit())
        {
            memset(buffer, 0, max_buf_len);

            uint count = recv(sock, buffer, max_buf_len,0);
            if (count >= sizeof(ip_header))
            {

            }
        }

    }
}
