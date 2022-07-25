#include "stdafx.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "winsock2.h"
#include "mstcpip.h"
int main()
{
WSADATA wsa;
WSAStartup(MAKEWORD(2, 2), &wsa);
SOCKET sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
if (sniffer == INVALID_SOCKET)
{
printf("Failed to create socket\n");
system("pause");
return 1;
}

SOCKADDR_IN addr;
addr.sin_family = AF_INET;
addr.sin_port = 0;
addr.sin_addr.s_addr = inet_addr("192.168.15.11");
bind(sniffer, (SOCKADDR *)&addr, sizeof(addr));
int opt = RCVALL_ON;
int bytesReturned = 0;
if (WSAIoctl(sniffer, SIO_RCVALL, &opt, sizeof(opt), 0, 0, 
(LPDWORD)&bytesReturned, 0, 0) == SOCKET_ERROR)
{
printf("WSAIoctl() failed.\n");
return 1;
}
char *buf = (char *)malloc(65536);
int res;
unsigned char ip_protocol;


while (1)
{
res = recvfrom(sniffer, buf, 65536, 0, 0, 0);
if (res <= 0) break;
// Kiem tra loai protocol
memcpy(&ip_protocol, buf + 9, 1);
if (ip_protocol == 1)
printf("ICMP\n");
else if (ip_protocol == 6)
printf("TCP\n");
else if (ip_protocol == 17)
printf("UDP\n");
}
free(buf);
closesocket(sniffer);
WSACleanup();
return 0;
}
