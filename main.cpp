#include <iostream>
#include <conio.h>

#include "RawSocket.hpp"
#include "Timer.hpp"

#define ESC			27

int main(void)
{
	int currentCnt = 0;
	RawSocket rawSock("127.0.0.1", "127.0.0.1", IPPROTO_ICMP);
	TIMER timer(1);

	timer.StartTimer();

	while(1) {
		if(timer.Tick()) {
			printf("[SYSTEM - TIME] : %d(s)\n", ++currentCnt);
			rawSock.ICMP_Attack();
		}

		if (_kbhit()) {
			if (_getch() == ESC) break;
		}
	}
	
	return 0;
}
