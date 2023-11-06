#include <iostream>
#include <conio.h>

#include "RawSocket.hpp"
#include "Timer.hpp"

#define ESC			27

int main(void)
{
	int currentCnt = 0;
	RawSocket rawSock("192.168.20.130", "192.168.20.70", 9000, 9000);
	TIMER timer(1);

	timer.StartTimer();

	while(1) {
		if(timer.Tick()) {
			rawSock.Attack();
			printf("[SYSTEM - TIME] : %d(s)\n", ++currentCnt);
		}

		if (_kbhit()) {
			if (_getch() == ESC) break;
		}
	}
	
	return 0;
}
