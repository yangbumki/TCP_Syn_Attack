#include <iostream>
#include <conio.h>

#include "RawSocket.hpp"

#define ESC			27

int main(void)
{
	RawSocket rawSock("192.168.100.56", "127.0.0.1", 8986, 52210);
	while(1) {
		rawSock.Attack();
		if (_kbhit()) {
			if (_getch() == ESC) break;
		}
	}
	
	return 0;
}
