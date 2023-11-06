#ifndef _TIMER_H_
#define _TIMER_H_

#include <iostream>

#define INTERVAL 1000

typedef class TIMER
{
private:
	bool sw = false;
	int currentTime, lastTime, tickTime;
	
public:
	TIMER(const int tick) {
		currentTime = 0;
		lastTime = 0;
		tickTime = tick * INTERVAL;
	};

	void StartTimer() {
		sw = true;
	};

	bool Tick() {
		while (sw) {
			currentTime = clock();
			if (currentTime - lastTime >= tickTime) {
				lastTime = clock();
				return true;
			}
		}
		return false;
	}
}timer;

#endif