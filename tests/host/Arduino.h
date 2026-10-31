#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
extern uint32_t mockMillis;
inline uint32_t millis() { return mockMillis; }
struct SerialMock {
  void println(const char*) {}
  template<typename... Args> void printf(const char*, Args...) {}
};
extern SerialMock Serial;
