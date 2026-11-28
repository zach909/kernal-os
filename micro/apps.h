/* Demo app images. Bytecode: see micro/README.md for the instruction set. Not an API: samples + test inputs. */
#ifndef APPS_H
#define APPS_H
#include "kmicro.h"

/* print 1..5 (needs PRINT) */
static const uint8_t app_count[] = {
    1, 1,  10, 0,  9, 0,  1, 6,  13,  12, 25,  9, 0,  15, 0,  7,  9, 0,  1, 1,  2,  10, 0,  11, 4,  0 };
/* asks for the LED without being permitted: must be killed and logged */
static const uint8_t app_led[]   = { 1, 1, 15, 1, 0 };
/* never stops: must be stopped by the fuel limit */
static const uint8_t app_spin[]  = { 11, 0 };
/* jumps into the middle of an instruction: must be refused at launch */
static const uint8_t app_evil[]  = { 1, 1, 11, 1, 0 };

#define DEMO_APPS_INIT { \
    { "count", app_count, sizeof app_count }, { "led", app_led, sizeof app_led }, \
    { "spin", app_spin, sizeof app_spin },   { "evil", app_evil, sizeof app_evil } }
#endif
