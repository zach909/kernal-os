/* Run the core on this machine, console on stdin/stdout. Password for the demo: open-sesame */
#include <stdio.h>
#include "apps.h"

int hal_getc(void) { return getchar(); }
void hal_putc(char c) { putchar(c); }
int hal_pw_check(const char *pw, uint8_t n) {
    static const char s[] = "open-sesame";
    uint8_t d = (uint8_t)(n ^ 11), i;
    for (i = 0; i < 11; i++) d |= (uint8_t)((i < n ? (uint8_t)pw[i] : 0) ^ (uint8_t)s[i]);
    return d == 0;
}
void hal_led(uint8_t on) { printf("[led %d]\n", on); }
int16_t hal_sense(void) { return 42; }

int main(void) {
    static const km_app apps[] = DEMO_APPS_INIT;
    km_init(apps, 4);
    km_serve();
    return 0;
}
