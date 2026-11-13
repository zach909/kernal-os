/* KOS-micro: the KOS rules in a core that fits a 7 KiB RAM budget.
 *
 * No libc, no malloc, no recursion, no floats. All RAM is one static struct (km_ram_bytes()) plus
 * a short stack. Apps are bytecode checked before every launch. See micro/README.md. */
#ifndef KMICRO_H
#define KMICRO_H
#include <stdint.h>

#define KM_RAM_BUDGET 7168u   /* the whole core: globals + peak stack */
#define KM_NAPPS_MAX  4
#define KM_MEM_WORDS  32      /* an app's scratch: 32 x int16, zeroed at every launch */
#define KM_FUEL       4096u   /* instructions per run, then the app is stopped */
#define KM_NACT       3       /* request actions an app can ask for */

enum { RQ_PRINT = 0, RQ_LED = 1, RQ_SENSE = 2 };

/* verify results (0 = ok) */
enum { KV_OK = 0, KV_SIZE = -1, KV_OPCODE = -2, KV_TRUNC = -3, KV_TARGET = -4,
       KV_MEM = -5, KV_ACTION = -6, KV_END = -7 };
/* run results (0 = ran to HALT); verify errors are returned as they are */
enum { KE_STACK = -10, KE_UNDER = -11, KE_DIV = -12, KE_FUEL = -13, KE_DENIED = -14, KE_PC = -15 };

typedef struct { const char *name; const uint8_t *code; uint8_t len; } km_app;

/* The board provides these. The core never touches hardware itself. */
int     hal_getc(void);                              /* admin console byte, -1 = end */
void    hal_putc(char c);                            /* admin console out */
int     hal_pw_check(const char *pw, uint8_t n);     /* constant time; the board owns the secret */
void    hal_led(uint8_t on);
int16_t hal_sense(void);

void     km_init(const km_app *apps, uint8_t n);
void     km_serve(void);                             /* admin console loop until hal_getc() < 0 */
int      km_verify(const uint8_t *code, uint8_t len);
int      km_exec(const uint8_t *code, uint8_t len, uint8_t permit, uint8_t who);
unsigned km_ram_bytes(void);
#endif
