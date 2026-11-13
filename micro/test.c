#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#ifndef NO_STACKTEST
#include <ucontext.h>
#endif

static const char *in; static size_t ip, op; static char out[4096];
int hal_getc(void) { return in[ip] ? (unsigned char)in[ip++] : -1; }
void hal_putc(char c) { out[op++ & 4095] = c; }
int hal_pw_check(const char *pw, uint8_t n) {
    static const char s[] = "open-sesame";
    uint8_t d = (uint8_t)(n ^ 11), i;
    for (i = 0; i < 11; i++) d |= (uint8_t)((i < n ? (uint8_t)pw[i] : 0) ^ (uint8_t)s[i]);
    return d == 0;
}
static int leds; void hal_led(uint8_t on) { leds += 1 + on; }
int16_t hal_sense(void) { return 7; }

static const km_app apps[] = DEMO_APPS_INIT;
static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static void session(const char *script) {
    memset(out, 0, sizeof out); in = script; ip = op = 0; leds = 0;
    km_init(apps, 4);
    km_serve();
}
static int count(const char *needle) {
    int n = 0; const char *p = out;
    while ((p = strstr(p, needle))) { n++; p += strlen(needle); }
    return n;
}

#define PW "open-sesame\n"
static void test_authority(void) {
    session("run 0\nwrong\n");
    CHECK(count("denied") == 1 && count("1\n2\n") == 0);          /* no password, nothing runs */
    session("grant 0 0\n" PW "run 0\n" PW);
    CHECK(count("1\n2\n3\n4\n5\n") == 1 && count("ok") == 2);
    session("run 1\n" PW "audit\n");                               /* not permitted: killed and logged */
    CHECK(count("fault -14") == 1 && leds == 0 && count(" 1 1 0\n") == 1);
    session("run 2\n" PW);
    CHECK(count("fault -13") == 1);                                /* fuel */
    session("run 3\nrun 3\n");
    CHECK(count("refused -4") == 2 && count("pw:") == 0);          /* refused before any prompt */
    session("run 0\nx\nrun 0\nx\nrun 0\nx\nrun 0\n" PW "grant 0 0\n" PW);
    CHECK(count("pw:") == 3 && count("locked") == 2 && count("fault") == 0 && count("ok") == 0);
    session("grant 0 0\n" PW "revoke 0 0\n" PW "run 0\n" PW);
    CHECK(count("fault -14") == 1);                                /* revoke takes effect */
    session("grant 0 0\nopen-sesameaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
    CHECK(count("denied") == 1 && count("ok") == 0);               /* overlong password is a failure */
}

static void test_console_hostile(void) {
    char big[200];
    session("\x1b[2J\x07\n" "run 0\x00" "x\n");
    CHECK(count("?") >= 1 && count("pw:") == 0);
    memset(big, 'a', sizeof big - 2); big[sizeof big - 2] = '\n'; big[sizeof big - 1] = 0;
    session(big);
    CHECK(count("?") == 1 && count("pw:") == 0);
    session("run 9\ngrant 0 9\ngrant x y\nrevoke 0 3\nrun\nGRANT 0 0\n");
    CHECK(count("pw:") == 0 && count("?") == 6);
    session("ps\n");
    CHECK(count("0 count p=0") == 1 && count("3 evil p=0") == 1);
}

static void test_verify(void) {
    static const uint8_t trunc[] = { 1 }, badop[] = { 99, 0 }, far[] = { 11, 50 }, mem[] = { 9, 40, 0 },
        act[] = { 1, 0, 15, 9, 0 }, falloff[] = { 1, 1 };
    CHECK(km_verify(0, 3) == KV_SIZE && km_verify(trunc, 0) == KV_SIZE);
    CHECK(km_verify(trunc, 1) == KV_TRUNC && km_verify(badop, 2) == KV_OPCODE);
    CHECK(km_verify(far, 2) == KV_TARGET && km_verify(app_evil, sizeof app_evil) == KV_TARGET);
    CHECK(km_verify(mem, 3) == KV_MEM && km_verify(act, 5) == KV_ACTION && km_verify(falloff, 2) == KV_END);
    CHECK(km_verify(app_count, sizeof app_count) == 0 && km_verify(app_spin, 2) == 0);
}

static void test_vm(void) {
    static const uint8_t over[] = { 1, 1, 11, 0 }, under[] = { 2, 0 }, dz[] = { 1, 1, 1, 0, 5, 0 },
        arith[] = { 1, 100, 1, 100, 4, 1, 3, 5, 15, 0, 7, 0 };   /* 100*100 wraps in 16 bits, /3 */
    km_init(apps, 4);
    CHECK(km_exec(over, 4, 0, 0) == KE_STACK && km_exec(under, 2, 0, 0) == KE_UNDER);
    CHECK(km_exec(dz, 6, 0, 0) == KE_DIV);
    CHECK(km_exec(arith, sizeof arith, 1, 0) == 0);
    CHECK(km_exec(app_led, 5, 0, 0) == KE_DENIED && km_exec(app_led, 5, 5, 0) == KE_DENIED);
    CHECK(km_exec(app_led, 5, 2, 0) == 0);
}

/* random images: anything verify accepts must run without a memory error or a crash (see the sanitizer build) */
static void test_fuzz(void) {
    uint32_t x = 2463534242u; int i, j, ok = 0;
    for (i = 0; i < 40000; i++) {
        uint8_t img[48]; uint8_t n;
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        n = (uint8_t)(1 + x % 47);
        for (j = 0; j < n; j++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; img[j] = (uint8_t)x; }
        if (i & 1) {                      /* structured: real opcodes, operands in range, so verify often accepts */
            uint8_t k = 0;
            while (k + 1u < n) {
                uint8_t op = (uint8_t)(img[k] % 16), a = img[k + 1];
                if (op == 1 || op == 9 || op == 10 || op == 11 || op == 12 || op == 15) {
                    img[k] = op; img[k + 1] = op == 1 ? a : op == 15 ? (uint8_t)(a % 3) : op >= 11 ? (uint8_t)(a % n) : (uint8_t)(a % 32);
                    k += 2;
                } else { img[k] = op; k++; }
            }
            img[n - 1] = 0;
        }
        if (km_verify(img, n) == 0) {
            int r; ok++;
            r = km_exec(img, n, 7, 0);
            CHECK(r == 0 || (r <= KE_STACK && r >= KE_PC));
        }
    }
    CHECK(ok > 2000);
    printf("fuzz: %d random images, %d passed verify and ran\n", 40000, ok);
}

#ifndef NO_STACKTEST
static ucontext_t mainc, subc;
static char stk[16384];
static void scenario(void) {
    session("ps\ngrant 0 0\n" PW "grant 1 2\n" PW "run 0\n" PW "run 1\n" PW "run 2\n" PW "run 3\naudit\n");
}
static unsigned peak_stack(void) {
    size_t i = 0;
    memset(stk, 0xA5, sizeof stk);
    getcontext(&subc);
    subc.uc_stack.ss_sp = stk; subc.uc_stack.ss_size = sizeof stk; subc.uc_link = &mainc;
    makecontext(&subc, scenario, 0);
    swapcontext(&mainc, &subc);
    while (i < sizeof stk && (unsigned char)stk[i] == 0xA5) i++;
    return (unsigned)(sizeof stk - i);
}
static void test_ram(void) {
    unsigned st = peak_stack(), g = km_ram_bytes();
    printf("RAM: globals %u B + peak stack %u B = %u B of %u B budget\n", g, st, g + st, KM_RAM_BUDGET);
    CHECK(g + st <= KM_RAM_BUDGET);
    CHECK(st < sizeof stk - 64);                                   /* the probe was not exhausted */
}
#endif

int main(void) {
    test_authority(); test_console_hostile(); test_verify(); test_vm(); test_fuzz();
#ifndef NO_STACKTEST
    test_ram();
#endif
    printf("%d checks, %d failed\n", checks, fails);
    return fails != 0;
}
