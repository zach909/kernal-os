#include "kmicro.h"

enum { OP_HALT, OP_PUSH, OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_DUP, OP_DROP, OP_SWAP,
       OP_LOAD, OP_STORE, OP_JMP, OP_JZ, OP_LT, OP_EQ, OP_REQ, OP_COUNT };
enum { ACT_RUN = 0x10, ACT_GRANT = 0x11, ACT_REVOKE = 0x12, ACT_REFUSED = 0x20, ACT_FAULT = 0x21 };

#define STK       16
#define AUDIT_N   32          /* power of two */
#define LINE_MAX  31
#define MAX_FAILS 3

struct audit { uint8_t who, act, ok, seq; };

static struct {
    int16_t mem[KM_MEM_WORDS];
    struct audit log[AUDIT_N];
    const km_app *apps;
    uint8_t napps, permit[KM_NAPPS_MAX];
    uint8_t line[LINE_MAX + 1];
    uint8_t head, nlog, seq, fails;
} S;

unsigned km_ram_bytes(void) { return (unsigned)sizeof S; }

void km_init(const km_app *apps, uint8_t n) {
    uint8_t *p = (uint8_t *)&S;
    unsigned i;
    for (i = 0; i < sizeof S; i++) p[i] = 0;
    S.apps = apps;
    S.napps = n > KM_NAPPS_MAX ? KM_NAPPS_MAX : n;
}

static void note(uint8_t who, uint8_t act, uint8_t ok) {
    struct audit *e = &S.log[S.head];
    e->who = who; e->act = act; e->ok = ok; e->seq = S.seq++;
    S.head = (uint8_t)((S.head + 1) & (AUDIT_N - 1));
    if (S.nlog < AUDIT_N) S.nlog++;
}

/* ---- output ---- */
static void ps(const char *s) { while (*s) hal_putc(*s++); }
static void pn(int16_t v) {
    char b[6]; uint8_t i = 6; uint16_t u = (uint16_t)v;
    if (v < 0) u = (uint16_t)(0u - u);
    do { b[--i] = (char)('0' + u % 10); u = (uint16_t)(u / 10); } while (u);
    if (v < 0) hal_putc('-');
    while (i < 6) hal_putc(b[i++]);
}

/* ---- verify: the static rules, run at every launch ---- */
static uint8_t argc_of(uint8_t op) {
    return op == OP_PUSH || op == OP_LOAD || op == OP_STORE || op == OP_JMP || op == OP_JZ || op == OP_REQ;
}

int km_verify(const uint8_t *c, uint8_t n) {
    uint8_t bm[32];
    uint16_t i;
    uint8_t last = OP_COUNT;
    if (!c || n == 0) return KV_SIZE;
    for (i = 0; i < 32; i++) bm[i] = 0;
    for (i = 0; i < n;) {                       /* pass 1: opcodes, operands present, boundaries */
        uint8_t op = c[i];
        if (op >= OP_COUNT) return KV_OPCODE;
        bm[i >> 3] |= (uint8_t)(1u << (i & 7));
        if (argc_of(op)) { if (i + 1u >= n) return KV_TRUNC; i += 2; } else i++;
    }
    for (i = 0; i < n;) {                       /* pass 2: operands mean something */
        uint8_t op = c[i], a = argc_of(op) ? c[i + 1] : 0;
        if ((op == OP_JMP || op == OP_JZ) && (a >= n || !(bm[a >> 3] & (1u << (a & 7))))) return KV_TARGET;
        if ((op == OP_LOAD || op == OP_STORE) && a >= KM_MEM_WORDS) return KV_MEM;
        if (op == OP_REQ && a >= KM_NACT) return KV_ACTION;
        last = op;
        i += argc_of(op) ? 2u : 1u;
    }
    return (last == OP_HALT || last == OP_JMP) ? KV_OK : KV_END;   /* cannot run off the end */
}

/* ---- the VM: 16-bit whole numbers only ---- */
#define POP(x) do { if (!sp) return KE_UNDER; x = st[--sp]; } while (0)

int km_exec(const uint8_t *c, uint8_t n, uint8_t permit, uint8_t who) {
    int16_t st[STK], a, b;
    uint8_t sp = 0, pc = 0, i;
    uint16_t fuel = KM_FUEL;
    int v = km_verify(c, n);                    /* nothing runs unproven */
    if (v) return v;
    for (i = 0; i < KM_MEM_WORDS; i++) S.mem[i] = 0;
    for (;;) {
        uint8_t op, arg = 0;
        if (pc >= n) return KE_PC;
        if (!fuel) return KE_FUEL;
        fuel--;
        op = c[pc++];
        if (argc_of(op)) { if (pc >= n) return KE_PC; arg = c[pc++]; }
        switch (op) {
        case OP_HALT: return 0;
        case OP_PUSH: if (sp >= STK) return KE_STACK; st[sp++] = (int16_t)(int8_t)arg; break;
        case OP_ADD: POP(b); POP(a); st[sp++] = (int16_t)((uint16_t)a + (uint16_t)b); break;
        case OP_SUB: POP(b); POP(a); st[sp++] = (int16_t)((uint16_t)a - (uint16_t)b); break;
        case OP_MUL: POP(b); POP(a);
            st[sp++] = (int16_t)(uint16_t)((uint32_t)(uint16_t)a * (uint16_t)b); break;
        case OP_DIV: POP(b); POP(a);
            if (b == 0 || (a == INT16_MIN && b == -1)) return KE_DIV;
            st[sp++] = (int16_t)(a / b); break;
        case OP_DUP: if (!sp) return KE_UNDER; if (sp >= STK) return KE_STACK; st[sp] = st[sp - 1]; sp++; break;
        case OP_DROP: POP(a); break;
        case OP_SWAP: POP(b); POP(a); st[sp++] = b; st[sp++] = a; break;
        case OP_LOAD: if (arg >= KM_MEM_WORDS) return KE_PC; if (sp >= STK) return KE_STACK;
            st[sp++] = S.mem[arg]; break;
        case OP_STORE: if (arg >= KM_MEM_WORDS) return KE_PC; POP(a); S.mem[arg] = a; break;
        case OP_JMP: pc = arg; break;
        case OP_JZ: POP(a); if (!a) pc = arg; break;
        case OP_LT: POP(b); POP(a); st[sp++] = (int16_t)(a < b); break;
        case OP_EQ: POP(b); POP(a); st[sp++] = (int16_t)(a == b); break;
        case OP_REQ:
            POP(a);
            if (arg >= KM_NACT || !((permit >> arg) & 1u)) { note(who, arg, 0); return KE_DENIED; }
            note(who, arg, 1);                  /* allowed and blocked are both logged */
            if (arg == RQ_PRINT) { pn(a); hal_putc('\n'); a = 0; }
            else if (arg == RQ_LED) { hal_led(a != 0); a = 0; }
            else a = hal_sense();
            st[sp++] = a;
            break;
        default: return KE_PC;
        }
    }
}

/* ---- the admin console: the only place a password is typed; apps never see it ---- */
static int readline(uint8_t secret) {           /* n >= 0 ok, -1 end of input, -2 hostile/overlong */
    uint8_t n = 0, bad = 0;
    for (;;) {
        int c = hal_getc();
        if (c < 0) return -1;
        if (c == '\n') break;
        if (c == '\r') continue;
        if (n >= LINE_MAX || (!secret && (c < 0x20 || c > 0x7e))) { bad = 1; continue; }
        S.line[n++] = (uint8_t)c;
    }
    S.line[n] = 0;
    return bad ? -2 : n;
}

static int authorize(uint8_t act, uint8_t target) {   /* rule 1: every action needs the password */
    int n, ok;
    uint8_t i;
    if (S.fails >= MAX_FAILS) { note(target, act, 0); ps("locked\n"); return 0; }
    ps("pw:");
    n = readline(1);
    ok = n >= 0 && hal_pw_check((const char *)S.line, (uint8_t)n);
    for (i = 0; i < sizeof S.line; i++) S.line[i] = 0;
    S.fails = ok ? 0 : (uint8_t)(S.fails + 1);
    note(target, act, (uint8_t)ok);
    if (!ok) ps("denied\n");
    return ok;
}

static int is(uint8_t n, const char *w) {
    uint8_t i = 0;
    while (w[i]) { if (i >= n || S.line[i] != (uint8_t)w[i]) return 0; i++; }
    return 1;
}
static int dig(uint8_t c) { return c >= '0' && c <= '9' ? c - '0' : -1; }

static void do_run(uint8_t app) {
    int r = km_verify(S.apps[app].code, S.apps[app].len);
    if (r) { note(app, ACT_REFUSED, 0); ps("refused "); pn((int16_t)r); hal_putc('\n'); return; }  /* before any prompt */
    if (!authorize(ACT_RUN, app)) return;
    r = km_exec(S.apps[app].code, S.apps[app].len, S.permit[app], app);
    if (r) { note(app, ACT_FAULT, 0); ps("fault "); pn((int16_t)r); hal_putc('\n'); }
    else ps("ok\n");
}

static void do_list(void) {
    uint8_t i;
    for (i = 0; i < S.napps; i++) {
        pn(i); hal_putc(' '); ps(S.apps[i].name); ps(" p="); pn(S.permit[i]); hal_putc('\n');
    }
}

static void do_audit(void) {
    uint8_t i, start = S.nlog < AUDIT_N ? 0 : S.head;
    for (i = 0; i < S.nlog; i++) {
        const struct audit *e = &S.log[(start + i) & (AUDIT_N - 1)];
        pn(e->seq); hal_putc(' '); pn(e->who); hal_putc(' '); pn(e->act); hal_putc(' '); pn(e->ok); hal_putc('\n');
    }
}

void km_serve(void) {
    for (;;) {
        int n, app, act;
        ps("> ");
        n = readline(0);
        if (n == -1) return;
        if (n < 0) { ps("?\n"); continue; }
        if (n == 2 && is(2, "ps")) do_list();
        else if (n == 5 && is(5, "audit")) do_audit();
        else if (n == 5 && is(5, "run ") && (app = dig(S.line[4])) >= 0 && app < S.napps) do_run((uint8_t)app);
        else if ((n == 9 && is(9, "grant ")) || (n == 10 && is(10, "revoke "))) {
            uint8_t g = n == 9, o = g ? 6 : 7;
            app = dig(S.line[o]); act = dig(S.line[o + 2]);
            if (app >= 0 && app < S.napps && act >= 0 && act < KM_NACT && S.line[o + 1] == ' ') {
                if (authorize(g ? ACT_GRANT : ACT_REVOKE, (uint8_t)app)) {
                    if (g) S.permit[app] |= (uint8_t)(1u << act);
                    else S.permit[app] &= (uint8_t)~(1u << act);
                    ps("ok\n");
                }
            } else ps("?\n");
        } else ps("?\n");
    }
}
