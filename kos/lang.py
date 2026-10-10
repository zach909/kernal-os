"""Every line is a command.

The KOS line shell (``kos line``, and what you get when you log in) does not
hand your input to a programming language. It reads a line of *human*
language, in any of the languages in the lexicon below, and turns it into
exactly one KOS command::

    run hello                 abre hello              启动 hello
    please scan notes.kapp    escanea notes.kapp      lance l'app hello

The result is always a structured ``argv`` for ``kos.cli.main`` - never a
string handed to a shell - so there is nothing to inject into: no pipes, no
``;``, no ``$(...)``, no redirects. The words are only ever *names for
existing commands*; every command still asks for the password exactly as it
does when typed as ``kos ...``.

Code is the one exception. A line that is written in a programming language
(Python, C, JavaScript, SQL, shell, HTML...) is not a command and is never
run by this layer; it is reported as code and ignored. Code belongs inside an
app (``kos pack`` / ``kos install``), where it runs sandboxed and can only
talk to the OS through the command protocol.

Resolution order for one line:

1. empty line                       -> ``empty``
2. looks like code                  -> ``code``   (never executed)
3. first meaningful word is a verb  -> ``command``/``help``/``exit``
4. anything else                    -> ``unknown`` (with a "did you mean")

Politeness words ("please", "por favor", "bitte"...) and articles are skipped.
Verbs are matched ignoring case and accents. Languages without spaces
(Chinese, Japanese) are matched by prefix.
"""

from __future__ import annotations

import difflib
import re
import unicodedata
from dataclasses import dataclass
from typing import NamedTuple

# --------------------------------------------------------------------------
# Lexicon: canonical verb -> language -> words.
# --------------------------------------------------------------------------

_LEXICON: dict[str, dict[str, str]] = {
    "run": {
        "en": "run start launch execute",
        "es": "ejecuta ejecutar corre correr lanza lanzar inicia iniciar",
        "fr": "lance lancer exécute exécuter démarre démarrer",
        "de": "starte starten führe ausführen",
        "pt": "execute executar rode rodar inicie",
        "it": "esegui eseguire avvia avviare",
        "ru": "запусти запустить выполни выполнить",
        "zh": "运行 運行 启动 啟動 执行 執行",
        "ja": "実行 起動",
    },
    "open": {
        "en": "open",
        "es": "abre abrir",
        "fr": "ouvre ouvrir",
        "de": "öffne öffnen",
        "pt": "abra abrir",
        "it": "apri aprire",
        "ru": "открой открыть",
        "zh": "打开 打開 开启 開啟",
        "ja": "開く",
    },
    "close": {
        "en": "close stop kill",
        "es": "cierra cerrar detén detener para parar",
        "fr": "ferme fermer arrête arrêter",
        "de": "schließe schliessen schließen beende beenden",
        "pt": "feche fechar pare",
        "it": "chiudi chiudere ferma fermare",
        "ru": "закрой закрыть останови остановить",
        "zh": "关闭 關閉 停止",
        "ja": "閉じる 停止",
    },
    "list": {
        "en": "list apps",
        "es": "lista listar aplicaciones",
        "fr": "liste lister applications",
        "de": "liste auflisten anwendungen",
        "pt": "liste listar aplicativos",
        "it": "elenca elenco applicazioni",
        "ru": "список приложения",
        "zh": "列表 应用 應用",
        "ja": "一覧 アプリ",
    },
    "ps": {
        "en": "ps running processes status",
        "es": "procesos abiertas estado",
        "fr": "processus ouverts état",
        "de": "prozesse laufend status",
        "pt": "processos abertos estado",
        "it": "processi aperti stato",
        "ru": "процессы статус",
        "zh": "进程 進程 状态 狀態",
        "ja": "プロセス 状態",
    },
    "install": {
        "en": "install add",
        "es": "instala instalar",
        "fr": "installe installer",
        "de": "installiere installieren",
        "pt": "instale instalar",
        "it": "installa installare",
        "ru": "установи установить",
        "zh": "安装 安裝",
        "ja": "インストール",
    },
    "update": {
        "en": "update upgrade",
        "es": "actualiza actualizar",
        "fr": "actualise actualiser",
        "de": "aktualisiere aktualisieren",
        "pt": "atualize atualizar",
        "it": "aggiorna aggiornare",
        "ru": "обнови обновить",
        "zh": "更新 升级 升級",
        "ja": "更新",
    },
    "remove": {
        "en": "remove delete uninstall",
        "es": "quita quitar elimina eliminar borra borrar desinstala",
        "fr": "supprime supprimer retire retirer désinstalle",
        "de": "entferne entfernen lösche löschen",
        "pt": "remova remover apague apagar",
        "it": "rimuovi rimuovere elimina eliminare",
        "ru": "удали удалить",
        "zh": "删除 刪除 移除 卸载 卸載",
        "ja": "削除 アンインストール",
    },
    "scan": {
        "en": "scan check",
        "es": "escanea escanear analiza analizar revisa revisar",
        "fr": "scanne scanner analyse analyser",
        "de": "scanne scannen prüfe prüfen",
        "pt": "escaneie escanear verifique verificar",
        "it": "scansiona scansionare controlla controllare",
        "ru": "проверь проверить сканируй сканировать",
        "zh": "扫描 掃描 检查 檢查",
        "ja": "スキャン",
    },
    "optimize": {
        "en": "optimize optimise clean cleanup compact",
        "es": "optimiza optimizar limpia limpiar",
        "fr": "optimise optimiser nettoie nettoyer",
        "de": "optimiere optimieren aufräumen",
        "pt": "otimize otimizar limpe limpar",
        "it": "ottimizza ottimizzare pulisci pulire",
        "ru": "оптимизируй оптимизировать",
        "zh": "优化 優化 清理",
        "ja": "最適化",
    },
    "write": {
        "en": "write save",
        "es": "escribe escribir guarda guardar",
        "fr": "écris écrire enregistre enregistrer sauvegarde",
        "de": "schreibe schreiben speichere speichern",
        "pt": "escreva escrever salve salvar",
        "it": "scrivi scrivere salva salvare",
        "ru": "запиши записать сохрани сохранить",
        "zh": "写入 寫入 保存 储存 儲存",
        "ja": "書く 保存",
    },
    "view": {
        "en": "view show read cat display",
        "es": "muestra mostrar ver lee leer",
        "fr": "montre montrer affiche afficher lis lire",
        "de": "zeige zeigen anzeigen lies lesen",
        "pt": "mostre mostrar veja ver leia ler",
        "it": "mostra mostrare leggi leggere vedi",
        "ru": "покажи показать прочитай прочитать",
        "zh": "查看 显示 顯示 读取 讀取",
        "ja": "表示 見る",
    },
    "browse": {
        "en": "ls dir browse files folder",
        "es": "explora explorar archivos carpeta",
        "fr": "parcours parcourir fichiers dossier",
        "de": "durchsuche durchsuchen dateien ordner",
        "pt": "navegue navegar arquivos pasta",
        "it": "sfoglia sfogliare cartella",
        "ru": "файлы папка",
        "zh": "浏览 瀏覽 文件 目录 目錄",
        "ja": "ファイル フォルダ",
    },
    "permit": {
        "en": "permit allow authorize authorise permission",
        "es": "permite permitir autoriza autorizar permiso",
        "fr": "permets permettre autorise autoriser",
        "de": "erlaube erlauben genehmige genehmigen",
        "pt": "permita permitir autorize autorizar",
        "it": "permetti permettere autorizza autorizzare",
        "ru": "разреши разрешить",
        "zh": "允许 允許 授权 授權",
        "ja": "許可",
    },
    "revoke": {
        "en": "revoke deny",
        "es": "revoca revocar deniega denegar",
        "fr": "révoque révoquer refuse refuser",
        "de": "widerrufe widerrufen verweigere verweigern",
        "pt": "revogue revogar negue negar",
        "it": "revoca revocare nega negare",
        "ru": "отзови отозвать запрети",
        "zh": "撤销 撤銷 禁止",
        "ja": "取り消す",
    },
    "desktop": {
        "en": "desktop taskbar home",
        "es": "escritorio",
        "fr": "bureau",
        "de": "desktop schreibtisch arbeitsfläche",
        "pt": "desktop",
        "it": "scrivania",
        "ru": "рабочий",
        "zh": "桌面",
        "ja": "デスクトップ",
    },
    "audit": {
        "en": "audit log history",
        "es": "auditoría auditoria historial",
        "fr": "journal historique",
        "de": "protokoll verlauf",
        "pt": "auditoria histórico",
        "it": "registro cronologia",
        "ru": "журнал",
        "zh": "日志 日誌 审计 審計",
        "ja": "ログ 監査",
    },
    "activity": {
        "en": "activity feed",
        "es": "actividad",
        "fr": "activité",
        "de": "aktivität",
        "pt": "atividade",
        "it": "attività",
        "ru": "активность",
        "zh": "活动 活動",
        "ja": "アクティビティ",
    },
    "doctor": {
        "en": "doctor diagnose health",
        "es": "diagnostica diagnóstico",
        "fr": "diagnostique diagnostic",
        "de": "diagnose",
        "pt": "diagnóstico",
        "it": "diagnostica",
        "ru": "диагностика",
        "zh": "诊断 診斷",
        "ja": "診断",
    },
    "attach": {
        "en": "attach switch focus",
        "es": "conecta conectar enfoca enfocar",
        "fr": "attache attacher",
        "de": "verbinde verbinden anhängen",
        "pt": "anexe anexar",
        "it": "collega collegare allega",
        "ru": "подключись подключить",
        "zh": "连接 連接 附加 切换 切換",
        "ja": "接続",
    },
    "admin": {
        "en": "admin administrator elevate elevated",
        "es": "administrador eleva elevar",
        "fr": "administrateur élève élever",
        "de": "administrator erhöhe erhöhen",
        "pt": "administrador eleve elevar",
        "it": "amministratore eleva elevare",
        "ru": "администратор",
        "zh": "管理员 管理員",
        "ja": "管理者",
    },
    "help": {
        "en": "help ?",
        "es": "ayuda",
        "fr": "aide",
        "de": "hilfe",
        "pt": "ajuda",
        "it": "aiuto",
        "ru": "помощь",
        "zh": "帮助 幫助",
        "ja": "ヘルプ",
    },
    "exit": {
        "en": "exit quit bye logout lock",
        "es": "salir adiós adios",
        "fr": "quitter sortir",
        "de": "verlassen tschüss",
        "pt": "sair",
        "it": "esci uscire",
        "ru": "выход выйти",
        "zh": "退出",
        "ja": "終了",
    },
}

# Words that modify run/open instead of naming a command.
_MODE_WORDS: dict[str, str] = {
    "graphical": "graphical", "graphic": "graphical", "gui": "graphical",
    "gráfico": "graphical", "grafico": "graphical", "graphique": "graphical",
    "grafisch": "graphical", "графический": "graphical", "图形": "graphical",
    "圖形": "graphical", "グラフィカル": "graphical",
    "cmd": "cmd", "raw": "cmd",
}

# Skipped before the verb and between arguments.
_POLITE = ("please pls kindly now can you could "
           "por favor puedes puede ahora "
           "s'il vous plaît plait svp maintenant peux pouvez "
           "bitte jetzt kannst könnten "
           "favor pode agora "
           "per favore puoi ora "
           "пожалуйста "
           "请 請 麻烦 麻煩 "
           "お願い").split()
_ARTICLES = ("the a an my "
             "el la los las un una mi "
             "le les une mon ma "
             "der die das den dem ein eine meine "
             "o os as um uma "
             "il lo gli uno").split()
# Nouns that mean "the app" - dropped only when another word follows them,
# so an app literally named "app" still works as the last word.
_NOUNS = ("app application program file aplicación aplicacion programa archivo fichier "
          "applicazione anwendung datei arquivo").split()


def _norm(s: str) -> str:
    """Lowercase and strip accents so 'Ejecútar' == 'ejecutar'."""
    s = unicodedata.normalize("NFKD", s.casefold())
    return "".join(c for c in s if not unicodedata.combining(c))


def _build_index() -> tuple[dict[str, tuple[str, str]], dict[str, tuple[str, str]]]:
    words: dict[str, tuple[str, str]] = {}
    for verb, langs in _LEXICON.items():
        for lang, text in langs.items():
            for w in text.split():
                words.setdefault(_norm(w), (verb, lang))
    cjk = {w: v for w, v in words.items() if any(ord(c) > 0x2E80 for c in w)}
    return words, cjk


_WORDS, _CJK_WORDS = _build_index()
_FILLERS = {_norm(w) for w in (*_POLITE, *_ARTICLES)}
_NOUN_SET = {_norm(w) for w in _NOUNS}
_MODES = {_norm(k): v for k, v in _MODE_WORDS.items()}


# --------------------------------------------------------------------------
# Code detection: a line written in a programming language is not a command.
# --------------------------------------------------------------------------

_STRONG_CODE: list[tuple[str, re.Pattern]] = [(name, re.compile(p, re.I if ci else 0)) for name, p, ci in [
    ("script", r"^\s*#!", False),
    ("html/xml", r"^\s*<[!?/]?[a-z][^>]*>", True),
    ("php", r"<\?php", True),
    ("python", r"^\s*(?:async\s+)?def\s+\w+\s*\(|^\s*class\s+\w+.*:\s*$", False),
    ("python", r"^\s*(?:from\s+[\w.]+\s+)?import\s+[\w.*, ]+(?:\s+as\s+\w+)?\s*$", False),
    ("python", r"^\s*(?:if|elif|while|for|with|try|except|else|finally)\b.*:\s*$", False),
    ("python", r"^\s*(?:lambda\b|@\w+)", False),
    ("c", r"^\s*#\s*(?:include|define|ifdef|ifndef|pragma)\b", False),
    ("c", r"^\s*(?:int|void|char|float|double|long|unsigned|static|struct|typedef)\s+\**\w+.*[;{(]\s*$", False),
    ("javascript", r"^\s*(?:const|let|var)\s+\w+\s*=", False),
    ("javascript", r"^\s*(?:async\s+)?function\b.*[({]", False),
    ("javascript", r"=>|\bconsole\.\w+\(|\brequire\(", False),
    ("java", r"^\s*(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\]]+\s+\w+", False),
    ("rust/go", r"^\s*(?:fn|func|impl|pub\s+fn|use\s+\w+::)\b", False),
    ("sql", r"^\s*select\b.+\bfrom\b|^\s*insert\s+into\b|^\s*update\s+\w+\s+set\b|"
            r"^\s*delete\s+from\b|^\s*(?:drop|create|alter)\s+(?:table|database|index)\b", True),
    # a call written as code: name(...), possibly dotted, possibly ending in ;
    ("code call", r"^\s*[A-Za-z_][\w.]*\(.*\)\s*;?\s*$", False),
    # an assignment: x = 1, x+=1, a[0] = 2, a.b = 3
    ("assignment", r"^\s*[A-Za-z_][\w.]*(?:\[[^\]]*\])?\s*(?:[-+*/%|&^]|<<|>>|\*\*|//)?=(?!=)", False),
    ("comment", r"^\s*(?://|/\*|\*/|--\s|#(?!\w))", False),
    # shell glue: pipes, chaining, substitution, redirection, variables, backticks
    ("shell", r"\|\||&&|\$\(|`|(?<![\w-])>>?\s*\S|\|\s*\S|;\s*\S|\$\{?\w", False),
    ("braces", r"[{}]\s*;?\s*$|^\s*[{}]", False),
]]


def detect_code(line: str) -> str | None:
    """Name the programming language a line looks like, or None for human text."""
    for name, pat in _STRONG_CODE:
        if pat.search(line):
            return name
    return None


# --------------------------------------------------------------------------
# Interpretation
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Line:
    kind: str                 # command | code | empty | unknown | help | exit
    argv: tuple[str, ...] = ()
    verb: str = ""            # canonical verb for command/help/exit
    language: str = ""        # language of the verb, or the code language
    word: str = ""            # the word the person actually typed
    hint: str = ""            # "did you mean" for unknown lines

    def explain(self) -> str:
        if self.kind == "command":
            return f"[{self.language}] {self.word} -> kos {' '.join(self.argv)}"
        if self.kind == "code":
            return f"[{self.language}] code - not a command"
        return self.kind


_TOKEN_RE = re.compile(r"""(?:^|(?<=\s))(?:"([^"]*)"|'([^']*)')(?=\s|$)|\S+""")


class Tok(NamedTuple):
    text: str
    quoted: bool = False


def _tokens(line: str) -> list[Tok]:
    out = []
    for m in _TOKEN_RE.finditer(line):
        if m.group(1) is not None:
            out.append(Tok(m.group(1), True))
        elif m.group(2) is not None:
            out.append(Tok(m.group(2), True))
        else:
            out.append(Tok(m.group(0)))
    return out


# Verbs whose argument is an app name or instance id: those are lowercase-only,
# so "Run Hello" means "run hello". File paths are never touched.
_TAKES_APP_NAME = {"run", "open", "close", "permit", "revoke", "remove", "attach"}
_APP_WORD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
_ELISION_RE = re.compile(r"^(?:l|d|un|dell|nell|all)['’](.+)$", re.I)


def _clean(tok: str) -> str:
    """Sentence punctuation is not part of a word: 'hello.' / '¿ayuda?' / 'run!'."""
    tok = tok.lstrip("¿¡").rstrip("!?,;。、！？")
    if len(tok) > 1 and tok.endswith(".") and not tok.endswith(("..", "/.")):
        tok = tok[:-1]
    return tok


def _is_filler(tok: Tok) -> bool:
    return not tok.quoted and _norm(_clean(tok.text)) in _FILLERS


def _split_verb(tokens: list[Tok]) -> tuple[str, str, str, list[Tok]] | None:
    """Find (canonical verb, language, typed word, remaining tokens)."""
    i = 0
    # skip a few politeness/article words in front ("por favor", "can you", ...)
    while i < len(tokens) and i < 4 and _is_filler(tokens[i]):
        i += 1
    if i >= len(tokens) or tokens[i].quoted:
        return None
    first = _clean(tokens[i].text) or tokens[i].text
    hit = _WORDS.get(_norm(first))
    if hit:
        return hit[0], hit[1], first, tokens[i + 1:]
    # CJK has no spaces: "运行hello" -> verb "运行" + "hello"
    nf = _norm(first)
    for word in sorted(_CJK_WORDS, key=len, reverse=True):
        if nf.startswith(word):
            verb, lang = _CJK_WORDS[word]
            rest = [Tok(first[len(word):])] if len(first) > len(word) else []
            return verb, lang, first[:len(word)], rest + tokens[i + 1:]
    return None


def _arguments(tokens: list[Tok]) -> list[str]:
    """Drop articles/politeness and 'the app' nouns and sentence punctuation;
    keep quoted text exactly as typed."""
    out: list[str] = []
    n = len(tokens)
    for idx, tok in enumerate(tokens):
        if tok.quoted:
            out.append(tok.text)
            continue
        text = tok.text
        m = _ELISION_RE.match(text)
        if m:                                   # l'app hello -> app hello
            text = m.group(1)
        c = _clean(text)
        if not c or _norm(c) in _FILLERS:
            continue
        if _norm(c) in _NOUN_SET and idx < n - 1:
            continue
        out.append(c)
    return out


def interpret(line: str) -> Line:
    """Turn one line of input into exactly one KOS command (or explain why not)."""
    text = line.strip()
    if not text:
        return Line("empty")
    lang = detect_code(text)
    if lang:
        return Line("code", language=lang)
    tokens = _tokens(text)
    found = _split_verb(tokens)
    if found is None:
        guess = _closest(_clean(tokens[0].text) if tokens else text)
        return Line("unknown", hint=guess)
    verb, language, word, rest = found
    if verb == "write":
        return Line("command", argv=tuple(_write_argv(rest)), verb=verb,
                    language=language, word=word)
    args = _arguments(rest)
    if verb in ("help", "exit"):
        return Line(verb, verb=verb, language=language, word=word)
    if verb in _TAKES_APP_NAME:
        args = [a.lower() if _APP_WORD_RE.match(a) else a for a in args]
    if verb in ("run", "open"):
        mode = []
        if args and _norm(args[0]) in _MODES:
            mode = [_MODES[_norm(args.pop(0))]]
        argv = [verb, *mode, *args]
    elif verb == "list":
        argv = ["list"]
    elif verb == "ps":
        argv = ["ps"]
    elif verb == "browse":
        argv = ["explore", *args] if not args else ["ls", *args]
    elif verb == "view":
        argv = ["view", *args]
    elif verb == "scan":
        argv = ["scan", "file", *args]
    elif verb == "revoke":
        argv = ["permit", "--revoke", *args]
    elif verb == "desktop":
        argv = ["boot", "desktop"]
    else:
        argv = [verb, *args]
    return Line("command", argv=tuple(argv), verb=verb, language=language, word=word)


def _write_argv(rest: list[Tok]) -> list[str]:
    """``write PATH some text``: the path is the first real word; everything
    after it is the file's text and is passed through exactly as typed."""
    i = 0
    while i < len(rest) and (rest[i].quoted is False) and (
            _norm(_clean(rest[i].text)) in _FILLERS or _norm(_clean(rest[i].text)) in _NOUN_SET):
        i += 1
    if i >= len(rest):
        return ["write"]
    path = rest[i].text if rest[i].quoted else _clean(rest[i].text)
    body = " ".join(t.text for t in rest[i + 1:])
    return ["write", path, "--text", body] if len(rest) > i + 1 else ["write", path]


def _closest(word: str) -> str:
    matches = difflib.get_close_matches(_norm(word), list(_WORDS), n=1, cutoff=0.7)
    return matches[0] if matches else ""


HELP = """\
Every line you type is a command. Say what you want, in your own language:

  run hello            start an app            (also: abre / lance / starte / 运行 ...)
  run graphical hello  start it graphically
  open hello           start it in the background
  list                 installed apps          ps   what's open
  scan FILE            security-scan a file
  write FILE TEXT      write a file (needs the admin keyboard; scanned + disk optimized)
  optimize             reclaim disk space
  desktop              the taskbar (right mouse = App Library)
  permit hello         let an app run at all   revoke hello   take that away
  admin                the elevated administrator keyboard
  help / exit

Lines written in a programming language are not commands and are never run
here - put code inside an app (kos pack, kos install) where it runs sandboxed.
"""


def run_shell(execute, read, say, prompt: str = "kos> ", explain: bool = False) -> int:
    """The line shell loop. ``execute(argv) -> int`` runs one command;
    ``read(prompt)`` returns the next line (raise EOFError to stop);
    ``say(text)`` prints. Every line is a command - or it is refused, loudly."""
    last = 0
    while True:
        try:
            raw = read(prompt)
        except EOFError:
            say("")
            return last
        result = interpret(raw)
        if result.kind == "empty":
            continue
        if result.kind == "exit":
            return last
        if result.kind == "help":
            say(HELP)
            continue
        if result.kind == "code":
            say(f"That looks like code ({result.language}), not a command, so I won't run it. "
                "Put code in an app (kos pack / kos install).")
            last = 64
            continue
        if result.kind == "unknown":
            tip = f" Did you mean '{result.hint}'?" if result.hint else ""
            say(f"I don't know that command.{tip} Type 'help'.")
            last = 65
            continue
        if explain:
            say(result.explain())
        last = execute(list(result.argv))
