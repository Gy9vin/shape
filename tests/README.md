# Тесты

Запускаются без root и без реального ядра: `bpftool`, `systemctl` и `ip`
подменяются заглушками, состояние Shape уводится во временный каталог.
Ничего на машине не трогают.

```bash
cd tests
python3 audit_tests.py          # ядро Shape: конфиг, валидация, штрафы, сводка
bash    audit_shell_tests.sh    # shell: инъекции, права, синтаксис, юниты
python3 api_tests.py            # API: 208 проверок по HTTP
bash    api_independence_tests.sh   # Shape работает без API
gcc -O1 -Wno-unknown-pragmas -I stub -o /tmp/h bpf_harness.c && /tmp/h
```

`bpf_harness.c` собирает **настоящий** `bpf/shaper.bpf.c` обычным gcc с
подменёнными картами и прогоняет через него пакеты, которых на живой ноде не
дождёшься: фрагменты IPv4, цепочки заголовков расширения IPv6, обрезанные
кадры, ICMP, истёкшие штрафы.

Всё это же гоняет GitHub Actions на каждый push — там дополнительно
собирается eBPF настоящим clang и проверяется, что версия согласована в
`VERSION`, обоих README и `CHANGELOG.md`.

Корень проекта тесты находят сами; переопределяется переменной `SHAPE_SRC`.
