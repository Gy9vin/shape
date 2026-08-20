#!/usr/bin/env python3
"""
shaperctl — управление eBPF-шейпером через pinned BPF-карты.

Одна настройка: порты и скорость в Мбит/с на каждый IP-адрес.
Только стандартная библиотека и bpftool.
"""

import argparse
import contextlib
import fcntl
import hashlib
import html
import http.client
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

PIN_DIR     = os.environ.get("SHAPER_PIN_DIR", "/sys/fs/bpf/shaper/maps")
ETC_DIR     = os.environ.get("SHAPE_ETC_DIR", "/etc/shaper")
CONFIG_FILE = os.path.join(ETC_DIR, "config.json")
WL_FILE     = os.path.join(ETC_DIR, "whitelist.txt")
PEN_FILE    = os.path.join(ETC_DIR, "penalties.json")
DAILY_FILE  = os.path.join(ETC_DIR, "daily.json")
DIGEST_FILE = os.path.join(ETC_DIR, "digest.json")
# Изменчивое состояние — отдельно от настроек: журнал событий пухнет,
# а /etc принято держать маленьким и бэкапить целиком.
# Каталог изменчивого состояния. Переопределяется переменной окружения —
# это нужно тестам, чтобы гонять настоящий CLI, не трогая систему.
VAR_DIR     = os.environ.get("SHAPE_VAR_DIR", "/var/lib/shape")
EVENT_FILE  = os.path.join(VAR_DIR, "events.jsonl")
EVENT_SEQ   = os.path.join(VAR_DIR, "events.seq")
# Кто стоит за адресом. Заполняется извне — сейчас руками или через API,
# позже сюда будет складывать карту резолвер панели. Shape сам никуда за
# этими данными не ходит: его дело — подставить ярлык в сообщение.
OWNERS_FILE = os.path.join(VAR_DIR, "owners.json")
# По строке JSON на прошедшие сутки. За год ~40 КБ.
# Постоянный идентификатор ноды. Имя хоста и адрес для этого не годятся:
# их меняют, а после смены метрики выглядят как метрики новой ноды и история
# рвётся. Файл создаётся один раз — при установке или при первом обращении.
NODE_ID_FILE = os.path.join(VAR_DIR, "node_id")

HISTORY_FILE = os.path.join(VAR_DIR, "history.jsonl")
HISTORY_MAX_DAYS = 400
# Три числа для расчёта текущей скорости канала: когда мерили и сколько
# было всего. Файл общий для CLI и API — кто бы ни собирал метрики,
# разница считается от последнего замера.
METRICS_STATE = os.path.join(VAR_DIR, "metrics.state")
METRICS_MIN_GAP = 10        # чаще этого замер не обновляем
METRICS_MAX_GAP = 300       # старше этого — считать скорость бессмысленно

# Версия схемы метрик. Меняется, если поменяются имена или смысл значений;
# по ней центральная система поймёт, что дашборд пора обновить.
METRICS_VERSION = "1"

NS = 1_000_000_000
# Мбит/с -> байт/с. Мегабит десятичный: 1 Мбит = 1 000 000 бит = 125 000 байт.
BYTES_PER_MBPS = 125_000
MAX_MBPS = 100_000          # 100 Гбит/с — заведомо выше любого разумного канала
MAX_PORTS = 64              # должно совпадать с max_entries port_map в shaper.bpf.c

CONFIG_FMT = "<Q"           # struct config, 8 байт
PEN_FMT = "<2Q"             # struct penalty: rate_bytes_per_sec, until_ns
USER_FMT, USER_SIZE = "<4Q", 32   # struct user_state

C = {
    "r": "\033[0m", "b": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "grn": "\033[32m", "yel": "\033[33m", "gry": "\033[90m",
    # Яркие оттенки для монитора: на тёмной теме обычный красный сливается
    # с фоном, а на светлой жёлтый становится нечитаемым.
    "cyan": "\033[36m", "bred": "\033[91m", "bgrn": "\033[92m",
    "byel": "\033[93m",
}


# ─────────────────────────── языки ───────────────────────────
# Язык берётся из UI_LANG в /etc/shaper/shaper.conf, его пишет меню.

MSG = {
    "ru": {
        "root": "нужны права root",
        "h_req_packet": "требовать крупные пакеты вверх: on/off",
        "guard_req_packet": "и только при пакетах вверх от {n} байт — подтверждения не в счёт",
        "mon_pkt": "пакет",
        "mon_leg_pkt": "пакет — средний размер в отдаче, байт; от {n} это данные, а не подтверждения",
        "id_node": "нода",
        "id_config": "отпечаток",
        "id_none": "не создан",
        "h_tg_backup": "включить или выключить отправку копии: on/off",
        "h_tg_bk_thread": "тема для копий, если отдельная от отчётов",
        "h_tg_bk_day": "день недели для копии: 1 понедельник … 7 воскресенье",
        "tg_backup": "копия",
        "tg_bk_state": "Копия",
        "tg_bk_when": "по {day}, в {at}",
        "tg_bk_thread": "тема копий",
        "bk_tg_caption": "Резервная копия состояния",
        "bk_tg_counts": "адресов в белом списке {w}, ограничений {p}, владельцев {o}",
        "bk_tg_nosec": "без токена бота — восстанавливать через shaperctl.py import",
        "bk_tg_secrets": "отправка отменена: в копию попал секрет, а в Telegram такое не уходит",
        "bk_tg_sent": "копия отправлена в Telegram",
        "bk_tg_off": "отправка копий выключена",
        "bk_tg_send_now": "Отправить копию в Telegram сейчас",
        "bk_tg_toggle": "Отправка копии в Telegram",
        "bk_tg_hint1": "Копия уходит файлом раз в неделю, в то же время, что и сводка.",
        "bk_tg_hint2": "Токен бота в неё не попадает никогда: бот пишет в эту же тему,",
        "bk_tg_hint3": "и любой её участник получил бы управление ботом.",
        "bk_tg_hint4": "В файле есть IP-адреса клиентов — тему держите закрытой.",
        "dow1": "понедельникам", "dow2": "вторникам", "dow3": "средам",
        "dow4": "четвергам", "dow5": "пятницам", "dow6": "субботам",
        "dow7": "воскресеньям",
        "tg_bad_day": "день недели: от 1 (понедельник) до 7 (воскресенье)",
        "h_export": "выгрузить состояние ноды в файл",
        "h_import": "восстановить состояние ноды из файла",
        "h_exp_out": "куда писать; по умолчанию на экран",
        "h_exp_secrets": "включить токен бота и пароль прокси",
        "h_imp_dry": "показать, что изменится, и ничего не менять",
        "h_imp_only": "только эти разделы через запятую",
        "h_imp_replace": "заменить белый список, а не дополнить",
        "exp_done": "состояние выгружено: {path}",
        "exp_counts": "белый список {w}, ограничения {p}, владельцы {o}, суток истории {h}",
        "exp_secrets": "в файле лежит токен бота — храните его как пароль",
        "exp_no_secrets": "токен и прокси не включены, добавьте --with-secrets при переносе ноды",
        "sec_config": "настройки",
        "sec_whitelist": "белый список",
        "sec_penalties": "ограничения",
        "sec_owners": "владельцы адресов",
        "sec_history": "история по суткам",
        "imp_not_object": "файл не похож на выгрузку Shape",
        "imp_not_shape": "это не выгрузка Shape: нет метки shape-node-state",
        "imp_no_schema": "в файле не указана версия формата",
        "imp_newer": "файл из более новой версии Shape (формат {got}, здесь {ours}) — обновите Shape",
        "imp_no_state": "в файле нет раздела state",
        "imp_no_file": "файл не открывается: {path} {err}",
        "imp_bad_json": "файл не читается как JSON: {err}",
        "imp_bad_only": "нет такого раздела: {s}; есть: {all}",
        "imp_bad_speed": "скорость отброшена: {v}",
        "imp_bad_port": "порт отброшен: {v}",
        "imp_many_ports": "портов больше {n}, лишние отброшены",
        "imp_bad_ports": "список портов испорчен и отброшен",
        "imp_bad_section": "раздел {s} испорчен и отброшен",
        "imp_bad_field": "{s}.{k} — неподходящее значение, отброшено",
        "imp_unknown_keys": "{s}: незнакомые ключи отброшены: {k}",
        "imp_bad_ip": "адрес отброшен: {v}",
        "imp_bad_entry": "запись для {v} отброшена",
        "imp_from": "выгрузка с ноды {node}, Shape {v}, от {when}",
        "imp_no_secrets": "токена в файле нет — тот, что настроен здесь, останется на месте",
        "imp_yes": "будет применено",
        "imp_skip": "пропущено",
        "imp_more_problems": "и ещё {n} замечаний",
        "imp_dry": "ничего не изменено: это была проверка",
        "imp_done": "восстановлено: {s}",
        "imp_live": "движок загружен — изменения уже в ядре",
        "imp_offline": "движок не загружен — настройки применятся при следующем запуске",
        "tg_mtproto": "это MTProto-прокси из ссылки t.me/proxy",
        "tg_mtproto2": "он умеет только протокол мессенджера, Bot API через него не пройдёт",
        "tg_mtproto3": "нужен SOCKS5 или HTTP: socks5://логин:пароль@хост:1080",
        "tg_proxy_scheme": "прокси должен начинаться с socks5:// или http://",
        "h_telegram": "уведомления в Telegram",
        "h_tg_name": "как подписывать ноду в сообщениях",
        "h_tg_proxy": "socks5://… или http://… — нужен на российских нодах",
        "tg_state": "Уведомления", "tg_node": "Подпись ноды",
        "tg_chat": "Чат", "tg_thread": "тема", "tg_proxy": "Прокси",
        "tg_direct": "напрямую",
        "tg_off": "уведомления выключены",
        "tg_no_creds": "не заданы токен или chat_id",
        "tg_bad_token": "токен неверный — проверь у @BotFather",
        "tg_bad_chat": "неверный chat_id, либо бота не добавили в группу",
        "tg_bad_thread": "нет такой темы — проверь ID темы",
        "tg_forbidden": "бота заблокировали или выгнали из чата",
        "tg_need_proxy": "похоже на блокировку — задай прокси",
        "tg_sent": "сообщение отправлено",
        "tg_test_text": "Проверка связи прошла успешно.",
        "tg_limited": "Ограничен",
        "tg_shared": "за адресом может стоять несколько человек",
        "bad_ip": "«{ip}» — это не IP-адрес",
        "tg_bad_token_fmt": "токен выглядит как 123456789:AAF… — возьми его у @BotFather",
        "tg_bad_chat_fmt": "chat_id — это число (часто со знаком минус) или @имя",
        "tg_bad_thread_fmt": "ID темы — число из ссылки на тему",
        "tg_bad_proxy": "в адресе прокси нет хоста или порт вне диапазона",
        "tg_name_long": "подпись ноды — до 64 символов",
        "tg_at": "Время сводки",
        "tg_digest_now": "сводка за текущие сутки",
        "tg_no_data": "за сегодня ещё нечего показать",
        "tg_bad_time": "время указывают как ЧЧ:ММ, например 09:00",
        "h_tg_at": "во сколько присылать сводку, ЧЧ:ММ",
        "tg_digest": "сводка за", "tg_traffic": "Трафик",
        "tg_addresses": "Адресов", "tg_top": "Больше всех скачали",
        "lim_why": "за что",
        "lim_when": "с",
        "lim_total": "всего адресов",
        "lim_speed": "скорость нарушителя",
        "h_score": "баллов для штрафа (1-6)",
        "h_both_min": "минут одновременной нагрузки в обе стороны",
        "h_both_dl": "порог скачивания для двусторонней нагрузки, в процентах",
        "h_both_ul": "порог отдачи для двусторонней нагрузки, в процентах",
        "h_hours": "часов активности за сутки",
        "h_upload_gb": "гигабайт отдачи за сутки",
        "h_download_gb": "гигабайт скачивания за сутки, 0 = выкл",
        "h_download_gbh": "гигабайт скачивания за час, 0 = выкл",
        "why_hourly": "выкачал гигабайты за час",
        "h_watch_iv": "период опроса карт, сек (больше = легче процессору)",
        "why_download": "выкачал десятки гигабайт за сутки",
        "h_packet": "средний размер пакета в отдаче, байт",
        "guard_both": "Обе стороны сразу",
        "guard_score": "Баллов для штрафа",
        "why_packet": "отдаёт данные, а не подтверждения",
        "why_peak": "держит потолок скачивания",
        "why_hours": "часами не отпускает канал",
        "why_upload": "много отдал за сутки",
        "h_guard": "автоограничение нарушителей",
        "h_percent": "порог в процентах от лимита",
        "h_sustain": "сколько минут держать нагрузку до штрафа",
        "h_pen_mbps": "скорость нарушителя, Мбит/с",
        "h_pen_min": "на сколько минут ограничивать",
        "h_watch": "демон слежения (запускается сервисом)",
        "h_limited": "кто сейчас ограничен",
        "h_release": "снять ограничение с IP",
        "guard_state": "Автоограничение",
        "guard_on": "включено", "guard_off": "выключено",
        "guard_trigger": "Порог", "guard_of_limit": "от лимита",
        "guard_during": "непрерывно", "guard_penalty": "Штраф",
        "guard_for": "на", "guard_range": "{k}: допустимо от {lo} до {hi}",
        "lim_title": "Ограниченные адреса",
        "lim_none": "ограниченных нет",
        "lim_left": "осталось",
        "rel_one": "ограничение с {ip} снято",
        "rel_all": "снято ограничений: {n}",
        "rel_need_ip": "укажи IP или --all",
        "restored_pen": "восстановлено штрафов: {n}",
        "watch_start": "сторож запущен",
        "watch_hit": "{ip} ограничен до {mbps:g} Мбит/с на {m} мин",
        "units": ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"],
        "sec": "с", "min": "мин", "hour": "ч",
        "measuring": "замер скорости {i} с…",
        "desc": "eBPF-шейпер: лимит скорости по IP-адресу. Всё в Мбит/с.",
        "h_apply": "задать порты и скорость",
        "h_ports": "через запятую, 0 = все порты",
        "h_speed": "Мбит/с на IP-адрес, 0 = снять ограничение",
        "h_show": "показать текущие настройки",
        "h_restore": "залить настройки в карты",
        "h_monitor": "кто грузит канал прямо сейчас",
        "h_interval": "период обновления, сек",
        "h_status": "статистика по IP",
        "h_live": "замерить текущую скорость",
        "h_full": "показать все IP",
        "h_json": "вывод в JSON",
        "h_whitelist": "белый список IP",
        "h_event": "записать событие в журнал",
        "h_personal": "постоянная скорость для адреса",
        "h_pers_speed": "Мбит/с, выше или ниже общего лимита",
        "h_owners": "кто стоит за адресом",
        "h_history": "трафик по суткам",
        "h_metrics": "метрики в формате Prometheus",
        "h_met_out": "записать в файл для node_exporter (*.prom)",
        "met_need_prom": "имя файла должно оканчиваться на .prom — так его ищет node_exporter",
        "met_written": "метрики записаны: {p} ({n} строк)",
        "pers_none": "персональных скоростей нет",
        "pers_set": "{ip}: персональная скорость {s:g} Мбит/с",
        "pers_removed": "{ip}: персональная скорость снята",
        "pers_absent": "у {ip} нет персональной скорости",
        "pers_need_speed": "укажи скорость: --speed 25",
        "pers_range": "скорость от {lo} до {hi} Мбит/с",
        "own_none": "владельцы адресов не заданы",
        "own_set": "{ip}: сведения сохранены",
        "own_removed": "{ip}: сведения удалены",
        "own_bad_tg": "telegram_id — это число",
        "hist_none": "история пока пуста, первая запись появится в полночь",
        "hist_day": "Дата", "hist_limited": "ограничений",
        "hist_total": "всего за {n} сут",
        "no_engine": "движок не запущен — карты не найдены в {d}\n  запусти: systemctl start shaper",
        "cmd_fail": "команда не выполнилась: {c}\n  {e}",
        "port_nan": "порт «{p}» не число",
        "port_range": "порт {p} вне диапазона 0..65535",
        "too_many_ports": "портов не больше {n}",
        "no_ports": "не указан ни один порт (0 = все порты)",
        "neg_speed": "скорость не может быть отрицательной",
        "too_fast": "{v} Мбит/с — это больше 100 Гбит/с, проверь значение",
        "speed": "Скорость", "ports": "Порты", "all_ports": "ВСЕ ПОРТЫ",
        "per_user": "на каждый IP-адрес, в обе стороны",
        "unlimited": "не ограничена",
        "restored": "лимит {s:g} Мбит/с на портах {p}",
        "limit": "Лимит", "no_limit": "не ограничено",
        "total_ips": "всего IP", "active_min": "активных за минуту",
        "no_traffic": "трафика через шейпер ещё не было",
        "downloaded": "скачал", "uploaded": "отдал", "now": "сейчас",
        "more_ips": "… ещё {n} IP, полный список: shaperctl status --full",
        "idle_note": "· — нет трафика больше 5 минут",
        "wl_added": "{ip} добавлен в белый список",
        "wl_removed": "{ip} убран из белого списка",
        "wl_loaded": "загружено в белый список: {n}",
        "wl_bad": "пропущен неверный адрес: {ip}",
        "wl_empty": "белый список пуст",
        "mon_title": "Монитор", "mon_hint": "обновление {i} с · Ctrl+C — выход",
        "mon_channel": "Канал сейчас", "mon_limit": "Лимит {s:g} Мбит/с на IP",
        "mon_nolimit": "Лимит не задан", "mon_loading": "нагружают канал",
        "mon_of": "из", "mon_idle": "сейчас никто не качает",
        "mon_up": "отдача", "mon_avg": "средн", "mon_hold": "держит",
        "mon_bar": "загрузка", "mon_more": "… ещё {n} активных",
        "mon_share": "доля лимита",
        "mon_minute": "за минуту",
        "mon_limit_row": "Лимит на адрес",
        "mon_per_ip": "на каждый IP",
        "mon_shown": "показано {a} из {b}",
        "mon_leg_hold": "держит больше 30 с",
        "mon_leg_wl": "белый список",
        "mon_leg_limited": "ограничен",
        "mon_legend": "жёлтым — держит нагрузку больше 30 с, красным — упёрся в лимит",
    },
    "en": {
        "root": "root privileges required",
        "h_req_packet": "require large upload packets: on/off",
        "guard_req_packet": "and only with upload packets from {n} bytes — acknowledgements do not count",
        "mon_pkt": "packet",
        "mon_leg_pkt": "packet — average upload size in bytes; from {n} it is data, not acknowledgements",
        "id_node": "node",
        "id_config": "fingerprint",
        "id_none": "not created",
        "h_tg_backup": "turn the backup upload on or off: on/off",
        "h_tg_bk_thread": "topic for backups, if separate from reports",
        "h_tg_bk_day": "weekday for the backup: 1 Monday … 7 Sunday",
        "tg_backup": "backup",
        "tg_bk_state": "Backup",
        "tg_bk_when": "on {day}, at {at}",
        "tg_bk_thread": "backup topic",
        "bk_tg_caption": "Node state backup",
        "bk_tg_counts": "whitelisted {w}, limits {p}, owners {o}",
        "bk_tg_nosec": "no bot token inside — restore with shaperctl.py import",
        "bk_tg_secrets": "upload cancelled: a secret ended up in the copy, and those do not go to Telegram",
        "bk_tg_sent": "backup sent to Telegram",
        "bk_tg_off": "backup upload is off",
        "bk_tg_send_now": "Send a backup to Telegram now",
        "bk_tg_toggle": "Backup upload to Telegram",
        "bk_tg_hint1": "The copy is uploaded as a file once a week, at the digest time.",
        "bk_tg_hint2": "The bot token never goes into it: the bot posts to that same topic,",
        "bk_tg_hint3": "so anyone in it would gain control of the bot.",
        "bk_tg_hint4": "The file holds client IP addresses — keep the topic private.",
        "dow1": "Mondays", "dow2": "Tuesdays", "dow3": "Wednesdays",
        "dow4": "Thursdays", "dow5": "Fridays", "dow6": "Saturdays",
        "dow7": "Sundays",
        "tg_bad_day": "weekday: from 1 (Monday) to 7 (Sunday)",
        "h_export": "export node state to a file",
        "h_import": "restore node state from a file",
        "h_exp_out": "where to write; prints to screen by default",
        "h_exp_secrets": "include the bot token and proxy password",
        "h_imp_dry": "show what would change and change nothing",
        "h_imp_only": "these sections only, comma separated",
        "h_imp_replace": "replace the whitelist instead of merging",
        "exp_done": "state exported: {path}",
        "exp_counts": "whitelist {w}, limits {p}, owners {o}, days of history {h}",
        "exp_secrets": "the file holds the bot token — keep it like a password",
        "exp_no_secrets": "token and proxy left out; add --with-secrets when moving a node",
        "sec_config": "settings",
        "sec_whitelist": "whitelist",
        "sec_penalties": "limits",
        "sec_owners": "address owners",
        "sec_history": "daily history",
        "imp_not_object": "this file does not look like a Shape export",
        "imp_not_shape": "not a Shape export: the shape-node-state marker is missing",
        "imp_no_schema": "the file carries no format version",
        "imp_newer": "file comes from a newer Shape (format {got}, this one reads {ours}) — update Shape",
        "imp_no_state": "the file has no state section",
        "imp_no_file": "cannot open the file: {path} {err}",
        "imp_bad_json": "the file is not valid JSON: {err}",
        "imp_bad_only": "no such section: {s}; available: {all}",
        "imp_bad_speed": "speed dropped: {v}",
        "imp_bad_port": "port dropped: {v}",
        "imp_many_ports": "more than {n} ports, the extra ones were dropped",
        "imp_bad_ports": "the port list is malformed and was dropped",
        "imp_bad_section": "section {s} is malformed and was dropped",
        "imp_bad_field": "{s}.{k} holds an unusable value and was dropped",
        "imp_unknown_keys": "{s}: unknown keys dropped: {k}",
        "imp_bad_ip": "address dropped: {v}",
        "imp_bad_entry": "the entry for {v} was dropped",
        "imp_from": "export from node {node}, Shape {v}, made {when}",
        "imp_no_secrets": "no token in the file — the one configured here stays",
        "imp_yes": "will be applied",
        "imp_skip": "skipped",
        "imp_more_problems": "and {n} more notes",
        "imp_dry": "nothing changed: this was a check",
        "imp_done": "restored: {s}",
        "imp_live": "engine is loaded — changes are already in the kernel",
        "imp_offline": "engine is not loaded — settings apply on the next start",
        "tg_mtproto": "this is an MTProto proxy from a t.me/proxy link",
        "tg_mtproto2": "it only speaks the messenger protocol, the Bot API will not pass",
        "tg_mtproto3": "you need SOCKS5 or HTTP: socks5://user:pass@host:1080",
        "tg_proxy_scheme": "proxy must start with socks5:// or http://",
        "h_telegram": "Telegram notifications",
        "h_tg_name": "how to label this node in messages",
        "h_tg_proxy": "socks5://… or http://… — needed on Russian nodes",
        "tg_state": "Notifications", "tg_node": "Node label",
        "tg_chat": "Chat", "tg_thread": "topic", "tg_proxy": "Proxy",
        "tg_direct": "direct",
        "tg_off": "notifications are disabled",
        "tg_no_creds": "token or chat_id is missing",
        "tg_bad_token": "invalid token — check with @BotFather",
        "tg_bad_chat": "wrong chat_id, or the bot is not in the group",
        "tg_bad_thread": "no such topic — check the thread ID",
        "tg_forbidden": "the bot was blocked or removed from the chat",
        "tg_need_proxy": "looks like blocking — set a proxy",
        "tg_sent": "message sent",
        "tg_test_text": "Connection test passed.",
        "tg_limited": "Limited",
        "tg_shared": "this address may be shared by several people",
        "bad_ip": "«{ip}» is not an IP address",
        "tg_bad_token_fmt": "a token looks like 123456789:AAF… — get it from @BotFather",
        "tg_bad_chat_fmt": "chat_id is a number (often negative) or @name",
        "tg_bad_thread_fmt": "topic ID is the number from the topic link",
        "tg_bad_proxy": "the proxy address has no host, or the port is out of range",
        "tg_name_long": "node label is limited to 64 characters",
        "tg_at": "Digest time",
        "tg_digest_now": "digest for the current day",
        "tg_no_data": "nothing to report for today yet",
        "tg_bad_time": "time is written as HH:MM, for example 09:00",
        "h_tg_at": "when to send the digest, HH:MM",
        "tg_digest": "digest for", "tg_traffic": "Traffic",
        "tg_addresses": "Addresses", "tg_top": "Top downloaders",
        "lim_why": "why",
        "lim_when": "since",
        "lim_total": "addresses total",
        "lim_speed": "offender speed",
        "h_score": "score needed for a penalty (1-6)",
        "h_both_min": "minutes of simultaneous two-way load",
        "h_both_dl": "download floor for two-way load, percent",
        "h_both_ul": "upload floor for two-way load, percent",
        "h_hours": "hours of activity per day",
        "h_upload_gb": "gigabytes uploaded per day",
        "h_download_gb": "gigabytes downloaded per day, 0 = off",
        "h_download_gbh": "gigabytes downloaded per hour, 0 = off",
        "why_hourly": "downloaded gigabytes within an hour",
        "h_watch_iv": "map polling period, sec (higher = lighter on CPU)",
        "why_download": "downloaded tens of gigabytes in 24h",
        "h_packet": "average upload packet size, bytes",
        "guard_both": "Both ways at once",
        "guard_score": "Score needed",
        "why_packet": "sends real data, not just ACKs",
        "why_peak": "holds the download ceiling",
        "why_upload": "uploaded a lot in 24h",
        "why_hours": "keeps the channel busy for hours",
        "h_guard": "automatic limiting of heavy users",
        "h_percent": "threshold as a percent of the limit",
        "h_sustain": "minutes of sustained load before the penalty",
        "h_pen_mbps": "offender speed, Mbit/s",
        "h_pen_min": "penalty duration, minutes",
        "h_watch": "watchdog daemon (started by the service)",
        "h_limited": "who is currently limited",
        "h_release": "release an IP",
        "guard_state": "Auto-limit",
        "guard_on": "enabled", "guard_off": "disabled",
        "guard_trigger": "Threshold", "guard_of_limit": "of the limit",
        "guard_during": "sustained for", "guard_penalty": "Penalty",
        "guard_for": "for", "guard_range": "{k}: allowed from {lo} to {hi}",
        "lim_title": "Limited addresses",
        "lim_none": "nobody is limited",
        "lim_left": "left",
        "rel_one": "{ip} released",
        "rel_all": "released: {n}",
        "rel_need_ip": "specify an IP or --all",
        "restored_pen": "penalties restored: {n}",
        "watch_start": "watchdog started",
        "watch_hit": "{ip} limited to {mbps:g} Mbit/s for {m} min",
        "units": ["B", "KB", "MB", "GB", "TB", "PB"],
        "sec": "s", "min": "min", "hour": "h",
        "measuring": "measuring speed for {i} s…",
        "desc": "eBPF shaper: per-IP speed limit. Everything in Mbit/s.",
        "h_apply": "set ports and speed",
        "h_ports": "comma separated, 0 = all ports",
        "h_speed": "Mbit/s per IP address, 0 = remove the limit",
        "h_show": "show current settings",
        "h_restore": "push settings into the maps",
        "h_monitor": "who is loading the channel right now",
        "h_interval": "refresh period, seconds",
        "h_status": "per-IP statistics",
        "h_live": "measure current speed",
        "h_full": "show all IPs",
        "h_json": "JSON output",
        "h_whitelist": "IP whitelist",
        "h_event": "write a line into the event log",
        "h_personal": "permanent speed for an address",
        "h_pers_speed": "Mbit/s, above or below the shared limit",
        "h_owners": "who is behind an address",
        "h_history": "traffic per day",
        "h_metrics": "metrics in Prometheus format",
        "h_met_out": "write to a file for node_exporter (*.prom)",
        "met_need_prom": "the file name must end with .prom — that is what node_exporter looks for",
        "met_written": "metrics written: {p} ({n} lines)",
        "pers_none": "no personal speeds set",
        "pers_set": "{ip}: personal speed {s:g} Mbit/s",
        "pers_removed": "{ip}: personal speed removed",
        "pers_absent": "{ip} has no personal speed",
        "pers_need_speed": "give a speed: --speed 25",
        "pers_range": "speed from {lo} to {hi} Mbit/s",
        "own_none": "no address owners known",
        "own_set": "{ip}: details saved",
        "own_removed": "{ip}: details removed",
        "own_bad_tg": "telegram_id must be a number",
        "hist_none": "history is empty, the first row appears at midnight",
        "hist_day": "Date", "hist_limited": "limits",
        "hist_total": "total over {n} days",
        "no_engine": "engine is not running — no maps in {d}\n  start it: systemctl start shaper",
        "cmd_fail": "command failed: {c}\n  {e}",
        "port_nan": "port \u00ab{p}\u00bb is not a number",
        "port_range": "port {p} is out of range 0..65535",
        "too_many_ports": "no more than {n} ports",
        "no_ports": "no ports given (0 = all ports)",
        "neg_speed": "speed cannot be negative",
        "too_fast": "{v} Mbit/s is over 100 Gbit/s, check the value",
        "speed": "Speed", "ports": "Ports", "all_ports": "ALL PORTS",
        "per_user": "per IP address, both directions",
        "unlimited": "unlimited",
        "restored": "limit {s:g} Mbit/s on ports {p}",
        "limit": "Limit", "no_limit": "unlimited",
        "total_ips": "total IPs", "active_min": "active in the last minute",
        "no_traffic": "no traffic through the shaper yet",
        "downloaded": "down", "uploaded": "up", "now": "now",
        "more_ips": "… {n} more IPs, full list: shaperctl status --full",
        "idle_note": "· — no traffic for over 5 minutes",
        "wl_added": "{ip} added to the whitelist",
        "wl_removed": "{ip} removed from the whitelist",
        "wl_loaded": "loaded into the whitelist: {n}",
        "wl_bad": "skipped invalid address: {ip}",
        "wl_empty": "whitelist is empty",
        "mon_title": "Monitor", "mon_hint": "refresh every {i} s · Ctrl+C to exit",
        "mon_channel": "Channel now", "mon_limit": "Limit {s:g} Mbit/s per IP",
        "mon_nolimit": "No limit set", "mon_loading": "loading the channel",
        "mon_of": "of", "mon_idle": "nobody is downloading right now",
        "mon_up": "upload", "mon_avg": "avg", "mon_hold": "holding",
        "mon_bar": "load", "mon_more": "… {n} more active",
        "mon_share": "share of limit",
        "mon_minute": "last minute",
        "mon_limit_row": "Limit per address",
        "mon_per_ip": "for every IP",
        "mon_shown": "showing {a} of {b}",
        "mon_leg_hold": "holding over 30 s",
        "mon_leg_wl": "whitelisted",
        "mon_leg_limited": "limited",
        "mon_legend": "yellow — holding load over 30 s, red — hitting the limit",
    },
}


def _detect_lang():
    try:
        for line in open(os.path.join(ETC_DIR, "shaper.conf")):
            if line.strip().startswith("UI_LANG"):
                v = line.split("=", 1)[1].strip().strip('"').strip("'")
                if v in MSG:
                    return v
    except Exception:
        pass
    return "ru"


LANG = _detect_lang()


def t(key, **kw):
    s = MSG.get(LANG, MSG["ru"]).get(key, key)
    return s.format(**kw) if kw else s


# ────────────────────────────── утилиты ──────────────────────────────

def die(msg, code=1):
    print(f"{C['red']}✗ {msg}{C['r']}", file=sys.stderr)
    sys.exit(code)


def run(cmd, check=True):
    """
    Запуск внешней команды списком аргументов, без оболочки.

    shell=True здесь был бы миной: аргументы собираются из имён карт и
    hex-строк, и достаточно одного невнимательного вызова, чтобы значение
    из конфига попало в /bin/sh с правами root. Без оболочки такой класс
    ошибок невозможен в принципе.
    """
    p = subprocess.run(cmd, shell=False, capture_output=True, text=True)
    if check and p.returncode != 0:
        die(t("cmd_fail", c=" ".join(cmd), e=p.stderr.strip()))
    return p.stdout.strip(), p.returncode


def hexs(data):
    """Байты -> отдельные аргументы 'de ad be ef' для bpftool."""
    return [f"{b:02x}" for b in data]


def map_path(name):
    return os.path.join(PIN_DIR, name)


def require_engine():
    if not os.path.exists(map_path("config_map")):
        die(t("no_engine", d=PIN_DIR))


def map_update(name, key, value):
    require_engine()
    run(["bpftool", "map", "update", "pinned", map_path(name),
         "key", "hex", *hexs(key), "value", "hex", *hexs(value)])


def map_delete(name, key):
    run(["bpftool", "map", "delete", "pinned", map_path(name),
         "key", "hex", *hexs(key)], check=False)


def map_dump(name):
    """
    Пары (key, value) как их отдал bpftool. Формат зависит от наличия BTF:
    с BTF — словари с именами полей, без BTF — списки байтов. Разборщики
    ниже понимают оба варианта.
    """
    path = map_path(name)
    if not os.path.exists(path):
        return []
    out, rc = run(["bpftool", "map", "dump", "pinned", path, "-j"], check=False)
    if rc != 0 or not out:
        return []
    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        return []
    return [(e["key"], e.get("value")) for e in raw
            if isinstance(e, dict) and "key" in e]


def _int(x):
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        return int(x, 16) if x.startswith("0x") else int(x)
    return 0


def _raw(x):
    """Список байтов -> bytes. Для структурного вида возвращает None."""
    if isinstance(x, list) and (not x or not isinstance(x[0], (dict, list))):
        try:
            return bytes(_int(v) & 0xFF for v in x)
        except (ValueError, TypeError):
            return None
    return None


def parse_u32(x):
    b = _raw(x)
    if b is not None and len(b) >= 4:
        return struct.unpack("<I", b[:4])[0]
    if isinstance(x, dict):
        return _int(next(iter(x.values()), 0))
    return _int(x)


def parse_ip_key(k):
    """struct ip_key -> (адрес строкой, 16 байт ключа)."""
    b = _raw(k)
    if b is not None and len(b) >= 16:
        words = struct.unpack("<4I", b[:16])
    elif isinstance(k, dict):
        words = tuple((list(map(_int, k.get("addr", []))) + [0, 0, 0, 0])[:4])
    else:
        return None, None
    kb = struct.pack("<4I", *words)
    if words[1] == 0 and words[2] == 0 and words[3] == 0:
        return str(ipaddress.IPv4Address(kb[:4])), kb
    return str(ipaddress.IPv6Address(kb)), kb


def parse_user_state(v):
    b = _raw(v)
    if b is not None and len(b) >= USER_SIZE:
        _dep, total, seen, pkts = struct.unpack(USER_FMT, b[:USER_SIZE])
        return {"total": total, "seen": seen, "pkts": pkts}
    if isinstance(v, dict):
        return {"total": _int(v.get("total_bytes", 0)),
                "seen":  _int(v.get("last_seen_ns", 0)),
                "pkts":  _int(v.get("packets", 0))}
    return {"total": 0, "seen": 0, "pkts": 0}


def fmt_bytes(n):
    n = float(n)
    units = t("units")
    for u in units[:-1]:
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} {units[-1]}"


def mono_ns():
    return int(time.clock_gettime(time.CLOCK_MONOTONIC) * NS)


# ───────────────────────────── конфигурация ─────────────────────────────
# config.json:  {"ports": [443], "speed_mbps": 15}
# speed_mbps = 0 означает «ограничение выключено», трафик проходит свободно.

# Настройки сторожа. Порог в процентах от лимита: YouTube 1080p выдаёт
# в среднем 30-40% от канала в 10 Мбит/с, торрент и закачка — все 100%.
GUARD_DEFAULT = {
    "enabled": False,
    "score_needed": 3,        # баллов для штрафа
    "penalty_mbps": 1,        # хватает на переписку и звонок в мессенджере
    "penalty_min": 60,

    # Обязательное условие. Торрент — почти единственное бытовое занятие,
    # которое часами тянет данные ВНИЗ И ВВЕРХ одновременно. Стриминг молчит
    # вверх, облачный бэкап молчит вниз — оба не проходят это условие вообще.
    # Пороги разные: торрент забирает ВСЁ скачивание, а видеозвонок держит
    # скромный битрейт. Верхний порог низкий — у мобильных операторов отдача
    # всего 3-20 Мбит, и при лимите 10 сидирование даёт лишь треть канала.
    "both_dl_percent": 50,    # % от лимита вниз
    "both_ul_percent": 15,    # % от лимита вверх
    "both_ways_min": 10,      # минут одновременной нагрузки

    # Признаки, за которые начисляются баллы
    "packet_bytes": 600,      # +2 средний размер пакета в отдаче

    # Делает размер пакета не признаком, а обязательным условием: без
    # крупных пакетов вверх двусторонний счётчик не растёт вообще.
    #
    # Зачем. Порог отдачи задан в процентах от лимита, и опускать его, чтобы
    # ловить торрент со слабой раздачей, само по себе опасно: скачивание
    # порождает подтверждения вверх, а их объём растёт вместе со скоростью
    # скачивания. На ста мегабитах это несколько мегабит "отдачи", в которой
    # нет ни байта пользовательских данных.
    #
    # Размер пакета от скорости канала не зависит: подтверждение остаётся
    # коротким и на десяти мегабитах, и на гигабите. Поэтому с включённым
    # признаком порог отдачи можно опускать до единиц процентов, не боясь
    # поймать обычную закачку.
    "require_packet": False,
    "trigger_percent": 80,    # +1 держит потолок скачивания
    "sustain_min": 5,
    "hours_per_day": 4,       # +2 часов активности за сутки
    "upload_gb_per_day": 2,   # +1 гигабайт отдачи за сутки

    # Отдельный путь к штрафу, в обход обязательного условия. Торрент с
    # выключенной раздачей с точки зрения сети неотличим от обычной тяжёлой
    # закачки — выдаёт его только объём за сутки. 0 = признак выключен.
    "download_gb_per_day": 50,

    # Часовой порог — самый быстрый объёмный признак. При лимите 10 Мбит/с
    # час на полной скорости даёт ровно 4.5 ГБ, поэтому значение около 4
    # означает «держал канал почти весь час». По умолчанию выключен: на
    # капнутом канале столько же дают 4K-стриминг и загрузка игры.
    "download_gb_per_hour": 0,

    # Период опроса карт. Каждый цикл — два дампа bpftool и разбор JSON;
    # на одноядерных VPS есть смысл поднять до 20-30 секунд, детект от этого
    # почти не страдает, потому что счётчики считаются в замерах, а не в секундах.
    "watch_interval": 10,
}

# Веса признаков. Размер пакета — самый надёжный: он не зависит от скорости
# канала, а у мобильных операторов отдача гуляет от 3 до 20 Мбит.
SIGNAL_WEIGHTS = {"packet": 2, "peak": 1, "hours": 2, "upload": 1,
                  "download": 3, "hourly": 3}

# Веса признаков. Одной нагрузки (3) не хватает — нужен второй признак.
# Так разовая большая закачка проходит мимо, а торрент набирает 7 из 7.
SCORE_LOAD, SCORE_RATIO, SCORE_PACKETS = 3, 2, 2
# Окно усреднения для соотношения и размера пакета.
SCORE_WINDOW_SEC = 60


# Уведомления. По умолчанию выключены: свежая установка ничего никуда не шлёт.
TG_DEFAULT = {
    "enabled": False,
    "token": "",
    "chat_id": "",
    "thread_id": "",      # message_thread_id для супергрупп с темами
    "node_name": "",      # как подписывать ноду, пусто = имя хоста
    "events": True,       # сообщение при каждом ограничении
    "daily": True,        # сводка за прошедшие сутки
    "digest_at": "09:00", # во сколько её присылать, местное время ноды
    "proxy": "",          # socks5://… или http://… — нужен на российских нодах

    # Резервная копия состояния файлом. По умолчанию выключена; включённая
    # уходит раз в неделю в digest_at того же дня. Своей темы может не иметь —
    # тогда идёт туда же, куда отчёты.
    "backup": False,
    "backup_thread_id": "",
    "backup_day": 1,      # 1 понедельник … 7 воскресенье
}


def load_config():
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    guard = dict(GUARD_DEFAULT)
    guard.update(cfg.get("guard", {}))
    tg = dict(TG_DEFAULT)
    tg.update(cfg.get("telegram", {}))
    return {"ports": cfg.get("ports", [443]),
            "speed_mbps": float(cfg.get("speed_mbps", 0)),
            "guard": guard, "telegram": tg}


def save_config(cfg):
    """
    Пишет конфиг целиком, сохраняя незнакомые разделы.

    Слияние с тем, что уже лежит на диске, — страховка от того самого класса
    ошибок, из-за которого правка автоограничения когда-то стирала настройки
    Telegram: вызывающий передал не все разделы, и остальные исчезли.
    """
    os.makedirs(ETC_DIR, exist_ok=True)
    try:
        with open(CONFIG_FILE) as f:
            merged = json.load(f)
        if not isinstance(merged, dict):
            merged = {}
    except Exception:
        merged = {}
    merged.update(cfg)

    tmp = CONFIG_FILE + ".tmp"
    # Права ставим до записи: между open и chmod иначе есть окно, в котором
    # файл с токеном лежит доступным на чтение всем.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(merged, f, indent=2)
    os.replace(tmp, CONFIG_FILE)
    # В конфиге лежит токен бота — читать его посторонним незачем.
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def valid_ip(s):
    """Строка -> нормализованный адрес или None. Единственная точка правды."""
    try:
        return str(ipaddress.ip_address(str(s).strip()))
    except ValueError:
        return None


def parse_ports(s):
    out = []
    for part in str(s).split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            die(t("port_nan", p=part))
        p = int(part)
        if not 0 <= p <= 65535:
            die(t("port_range", p=p))
        if p not in out:
            out.append(p)
    if len(out) > MAX_PORTS:
        die(t("too_many_ports", n=MAX_PORTS))
    return out


def write_to_kernel(cfg):
    """Заливает скорость и список портов в BPF-карты."""
    require_engine()
    bps = int(cfg["speed_mbps"] * BYTES_PER_MBPS)
    map_update("config_map", struct.pack("<I", 0), struct.pack(CONFIG_FMT, bps))

    live = {parse_u32(k) for k, _ in map_dump("port_map")}
    for p in live - set(cfg["ports"]):
        map_delete("port_map", struct.pack("<I", p))
    for p in cfg["ports"]:
        map_update("port_map", struct.pack("<I", p), b"\x01")


def cmd_apply(a):
    cfg = load_config()
    if a.ports is not None:
        ports = parse_ports(a.ports)
        if not ports:
            die(t("no_ports"))
        cfg["ports"] = ports
    if a.speed is not None:
        # nan и inf проходят любые сравнения: nan < 0 ложь, nan > MAX ложь.
        # Без явной проверки такое значение доехало бы до int() и уронило
        # команду с трассировкой прямо посреди применения настроек.
        if a.speed != a.speed or a.speed in (float("inf"), float("-inf")):
            die(t("neg_speed"))
        if a.speed < 0:
            die(t("neg_speed"))
        if a.speed > MAX_MBPS:
            die(t("too_fast", v=a.speed))
        cfg["speed_mbps"] = a.speed

    write_to_kernel(cfg)
    save_config(cfg)
    if not a.quiet:
        cmd_show(a)


def cmd_show(a):
    cfg = load_config()
    ports = ", ".join(map(str, cfg["ports"])) if cfg["ports"] != [0] else t("all_ports")
    print()
    if cfg["speed_mbps"] > 0:
        print(f"  {t('speed'):<9}: {C['b']}{cfg['speed_mbps']:g} Mbit/s{C['r']} "
              f"{t('per_user')}")
    else:
        print(f"  {t('speed'):<9}: {C['yel']}{t('unlimited')}{C['r']}")
    print(f"  {t('ports'):<9}: {ports}")
    cmd_guard_show(cfg["speed_mbps"], cfg["guard"])
    # Строка для сверки нод между собой: одинаковый отпечаток — одинаковая
    # политика. Держим её приглушённой, повседневной работе она не мешает.
    nid = node_id()
    print(f"  {C['gry']}{t('id_node')} {nid or t('id_none')}"
          f"  ·  {t('id_config')} {config_hash(cfg)}{C['r']}")
    print()


def cmd_restore(a):
    """Вызывается сервисом при старте: заливает config.json в свежие карты."""
    cfg = load_config()
    write_to_kernel(cfg)
    n = restore_penalties()
    print(t("restored", s=cfg["speed_mbps"], p=",".join(map(str, cfg["ports"]))))
    if n:
        print(t("restored_pen", n=n))


# ───────────────────────────── статистика ─────────────────────────────

def read_users():
    """{ip: {"down": байт, "up": байт, "up_pkts": шт, "seen": нс}}"""
    users = {}
    for map_name, direction in (("user_state_map_down", "down"),
                                ("user_state_map_up", "up")):
        for k, v in map_dump(map_name):
            ip, _ = parse_ip_key(k)
            if ip is None:
                continue
            st = parse_user_state(v)
            e = users.setdefault(ip, {"down": 0, "up": 0, "up_pkts": 0, "seen": 0})
            e[direction] = st["total"]
            if direction == "up":
                e["up_pkts"] = st["pkts"]
            e["seen"] = max(e["seen"], st["seen"])
    return users


def cmd_status(a):
    require_engine()
    cfg = load_config()

    first = read_users()
    if a.live:
        print(f"{C['gry']}  {t('measuring', i=a.interval)}{C['r']}")
        time.sleep(a.interval)
        second = read_users()
    else:
        second = first

    now = mono_ns()
    rows = []
    for ip, cur in second.items():
        prev = first.get(ip, {"down": 0, "up": 0})
        # байты за интервал -> Мбит/с
        dl = max(0, cur["down"] - prev["down"]) * 8 / 1e6 / a.interval if a.live else None
        ul = max(0, cur["up"] - prev["up"]) * 8 / 1e6 / a.interval if a.live else None
        idle = (now - cur["seen"]) / NS if cur["seen"] else 0
        rows.append((ip, cur, dl, ul, idle))

    if a.json:
        print(json.dumps([
            {"ip": ip, "downloaded_bytes": c["down"], "uploaded_bytes": c["up"],
             "download_mbps": dl, "upload_mbps": ul, "idle_sec": round(idle, 1)}
            for ip, c, dl, ul, idle in rows], indent=2))
        return

    rows.sort(key=(lambda x: (x[2] or 0) + (x[3] or 0)) if a.live
              else (lambda x: x[1]["down"] + x[1]["up"]), reverse=True)
    active = [x for x in rows if x[4] < 60]

    limit = (f"{cfg['speed_mbps']:g} Mbit/s" if cfg["speed_mbps"] > 0
             else t("no_limit"))
    ports = ", ".join(map(str, cfg["ports"])) if cfg["ports"] != [0] else t("all_ports")
    print(f"\n  {t('limit')} {C['b']}{limit}{C['r']} · {t('ports').lower()} {ports} · "
          f"{t('total_ips')}: {len(rows)} · {t('active_min')}: {len(active)}")
    print("  " + "─" * 70)

    if not rows:
        print(f"  {C['gry']}{t('no_traffic')}{C['r']}\n")
        return

    head = f"  {'IP':<30}{t('downloaded'):>12}{t('uploaded'):>12}"
    head += f"{t('now'):>14}" if a.live else ""
    print(f"{C['gry']}{head}{C['r']}")

    shown = rows if a.full else rows[:a.top]
    for ip, c, dl, _ul, idle in shown:
        mark = f"{C['gry']}·{C['r']}" if idle > 300 else " "
        line = f" {mark}{ip:<30}{fmt_bytes(c['down']):>12}{fmt_bytes(c['up']):>12}"
        if a.live:
            line += f"{dl:>9.1f} Mbit/s"
        print(line)

    if not a.full and len(rows) > a.top:
        print(f"  {C['gry']}{t('more_ips', n=len(rows) - a.top)}{C['r']}")
    print(f"  {C['gry']}{t('idle_note')}{C['r']}\n")


# ────────────────────────────── монитор ──────────────────────────────

def rates(prev, cur, dt):
    """
    По каждому IP за прошедший интервал: скорости в Мбит/с и средний размер
    пакета в отдаче.

    Размер пакета здесь не для красоты. Это единственное число, которое
    отличает раздачу от обычной закачки, и оно не зависит от скорости канала:
    подтверждение остаётся коротким и на десяти мегабитах, и на гигабите.
    """
    out = {}
    for ip, c in cur.items():
        p = prev.get(ip, {"down": 0, "up": 0, "up_pkts": 0})
        up_bytes = max(0, c["up"] - p["up"])
        up_pkts = max(0, c.get("up_pkts", 0) - p.get("up_pkts", 0))
        out[ip] = (max(0, c["down"] - p["down"]) * 8 / 1e6 / dt,
                   up_bytes * 8 / 1e6 / dt,
                   (up_bytes / up_pkts) if up_pkts else 0)
    return out


def fmt_hold(sec):
    """Сколько времени подряд IP держит нагрузку."""
    if sec < 1:
        return "—"
    if sec < 60:
        return f"{int(sec)} {t('sec')}"
    if sec < 3600:
        return f"{int(sec // 60)} {t('min')}"
    return f"{sec / 3600:.1f} {t('hour')}"


# Дробные блоки: восьмушки ширины символа. Обычная полоса из целых блоков
# при ширине 12 различает всего двенадцать уровней — разница между 7.3 и 7.4
# на ней не видна вовсе. С восьмушками уровней 96 при той же ширине.
# Выше этого среднего размера пакета отдача перестаёт быть подтверждениями и
# становится данными. Подтверждение в туннеле занимает 100-170 байт, кусок
# торрента — больше тысячи. Число служит только подсветкой в мониторе;
# решение сторож принимает по своему packet_bytes.
PKT_DATA_HINT = 600

EIGHTHS = "▏▎▍▌▋▊▉█"
SPARK = "▁▂▃▄▅▆▇█"


def bar(value, scale, width=14):
    if scale <= 0:
        return ""
    units = max(0.0, min(1.0, value / scale)) * width
    full = int(units)
    rest = units - full
    out = "█" * full
    if full < width and rest > 0.06:
        out += EIGHTHS[min(7, int(rest * 8))]
    return out + "·" * max(0, width - len(out))


def spark(values, width=12):
    """Мини-график последних значений. Пусто, если рисовать нечего."""
    vals = [v for v in values if v is not None][-width:]
    if len(vals) < 2:
        return ""
    top = max(vals)
    if top <= 0:
        return "▁" * len(vals)
    return "".join(SPARK[min(7, int(v / top * 7.999))] for v in vals)


def load_color(share):
    """
    Цвет по доле от лимита. Раньше цвет зависел от того, «держит» ли адрес
    нагрузку дольше тридцати секунд, и на спокойной ноде экран был
    одноцветным — глазу не за что зацепиться.
    """
    if share >= 0.8:
        return C["bred"]
    if share >= 0.5:
        return C["byel"]
    if share >= 0.2:
        return C["bgrn"]
    return C["gry"]


def cmd_monitor(a):
    require_engine()
    cfg = load_config()
    limit = cfg["speed_mbps"]
    # «Держит нагрузку» — выше половины лимита. Без лимита берём 5 Мбит/с.
    busy_at = max(1.0, limit * 0.5) if limit > 0 else 5.0
    keep = max(3, int(60 / a.interval))     # усреднение примерно за минуту
    spark_keep = max(8, int(60 / a.interval))

    history, since, chan = {}, {}, []
    prev, prev_t = read_users(), time.monotonic()
    pens, pens_at = load_penalties(), 0.0
    wl = whitelist_ips()
    width = 78

    print("\033[?25l", end="", flush=True)   # спрятать курсор
    try:
        while True:
            time.sleep(a.interval)
            cur = read_users()
            now_t = time.monotonic()
            dt = max(0.1, now_t - prev_t)
            rt = rates(prev, cur, dt)
            prev, prev_t = cur, now_t

            # Список штрафов меняется редко — перечитываем раз в пять секунд.
            if now_t - pens_at > 5:
                pens, pens_at = load_penalties(), now_t
                wl = whitelist_ips()

            rows = []
            for ip, (dl, ul, up_pkt) in rt.items():
                h = history.setdefault(ip, [])
                h.append(dl)
                del h[:-keep]
                if dl >= busy_at:
                    since.setdefault(ip, now_t)
                else:
                    since.pop(ip, None)
                rows.append((ip, dl, ul, sum(h) / len(h),
                             now_t - since[ip] if ip in since else 0, up_pkt))

            active = [r for r in rows if r[1] + r[2] > 0.05]
            active.sort(key=lambda r: r[1] + r[2], reverse=True)
            total_dl = sum(r[1] for r in rows)
            total_ul = sum(r[2] for r in rows)
            chan.append(total_dl)
            del chan[:-spark_keep]
            scale = limit if limit > 0 else max([r[1] for r in active] + [10])

            out = ["\033[H\033[2J"]
            out.append(f"\n  {C['b']}{t('mon_title')}{C['r']}"
                       f"{C['gry']}{t('mon_hint', i=a.interval):>{width - 8}}{C['r']}")
            out.append(f"  {C['gry']}{'─' * width}{C['r']}")

            line = spark(chan)
            out.append(f"   {t('mon_channel'):<16}"
                       f"{C['b']}↓ {total_dl:>6.1f}{C['r']}   ↑ {total_ul:>5.1f} Mbit/s"
                       f"   {C['cyan']}{line}{C['r']}"
                       f"{('  ' + t('mon_minute')) if line else ''}")
            if limit > 0:
                out.append(f"   {t('mon_limit_row'):<16}{C['b']}{limit:g} Mbit/s{C['r']}"
                           f"   {C['gry']}{t('mon_per_ip')}{C['r']}"
                           f"      {t('mon_loading')} {C['b']}{len(active)}{C['r']}"
                           f" {t('mon_of')} {len(rows)}")
            else:
                out.append(f"   {t('mon_limit_row'):<16}{C['yel']}{t('mon_nolimit')}{C['r']}"
                           f"          {t('mon_loading')} {C['b']}{len(active)}{C['r']}"
                           f" {t('mon_of')} {len(rows)}")
            out.append(f"  {C['gry']}{'─' * width}{C['r']}")
            out.append(f"{C['gry']}   {'IP':<21}{t('now'):>8}{t('mon_up'):>8}"
                       f"{t('mon_pkt'):>7}{t('mon_avg'):>8}{t('mon_hold'):>7}"
                       f"  {t('mon_share')}{C['r']}")

            if not active:
                out.append(f"\n   {C['gry']}{t('mon_idle')}{C['r']}")

            for ip, dl, ul, avg, hold, up_pkt in active[:a.top]:
                share = dl / scale if scale > 0 else 0
                col = load_color(share)
                # Значок слева вместо колонки «держит»: в спокойный час она
                # была сплошь из прочерков и занимала девять знаков впустую.
                if ip in pens:
                    mark = f"{C['bred']}⊘{C['r']}"
                elif ip in wl:
                    # Адрес из белого списка: считаем, но не ограничиваем.
                    # Видеть его нагрузку важнее всего — именно он может
                    # незаметно съесть канал, оставаясь вне лимита.
                    mark = f"{C['cyan']}✓{C['r']}"
                elif hold >= 30:
                    mark = f"{C['byel']}▪{C['r']}"
                else:
                    mark = " "
                pct = f"{share * 100:>3.0f}%" if limit > 0 else "   "
                # Отдачу красим по своей шкале: у мобильных операторов канал
                # вверх узкий, и заметная отдача — первый признак раздачи.
                ul_col = C["gry"]
                if limit > 0 and ul >= limit * 0.15:
                    ul_col = C["bred"] if ul >= limit * 0.4 else C["byel"]
                # Время удержания вернулось отдельной колонкой: по нему
                # видно разницу между всплеском и постоянной нагрузкой,
                # а значок слева этого не показывает.
                hold_txt = fmt_hold(hold) if hold >= 1 else "—"
                hold_col = C["byel"] if hold >= 30 else C["gry"]
                # Средний размер пакета в отдаче — единственное число, по
                # которому раздача отличается от обычной закачки, и оно не
                # зависит от скорости канала. Подтверждения занимают около
                # сотни байт, данные — за тысячу; красим по порогу сторожа.
                if up_pkt < 1:
                    pkt_txt, pkt_col = "—", C["gry"]
                else:
                    pkt_txt = f"{up_pkt:.0f}"
                    pkt_col = C["byel"] if up_pkt >= PKT_DATA_HINT else C["gry"]
                out.append(f" {mark} {ip:<21}{col}{dl:>8.1f}{C['r']}"
                           f"{ul_col}{ul:>8.1f}{C['r']}"
                           f"{pkt_col}{pkt_txt:>7}{C['r']}"
                           f"{C['gry']}{avg:>8.1f}{C['r']}"
                           f"{hold_col}{hold_txt:>7}{C['r']}"
                           f"  {col}{bar(dl, scale, 12)}{C['r']} {C['gry']}{pct}{C['r']}")

            out.append(f"  {C['gry']}{'─' * width}{C['r']}")
            shown = min(len(active), a.top)
            out.append(f"   {C['gry']}{t('mon_shown', a=shown, b=len(active))}"
                       f"   ▪ {t('mon_leg_hold')}   ✓ {t('mon_leg_wl')}"
                       f"   ⊘ {t('mon_leg_limited')}{C['r']}")
            out.append(f"   {C['gry']}{t('mon_leg_pkt', n=PKT_DATA_HINT)}{C['r']}")
            print("\n".join(out), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        print("\033[?25h", end="", flush=True)   # вернуть курсор
        print()


# ─────────────────────── штрафы и сторож ───────────────────────
# Сторож раз в WATCH_INTERVAL секунд смотрит скорость каждого IP. Если она
# держится выше порога дольше заданного времени — это не стриминг, а закачка,
# и адрес получает персональный лимит на время.
#
# Счётчик с допуском: замер выше порога прибавляет очко, ниже — отнимает.
# Короткие провалы (буферизация, смена сегмента) штраф не отменяют, а вот
# нормальный сёрфинг с паузами очков не накопит.

WATCH_INTERVAL = 10          # значение по умолчанию, живое берётся из конфига


def load_penalties():
    """{ip: {"until": epoch, "mbps": float}} — только живые записи."""
    try:
        with open(PEN_FILE) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
    except Exception:
        return {}
    now = time.time()
    out = {}
    for ip, p in data.items():
        # Файл могли покорёжить руками. Сторож перезапускается каждые 15 с,
        # и одна строка «until»: «завтра» иначе крутила бы его в вечном цикле.
        if not isinstance(p, dict) or valid_ip(ip) is None:
            continue
        try:
            if float(p.get("until", 0)) > now and float(p.get("mbps", 0)) > 0:
                out[ip] = p
        except (TypeError, ValueError):
            continue
    return out


def save_penalties(pens):
    tmp = PEN_FILE + ".tmp"
    os.makedirs(ETC_DIR, exist_ok=True)
    with open(tmp, "w") as f:
        json.dump(pens, f, indent=2)
    os.replace(tmp, PEN_FILE)


@contextlib.contextmanager
def file_lock(path):
    """
    Блокировка на время «прочитал — изменил — записал».

    Раньше штрафы правил только сторож, и гонки быть не могло. Теперь их
    правят ещё CLI и API: без замка сторож, сохраняя свой штраф, затирал бы
    чужую запись, сделанную секунду назад, — в карте ядра она осталась бы,
    а в файле исчезла.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def penalties_update(fn):
    """
    Атомарно меняет список штрафов: fn получает словарь и правит его на месте.
    Возвращает то, что вернул fn. Единственный правильный способ записи —
    им пользуются и сторож, и CLI, и API.
    """
    with file_lock(PEN_FILE + ".lock"):
        pens = load_penalties()
        result = fn(pens)
        save_penalties(pens)
    return result


# ───────────────────────────── журнал событий ─────────────────────────────
# Одна строка JSON на событие. Пишут сторож, CLI, движок и API — читают
# оттуда же, чтобы у всех была одна версия истории. Базы данных для этого
# заводить незачем: файл с ротацией по размеру переживает и сотню нод.

EVENT_TYPES = {
    "limit_applied",     # адрес получил ограничение
    "limit_released",    # ограничение снято
    "limit_expired",     # ограничение истекло само
    "guard_triggered",   # сработало автоограничение
    "config_changed",    # изменены настройки
    "engine_started",    # движок загрузил eBPF
    "engine_stopped",    # движок выгружен
    "api_action",        # действие через API
    "error",             # ошибка
}
EVENT_MAX_BYTES = 4 * 1024 * 1024      # больше — половина уезжает в .1


def log_event(etype, ip=None, source="shape", **fields):
    """
    Добавляет событие. Никогда не бросает исключение: журнал не должен
    ронять ни сторож, ни API. Секретов здесь быть не может — в fields
    попадают только заранее известные поля вызывающего кода.
    """
    try:
        if etype not in EVENT_TYPES:
            etype = "error"
        rec = {"ts": round(time.time(), 3), "type": etype, "source": str(source)[:32]}
        if ip:
            rec["ip"] = str(ip)[:45]
        for k, v in fields.items():
            if v is None:
                continue
            rec[str(k)[:32]] = v if isinstance(v, (int, float, bool)) else str(v)[:200]

        os.makedirs(VAR_DIR, exist_ok=True)
        with file_lock(os.path.join(VAR_DIR, "events.lock")):
            seq = 0
            try:
                with open(EVENT_SEQ) as f:
                    seq = int(f.read().strip() or 0)
            except Exception:
                seq = 0
            seq += 1
            rec["id"] = seq

            if os.path.exists(EVENT_FILE) and os.path.getsize(EVENT_FILE) > EVENT_MAX_BYTES:
                os.replace(EVENT_FILE, EVENT_FILE + ".1")
            fd = os.open(EVENT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            tmp = EVENT_SEQ + ".tmp"
            with open(tmp, "w") as f:
                f.write(str(seq))
            os.replace(tmp, EVENT_SEQ)
        return rec["id"]
    except Exception:
        return 0


def read_events(after=0, limit=100, etype=None, ip=None, since=None, until=None):
    """
    Возвращает (список событий, есть ли ещё). Читаем с конца — свежие нужны
    чаще. Ротированный файл подхватываем, только если в свежем не хватило.
    """
    limit = max(1, min(int(limit or 100), 1000))
    out = []
    for path in (EVENT_FILE, EVENT_FILE + ".1"):
        if not os.path.exists(path):
            continue
        try:
            with open(path, errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            if after and rec.get("id", 0) <= after:
                continue
            if etype and rec.get("type") != etype:
                continue
            if ip and rec.get("ip") != ip:
                continue
            if since and rec.get("ts", 0) < since:
                continue
            if until and rec.get("ts", 0) > until:
                continue
            out.append(rec)
            if len(out) > limit:
                return out[:limit], True
        if len(out) >= limit:
            break
    return out[:limit], False



# ─────────────────────────── владельцы адресов ───────────────────────────
# За IP-адресом стоит человек, но шейпер об этом знать не может: он работает
# на сетевом уровне. Зато об этом знает панель. Здесь лежит готовое место,
# куда эти сведения складываются, и одна функция, которой пользуются
# уведомления, журнал событий и API.
#
# Формат: {"1.2.3.4": {"label": "Александр", "user_id": "42",
#                      "telegram_id": 123456789, "updated": 1755100000}}

OWNER_FIELDS = ("label", "user_id", "telegram_id")


def load_owners():
    try:
        with open(OWNERS_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_owners(owners):
    os.makedirs(VAR_DIR, exist_ok=True)
    tmp = OWNERS_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w") as f:
        json.dump(owners, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OWNERS_FILE)


def owners_update(fn):
    """Атомарная правка карты владельцев: её пишут и API, и CLI."""
    with file_lock(OWNERS_FILE + ".lock"):
        owners = load_owners()
        result = fn(owners)
        save_owners(owners)
    return result


def owner_of(ip, owners=None):
    """Сведения о владельце адреса или None. Никогда не бросает исключение."""
    try:
        rec = (owners if owners is not None else load_owners()).get(ip)
        if not isinstance(rec, dict):
            return None
        out = {k: rec[k] for k in OWNER_FIELDS if rec.get(k) not in (None, "")}
        return out or None
    except Exception:
        return None


def subject_text(subject, ip):
    """
    Как назвать нарушителя в сообщении.

    Ссылка делается через tg://user?id=…, а не через @username: имя
    пользователя есть далеко не у всех, а telegram_id панель знает всегда.
    """
    if not subject:
        return f"<code>{ip}</code>"
    label = html.escape(str(subject.get("label") or "")).strip()
    tg_id = subject.get("telegram_id")
    if label and tg_id:
        return f'<a href="tg://user?id={int(tg_id)}">{label}</a> · <code>{ip}</code>'
    if label:
        return f"{label} · <code>{ip}</code>"
    if tg_id:
        return f'<a href="tg://user?id={int(tg_id)}">id {int(tg_id)}</a> · <code>{ip}</code>'
    return f"<code>{ip}</code>"


# ──────────────────────────── история по суткам ───────────────────────────
# Суточные счётчики обнуляются в полночь, и до сих пор от них не оставалось
# ничего. Одна строка в день стоит около сотни байт — зато появляется ответ
# на вопрос «сколько мы отдали за прошлый месяц», который рано или поздно
# задаёт хостер.

def history_append(day, snapshot, limited=0):
    try:
        if not snapshot:
            return
        owners = load_owners()
        top = sorted(snapshot.items(), key=lambda kv: -kv[1].get("down", 0))[:5]
        rec = {
            "day": day,
            "down": int(sum(v.get("down", 0) for v in snapshot.values())),
            "up": int(sum(v.get("up", 0) for v in snapshot.values())),
            "ips": len(snapshot),
            "limited": int(limited),
            "top": [{"ip": ip,
                     "down": int(v.get("down", 0)),
                     "label": (owner_of(ip, owners) or {}).get("label")}
                    for ip, v in top],
        }
        os.makedirs(VAR_DIR, exist_ok=True)
        with file_lock(HISTORY_FILE + ".lock"):
            rows = read_history(limit=HISTORY_MAX_DAYS)
            rows = [r for r in rows if r.get("day") != day]
            rows.append(rec)
            rows.sort(key=lambda r: r.get("day", ""))
            rows = rows[-HISTORY_MAX_DAYS:]
            tmp = HISTORY_FILE + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            with os.fdopen(fd, "w") as f:
                for r in rows:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            os.replace(tmp, HISTORY_FILE)
    except Exception:
        pass


def read_history(limit=30):
    """Свежие сутки в конце списка."""
    try:
        with open(HISTORY_FILE) as f:
            rows = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("day"):
                    rows.append(rec)
        return rows[-max(1, int(limit)):]
    except Exception:
        return []


def penalty_apply(ip, mbps, until_epoch):
    """Пишет штраф в BPF-карту. until пересчитывается в шкалу ядра."""
    left = max(1.0, until_epoch - time.time())
    until_ns = mono_ns() + int(left * NS)
    map_update("penalty_map", ip_key(ip),
               struct.pack(PEN_FMT, int(mbps * BYTES_PER_MBPS), until_ns))


def penalty_clear(ip):
    map_delete("penalty_map", ip_key(ip))



# ───────────────────────── персональные скорости ─────────────────────────
# Карта штрафов в ядре хранит «этому адресу такая-то скорость до такого-то
# времени» и не проверяет, ниже она общей или выше. Значит тем же механизмом
# выдаётся и постоянная персональная скорость: сотруднику с рабочей системой
# больше общего лимита, проблемному адресу — меньше. Отдельного кода в ядре
# для этого не нужно.
#
# Отличаются такие записи полем kind: "personal". Срок им ставится далёкий и
# продлевается сторожем — бессрочных записей в ядре не бывает.

PERSONAL_TTL = 30 * 24 * 3600      # на сколько вперёд ставится срок в ядре
PERSONAL_RENEW = 3600              # как часто сторож его продлевает


def is_personal(entry):
    return isinstance(entry, dict) and entry.get("kind") == "personal"


def personal_set(ip, mbps, note="", subject=None):
    """Назначить адресу постоянную скорость. Возвращает запись."""
    now = time.time()
    entry = {"until": now + PERSONAL_TTL, "mbps": float(mbps), "since": now,
             "kind": "personal", "source": "manual", "reason": note or None}
    if subject:
        entry["subject"] = subject
    penalty_apply(ip, mbps, entry["until"])
    penalties_update(lambda pens: pens.__setitem__(ip, entry))
    log_event("config_changed", ip=ip, source="manual",
              message=f"personal {mbps:g} Mbit/s")
    return entry


def personal_clear(ip):
    existing = load_penalties().get(ip)
    if not is_personal(existing):
        return None
    penalty_clear(ip)
    penalties_update(lambda pens: pens.pop(ip, None))
    log_event("config_changed", ip=ip, source="manual", message="personal off")
    return existing


def personal_list():
    return {ip: p for ip, p in load_penalties().items() if is_personal(p)}


def restore_penalties():
    """Перезаливает живые штрафы в карту — после рестарта движка."""
    pens = load_penalties()
    for ip, p in pens.items():
        try:
            penalty_apply(ip, p["mbps"], p["until"])
        except Exception:
            pass
    save_penalties(pens)
    return len(pens)


def cmd_limited(a):
    # Персональные скорости — не наказание, им место в своём списке.
    pens = {ip: p for ip, p in load_penalties().items() if not is_personal(p)}
    if a.json:
        print(json.dumps([{"ip": ip, "mbps": p["mbps"],
                           "since": p.get("since"),
                           "seconds_left": round(p["until"] - time.time()),
                           "score": p.get("score"),
                           "reasons": p.get("reasons", [])}
                          for ip, p in pens.items()], indent=2))
        return
    if not pens:
        print(f"\n  {C['gry']}{t('lim_none')}{C['r']}\n")
        return

    print(f"\n{C['gry']}  {'IP':<24}{t('lim_when'):>8}{t('lim_left'):>12}"
          f"   {t('lim_why')}{C['r']}")
    print("  " + "─" * 68)
    # свежие сверху: интереснее всего то, что произошло только что
    for ip, p in sorted(pens.items(), key=lambda x: -x[1].get("since", 0)):
        since = p.get("since")
        when = time.strftime("%H:%M", time.localtime(since)) if since else "—"
        why = ", ".join(t("why_" + r) for r in p.get("reasons") or []) or "—"
        print(f"  {C['red']}{ip:<24}{C['r']}{when:>8}"
              f"{fmt_hold(p['until'] - time.time()):>12}   {C['gry']}{why}{C['r']}")
    speeds = sorted({float(p.get("mbps", 0)) for p in pens.values()})
    speed_txt = " / ".join(f"{s:g}" for s in speeds)
    print(f"\n  {C['gry']}{t('lim_total')}: {len(pens)} · "
          f"{t('lim_speed')} {speed_txt} Mbit/s{C['r']}\n")


def cmd_release(a):
    if a.all:
        def drop_all(pens):
            for ip in list(pens):
                penalty_clear(ip)
                log_event("limit_released", ip=ip, source="cli")
            n = len(pens)
            pens.clear()
            return n
        n = penalties_update(drop_all)
        print(f"{C['grn']}✓ {t('rel_all', n=n)}{C['r']}")
        return
    if not a.ip:
        die(t("rel_need_ip"))
    ip = valid_ip(a.ip)
    if ip is None:
        die(t("bad_ip", ip=a.ip[:60]))
    penalty_clear(ip)

    def drop_one(pens):
        pens.pop(ip, None)
        pens.pop(a.ip, None)
    penalties_update(drop_one)
    log_event("limit_released", ip=ip, source="cli")
    print(f"{C['grn']}✓ {t('rel_one', ip=ip)}{C['r']}")


def cmd_guard(a):
    cfg = load_config()
    g = cfg["guard"]
    if a.enable:
        g["enabled"] = True
    if a.disable:
        g["enabled"] = False

    limits = (
        (a.score,      "score_needed",      1, 6),
        (a.both_min,   "both_ways_min",     1, 120),
        (a.both_dl,    "both_dl_percent",   10, 100),
        (a.both_ul,    "both_ul_percent",   1, 100),
        (a.percent,    "trigger_percent",   10, 100),
        (a.sustain,    "sustain_min",       1, 1440),
        (a.penalty_mbps, "penalty_mbps",    0.1, 1000),
        (a.penalty_min,  "penalty_min",     1, 10080),
        (a.hours,      "hours_per_day",     1, 24),
        (a.upload_gb,  "upload_gb_per_day", 0.1, 1000),
        (a.download_gb, "download_gb_per_day", 0, 10000),
        (a.download_gbh, "download_gb_per_hour", 0, 1000),
        (a.interval,   "watch_interval",     5, 60),
        (a.packet,     "packet_bytes",      100, 1500),
    )
    for val, key, lo, hi in limits:
        if val is not None:
            if not lo <= val <= hi:
                die(t("guard_range", k=key, lo=lo, hi=hi))
            g[key] = val

    if a.require_packet is not None:
        g["require_packet"] = a.require_packet == "on"

    # Секцию telegram сюда обязательно: раньше её здесь не было, и любая
    # правка автоограничения молча стирала токен, чат, прокси и время сводки.
    cfg["guard"] = g
    save_config(cfg)
    if not a.quiet:
        cmd_guard_show(cfg["speed_mbps"], g)


def cmd_guard_show(speed, g):
    print()
    state = f"{C['grn']}{t('guard_on')}{C['r']}" if g["enabled"] \
        else f"{C['gry']}{t('guard_off')}{C['r']}"
    print(f"  {t('guard_state')}: {state}")
    if speed > 0:
        print(f"  {t('guard_both')}: ↓{speed * g['both_dl_percent'] / 100:g} "
              f"↑{speed * g['both_ul_percent'] / 100:g} Mbit/s "
              f"{t('guard_during')} {g['both_ways_min']} {t('min')}")
        if g.get("require_packet"):
            print(f"  {C['gry']}{t('guard_req_packet', n=g['packet_bytes'])}{C['r']}")
        print(f"  {t('guard_score')}: {g['score_needed']}")
    print(f"  {t('guard_penalty')}: {g['penalty_mbps']:g} Mbit/s "
          f"{t('guard_for')} {g['penalty_min']} {t('min')}")
    print()


def traffic_sample(prev, cur, dt):
    """
    Замер за интервал по каждому IP:
      dl, ul   — Мбит/с
      up_pkt   — средний размер пакета в отдаче, байт
      up_bytes — сколько отдано за интервал
    """
    out = {}
    for ip, c in cur.items():
        p = prev.get(ip, {"down": 0, "up": 0, "up_pkts": 0})
        d_bytes = max(0, c["down"] - p["down"])
        u_bytes = max(0, c["up"] - p["up"])
        u_pkts = max(0, c["up_pkts"] - p["up_pkts"])
        out[ip] = {
            "dl": d_bytes * 8 / 1e6 / dt,
            "ul": u_bytes * 8 / 1e6 / dt,
            "up_pkt": (u_bytes / u_pkts) if u_pkts else 0,
            "up_bytes": u_bytes,
            "dl_bytes": d_bytes,
        }
    return out


def load_daily():
    """Суточные счётчики: секунды активности и объём отдачи. Сброс в полночь."""
    try:
        with open(DAILY_FILE) as f:
            data = json.load(f)
    except Exception:
        return {}
    if data.get("day") != time.strftime("%Y-%m-%d"):
        return {}
    return data.get("ips", {})


def save_daily(ips):
    tmp = DAILY_FILE + ".tmp"
    os.makedirs(ETC_DIR, exist_ok=True)
    with open(tmp, "w") as f:
        json.dump({"day": time.strftime("%Y-%m-%d"), "ips": ips}, f)
    os.replace(tmp, DAILY_FILE)


HOUR_BUCKET = 300          # окно из двенадцати пятиминутных корзин


def hourly_add(hourly, ip, nbytes, now):
    """Копит скачанное за последний час корзинами по 5 минут."""
    b = int(now // HOUR_BUCKET)
    d = hourly.setdefault(ip, {})
    d[b] = d.get(b, 0) + nbytes
    for old in [k for k in d if k <= b - 12]:
        del d[old]


def evaluate(ip, s, g, cap, both_streak, peak_streak, daily, hourly=None):
    """
    Решает, нарушитель ли это. Возвращает (баллы, сработавшие признаки).

    Обязательное условие — трафик в обе стороны одновременно. Без него ноль
    баллов, каким бы тяжёлым трафик ни был: так из-под удара выходят стриминг
    (молчит вверх) и облачный бэкап (молчит вниз).
    """
    day = daily.get(ip, {"active": 0, "up": 0, "down": 0})

    # Независимый путь: качает десятками гигабайт в сутки. Отдача не важна —
    # торрент с выключенной раздачей выглядит как обычная тяжёлая закачка,
    # и единственное, что его выдаёт, это объём.
    gb = g.get("download_gb_per_day", 0)
    if gb and day.get("down", 0) >= gb * 1e9:
        return max(g["score_needed"], SIGNAL_WEIGHTS["download"]), ["download"]

    # То же самое, но по скользящему часу: реагирует за час вместо суток.
    gbh = g.get("download_gb_per_hour", 0)
    if gbh and hourly and sum(hourly.get(ip, {}).values()) >= gbh * 1e9:
        return max(g["score_needed"], SIGNAL_WEIGHTS["hourly"]), ["hourly"]

    iv = g.get("watch_interval", WATCH_INTERVAL)
    if both_streak < max(1, int(g["both_ways_min"] * 60 / iv)):
        return 0, []

    reasons = []

    # Крупные пакеты вверх = клиент отдаёт данные, а не подтверждения.
    # Нижний порог по отдаче нужен, чтобы редкие пакеты не давали случайных
    # средних. Признак не зависит от скорости канала — это его главная ценность.
    if s["up_pkt"] >= g["packet_bytes"] and s["ul"] >= 0.3:
        reasons.append("packet")
    if peak_streak >= max(1, int(g["sustain_min"] * 60 / iv)):
        reasons.append("peak")
    if day["active"] >= g["hours_per_day"] * 3600:
        reasons.append("hours")
    if day["up"] >= g["upload_gb_per_day"] * 1e9:
        reasons.append("upload")

    return sum(SIGNAL_WEIGHTS[r] for r in reasons), reasons


def cmd_watch(a):
    """Демон: следит за нагрузкой и выдаёт штрафы. Запускается сервисом."""
    require_engine()
    print(t("watch_start"), flush=True)
    restore_penalties()

    both_streak, peak_streak, hourly = {}, {}, {}
    daily = load_daily()
    today = time.strftime("%Y-%m-%d")
    prev, prev_t = read_users(), time.monotonic()
    last_daily_save = time.time()
    last_personal_renew = 0.0
    interval = load_config()["guard"].get("watch_interval", WATCH_INTERVAL)

    while True:
        time.sleep(interval)
        try:
            cfg = load_config()
            g = cfg["guard"]
            interval = g.get("watch_interval", WATCH_INTERVAL)
            cap = cfg["speed_mbps"]

            # Сутки закрылись: откладываем срез и обнуляем счётчики.
            day_now = time.strftime("%Y-%m-%d")
            if day_now != today:
                digest_stash(today, daily)
                # Та же точка — единственная, где сутки видны целиком.
                history_append(today, daily,
                               limited=len([p for p in load_penalties().values()
                                            if not is_personal(p)]))
                daily = {}
                save_daily(daily)
                today = day_now
            digest_due(cfg)
            backup_due(cfg)

            # Персональные скорости живут в ядре с далёким, но конечным
            # сроком. Продлеваем раз в час, чтобы они не истекли молча.
            if time.time() - last_personal_renew > PERSONAL_RENEW:
                last_personal_renew = time.time()
                for pip, pentry in personal_list().items():
                    try:
                        penalty_apply(pip, pentry["mbps"],
                                      time.time() + PERSONAL_TTL)
                    except Exception:
                        pass

            cur = read_users()
            now_t = time.monotonic()
            dt = max(1.0, now_t - prev_t)
            sample = traffic_sample(prev, cur, dt)
            prev, prev_t = cur, now_t

            # забываем тех, кто отвалился
            for d in (both_streak, peak_streak, hourly):
                for ip in [i for i in d if i not in cur]:
                    d.pop(ip, None)

            # снимаем истёкшие штрафы из карты ядра
            pens = load_penalties()
            in_map = {ip for ip, _ in
                      [(parse_ip_key(k)[0], v) for k, v in map_dump("penalty_map")]}
            for ip in in_map - set(pens):
                penalty_clear(ip)
                log_event("limit_expired", ip=ip, source="watchdog")

            # Автоограничение выключено — штрафов не выдаём, но счёт трафика
            # продолжаем: на нём держится суточная сводка в Telegram, и раньше
            # при выключенном стороже она приходила пустой.
            guard_on = bool(g["enabled"]) and cap > 0
            if not guard_on:
                both_streak.clear()
                peak_streak.clear()

            dl_floor = cap * g["both_dl_percent"] / 100
            ul_floor = cap * g["both_ul_percent"] / 100
            peak_floor = cap * g["trigger_percent"] / 100
            active_floor = cap * 0.25 if cap > 0 else 1.0
            need_score = g["score_needed"]
            wl = whitelist_ips()

            for ip, s in sample.items():
                # суточные счётчики ведём для всех, даже для уже наказанных
                d = daily.setdefault(ip, {"active": 0, "up": 0, "down": 0})
                d.setdefault("down", 0)
                if max(s["dl"], s["ul"]) >= active_floor:
                    d["active"] += interval
                d["up"] += s["up_bytes"]
                d["down"] += s["dl_bytes"]
                if s["dl_bytes"]:
                    hourly_add(hourly, ip, s["dl_bytes"], time.time())

                # Адрес с персональной скоростью автоограничению не подлежит:
                # решение по нему уже принято человеком.
                if not guard_on or ip in pens or ip in wl:
                    continue

                # счётчики с допуском: короткий провал не обнуляет наблюдение
                both = s["dl"] >= dl_floor and s["ul"] >= ul_floor
                # Крупные пакеты вверх как часть обязательного условия, а не
                # как балл: иначе низкий порог отдачи ловил бы подтверждения
                # обычной закачки, которых тем больше, чем быстрее качают.
                if g.get("require_packet") and s["up_pkt"] < g["packet_bytes"]:
                    both = False
                both_streak[ip] = (both_streak.get(ip, 0) + 1) if both \
                    else max(0, both_streak.get(ip, 0) - 1)
                peak = s["dl"] >= peak_floor
                peak_streak[ip] = (peak_streak.get(ip, 0) + 1) if peak \
                    else max(0, peak_streak.get(ip, 0) - 1)

                score, reasons = evaluate(ip, s, g, cap, both_streak[ip],
                                          peak_streak[ip], daily, hourly)
                if score >= need_score:
                    until = time.time() + g["penalty_min"] * 60
                    penalty_apply(ip, g["penalty_mbps"], until)
                    entry = {"until": until, "mbps": g["penalty_mbps"],
                             "since": time.time(), "source": "watchdog",
                             "kind": "auto", "reason": ",".join(reasons),
                             "score": score, "reasons": reasons}
                    # Ярлык владельца прикрепляем в момент выдачи: позже
                    # человек может отключиться, и связь потеряется.
                    who = owner_of(ip)
                    if who:
                        entry["subject"] = who
                    # Под замком: файл теперь правит ещё и API.
                    penalties_update(lambda p, i=ip, e=entry: p.__setitem__(i, e))
                    pens[ip] = entry
                    log_event("guard_triggered", ip=ip, source="watchdog",
                              mbps=g["penalty_mbps"], minutes=g["penalty_min"],
                              score=score, reason=",".join(reasons),
                              subject=(entry.get("subject") or {}).get("label"),
                              telegram_id=(entry.get("subject") or {}).get("telegram_id"))
                    both_streak[ip] = peak_streak[ip] = 0
                    # Окно очищаем: иначе после снятия штрафа те же гигабайты
                    # в скользящем часе тут же уронили бы человека повторно.
                    hourly.pop(ip, None)
                    print(t("watch_hit", ip=ip, mbps=g["penalty_mbps"],
                            m=g["penalty_min"]) +
                          f" [{score}: {','.join(reasons)}]", flush=True)
                    tg_penalty(cfg, ip, g["penalty_mbps"], g["penalty_min"],
                               reasons, subject=entry.get("subject"))

            if time.time() - last_daily_save > 60:
                # чистим тех, кто за сутки не набрал ничего заметного
                daily = {k: v for k, v in daily.items()
                         if v["active"] > 0 or v["up"] > 1e6 or v.get("down", 0) > 1e6}
                save_daily(daily)
                last_daily_save = time.time()
        except Exception as e:
            print(f"watch: {e}", flush=True)


def whitelist_ips():
    out = set()
    try:
        for line in open(WL_FILE):
            s = line.split("#")[0].strip()
            if s:
                out.add(s)
    except Exception:
        pass
    return out


# ─────────────────────── отправка в Telegram ───────────────────────
# Только stdlib. SOCKS5 реализован здесь же: на российских нодах
# api.telegram.org режется по SNI, и без прокси сообщения не уходят.

def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("прокси закрыл соединение")
        buf += chunk
    return buf


def _socks5(sock, host, port, user=None, pwd=None):
    """Минимальный SOCKS5 CONNECT. Имя хоста резолвит прокси, не мы."""
    sock.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
    ver, method = _recvn(sock, 2)
    if ver != 5:
        raise OSError("это не SOCKS5-прокси")
    if method == 0x02:
        u, p = user.encode(), (pwd or "").encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if _recvn(sock, 2)[1] != 0:
            raise OSError("SOCKS5: неверный логин или пароль")
    elif method != 0x00:
        raise OSError("SOCKS5: прокси требует неподдерживаемую авторизацию")
    h = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big"))
    rep = _recvn(sock, 4)
    if rep[1] != 0:
        codes = {2: "запрещено правилами", 3: "сеть недоступна",
                 4: "хост недоступен", 5: "соединение отклонено"}
        raise OSError(f"SOCKS5: {codes.get(rep[1], f'код {rep[1]}')}")
    atyp = rep[3]
    _recvn(sock, (4 if atyp == 1 else 16 if atyp == 4 else _recvn(sock, 1)[0]) + 2)


def _post(url, data, proxy="", content_type="application/x-www-form-urlencoded"):
    u = urllib.parse.urlsplit(url)
    if proxy.startswith(("socks5://", "socks5h://")):
        p = urllib.parse.urlsplit(proxy)
        sock = socket.create_connection((p.hostname, p.port or 1080), timeout=15)
        try:
            _socks5(sock, u.hostname, 443, p.username, p.password)
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(u.hostname, 443, timeout=15, context=ctx)
            conn.sock = ctx.wrap_socket(sock, server_hostname=u.hostname)
            conn.request("POST", u.path, body=data, headers={
                "Host": u.hostname, "Content-Type": content_type,
                "Content-Length": str(len(data))})
            r = conn.getresponse()
            body = r.read()
            if r.status != 200:
                raise urllib.error.HTTPError(url, r.status, r.reason, r.headers,
                                             io.BytesIO(body))
            return r.status
        finally:
            try:
                sock.close()
            except Exception:
                pass

    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": content_type})
    # Открыватель строим всегда, даже без прокси. Раньше в этой ветке стоял
    # сам модуль urllib.request: у него есть urlopen, но нет open, и отправка
    # без прокси падала на AttributeError. На российских нодах прокси задан
    # всегда, поэтому ветка не выполнялась и ошибка не всплывала до первой
    # ноды, которой прокси не нужен.
    #
    # Пустой ProxyHandler отключает подхват http_proxy из окружения: прокси у
    # Shape свой, в настройках, и брать его откуда-то ещё он не должен.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {}))
    with opener.open(req, timeout=15) as r:
        return r.status


def node_label(tg):
    """
    Подпись ноды для сообщения. Пусто — берём имя хоста.

    Экранируем: сообщения уходят с parse_mode=HTML, и одинокий «<» в подписи
    или в имени хоста заставляет Telegram отвечать 400 «can't parse entities».
    Уведомления после этого молча перестают приходить.
    """
    return html.escape(tg.get("node_name") or os.uname().nodename)


def scrub(text, cfg=None):
    """Убирает токен бота из текста ошибки — журнал читают не только свои."""
    try:
        token = (cfg or {}).get("telegram", {}).get("token", "")
    except Exception:
        token = ""
    s = str(text)
    if token:
        s = s.replace(token, "***")
    # На случай, если токен просочился из другого источника: /bot<цифры>:<...>
    return re.sub(r"(?<=/bot)\d+:[A-Za-z0-9_-]+", "***", s)


def tg_send(text, cfg=None, force=False):
    """Возвращает (успех, пояснение). force — для кнопки «проверить»."""
    tg = (cfg or load_config())["telegram"]
    if not force and not tg.get("enabled"):
        return False, t("tg_off")
    if not tg.get("token") or not tg.get("chat_id"):
        return False, t("tg_no_creds")

    fields = {"chat_id": tg["chat_id"], "text": text,
              "parse_mode": "HTML", "disable_web_page_preview": "true"}
    if str(tg.get("thread_id") or "").strip():
        fields["message_thread_id"] = str(tg["thread_id"]).strip()
    data = urllib.parse.urlencode(fields).encode()
    url = f"https://api.telegram.org/bot{tg['token']}/sendMessage"

    try:
        return _post(url, data, tg.get("proxy", "")) == 200, "ok"
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:200]
        hint = ""
        if e.code in (401, 404):
            hint = "\n  " + t("tg_bad_token")
        elif "chat not found" in body:
            hint = "\n  " + t("tg_bad_chat")
        elif "message thread not found" in body:
            hint = "\n  " + t("tg_bad_thread")
        elif e.code == 403:
            hint = "\n  " + t("tg_forbidden")
        # Текст ошибки уходит в journalctl: токен из него вычищаем.
        return False, scrub(f"HTTP {e.code}: {body}{hint}", {"telegram": tg})
    except Exception as e:
        # Подсказку про прокси даём только на сетевые ошибки. Раньше она
        # висела на любом исключении, и ошибка в самом Shape выглядела как
        # блокировка Telegram — диагностика уходила не туда.
        # OSError покрывает и URLError, и SSLError, и таймаут сокета.
        hint = "" if tg.get("proxy") or not isinstance(e, OSError) \
            else "\n  " + t("tg_need_proxy")
        return False, scrub(f"{e}{hint}", {"telegram": tg})


def tg_penalty(cfg, ip, mbps, minutes, reasons, subject=None):
    """Событие: адрес получил ограничение."""
    tg = cfg["telegram"]
    if not tg.get("enabled") or not tg.get("events"):
        return
    why = ", ".join(t("why_" + r) for r in reasons) or "—"
    lines = [f"🚦 <b>{node_label(tg)}</b>",
             f"{t('tg_limited')} {subject_text(subject, ip)} → {mbps:g} Mbit/s "
             f"{t('guard_for')} {fmt_hold(minutes * 60)}",
             f"<i>{why}</i>"]
    # За одним адресом может сидеть несколько человек — предупреждаем прямо
    # в сообщении, чтобы никто не обвинил не того.
    if subject and subject.get("shared"):
        lines.append(f"<i>{t('tg_shared')}</i>")
    ok, err = tg_send("\n".join(lines), cfg)
    if not ok:
        print(f"telegram: {err}", flush=True)


def digest_text(cfg, day, snapshot, partial=False):
    """Текст сводки. partial — сутки ещё не закончились."""
    tg = cfg["telegram"]
    down = sum(v.get("down", 0) for v in snapshot.values())
    up = sum(v.get("up", 0) for v in snapshot.values())
    top = sorted(snapshot.items(), key=lambda x: -x[1].get("down", 0))[:5]
    head = t("tg_digest_now") if partial else f"{t('tg_digest')} {day}"
    lines = [f"📊 <b>{node_label(tg)}</b> · {head}",
             f"{t('tg_traffic')}: ↓ {fmt_bytes(down)} · ↑ {fmt_bytes(up)}",
             f"{t('tg_addresses')}: {len(snapshot)}"]
    if top:
        lines.append("")
        lines.append(t("tg_top") + ":")
        owners = load_owners()
        for i, (ip, v) in enumerate(top, 1):
            who = owner_of(ip, owners)
            name = html.escape(str(who["label"])) + " · " if who and who.get("label") else ""
            lines.append(f"{i}. {name}<code>{ip}</code> — {fmt_bytes(v.get('down', 0))}")
    return "\n".join(lines)


def parse_hhmm(s, fallback=(9, 0)):
    """'09:30' -> (9, 30). Кривое значение не должно ронять сторожа."""
    try:
        h, m = str(s).strip().split(":")
        h, m = int(h), int(m)
        if 0 <= h <= 23 and 0 <= m <= 59:
            return h, m
    except Exception:
        pass
    return fallback


def digest_stash(day, snapshot):
    """Закрываем сутки: откладываем срез до назначенного часа."""
    if not snapshot:
        return
    tmp = DIGEST_FILE + ".tmp"
    os.makedirs(ETC_DIR, exist_ok=True)
    with open(tmp, "w") as f:
        json.dump({"day": day, "ips": snapshot}, f)
    os.replace(tmp, DIGEST_FILE)


def digest_due(cfg):
    """
    Раз в цикл проверяем, не пора ли отправить отложенную сводку.

    Отправляем не раньше назначенного времени следующих суток. Если нода
    была выключена и момент пропущен больше чем на сутки — сводку роняем,
    позавчерашние цифры никому не нужны.
    """
    try:
        with open(DIGEST_FILE) as f:
            d = json.load(f)
    except Exception:
        return
    tg = cfg["telegram"]
    day, ips = d.get("day", ""), d.get("ips", {})
    h, m = parse_hhmm(tg.get("digest_at", "09:00"))
    try:
        base = time.mktime(time.strptime(day, "%Y-%m-%d"))
    except Exception:
        os.remove(DIGEST_FILE)
        return
    due = base + 86400 + h * 3600 + m * 60
    now = time.time()
    if now < max(due, d.get("retry_at", 0)):
        return
    if now <= due + 86400 and ips and tg.get("enabled") and tg.get("daily"):
        ok, err = tg_send(digest_text(cfg, day, ips), cfg)
        if not ok:
            # связи нет — не долбим API каждые десять секунд
            print(f"telegram: {err}", flush=True)
            d["retry_at"] = now + 900
            with open(DIGEST_FILE, "w") as f:
                json.dump(d, f)
            return
    try:
        os.remove(DIGEST_FILE)
    except OSError:
        pass



# ──────────────── резервная копия в Telegram ────────────────
# Копия, лежащая на том же диске, который однажды умрёт, копией не является.
# Отдельный сервер под 200 килобайт заводить незачем, а Telegram на ноде уже
# настроен — вместе с прокси, который на российских нодах всё равно нужен.
#
# Жёсткое правило: секреты сюда не уходят никогда. Токен бота в чате, куда
# этот же бот пишет, означает, что любой участник темы — сейчас или добавленный
# через полгода — забирает управление ботом и всю переписку разом. Копия с
# токеном существует только как файл на диске, для переноса ноды.

BACKUP_STATE = os.path.join(VAR_DIR, "backup.state")
BACKUP_RETRY = 3600        # связи нет — пробуем через час, а не каждый цикл


def _safe_name(s, fallback="node"):
    """Имя файла без сюрпризов: только буквы, цифры, точка, дефис."""
    s = re.sub(r"[^A-Za-z0-9._-]", "-", str(s))[:40].strip("-.")
    return s or fallback


def _multipart(fields, filename, content, field="document",
               mime="application/json"):
    """
    Собирает multipart/form-data. Возвращает (тело, значение Content-Type).

    Своими руками, потому что весь Shape живёт на стандартной библиотеке, а
    в ней готового сборщика нет. Граница берётся из os.urandom: угадать её и
    подсунуть в имя файла или в подпись свою секцию не выйдет.
    """
    boundary = "----shape" + os.urandom(16).hex()
    out = []
    for k, v in fields.items():
        out.append(f"--{boundary}\r\n"
                   f'Content-Disposition: form-data; name="{k}"\r\n\r\n'
                   f"{v}\r\n".encode())
    out.append(f"--{boundary}\r\n"
               f'Content-Disposition: form-data; name="{field}"; '
               f'filename="{_safe_name(filename, "backup.json")}"\r\n'
               f"Content-Type: {mime}\r\n\r\n".encode())
    out.append(content)
    out.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


def backup_filename(node=None):
    node = _safe_name(node or socket.gethostname())
    return f"shape-{node}-{time.strftime('%Y-%m-%d')}.json"


def tg_backup(cfg=None, force=False):
    """
    Отправляет копию состояния файлом. Возвращает (успех, пояснение).

    force — для кнопки «отправить сейчас»: она работает и когда еженедельная
    отправка выключена, но сам Telegram должен быть настроен.
    """
    cfg = cfg or load_config()
    tg = cfg["telegram"]
    if not force and not (tg.get("enabled") and tg.get("backup")):
        return False, t("bk_tg_off")
    if not tg.get("token") or not tg.get("chat_id"):
        return False, t("tg_no_creds")

    data = build_export(with_secrets=False)
    blob = json.dumps(data, ensure_ascii=False, indent=1).encode()

    # Последняя проверка перед отправкой, а не вера в флаг выше. Если код
    # когда-нибудь поменяют так, что секрет просочится в выгрузку, отправка
    # должна сорваться здесь — а не после того, как токен уже улетел в чат.
    text = blob.decode("utf-8", "replace")
    for section, field in SECRET_PATHS:
        secret = str((cfg.get(section) or {}).get(field) or "")
        if secret and secret in text:
            return False, t("bk_tg_secrets")
    if data.get("secrets_included"):
        return False, t("bk_tg_secrets")

    st = data["state"]
    caption = (f"💾 <b>{node_label(tg)}</b> · {t('bk_tg_caption')}\n"
               f"{t('bk_tg_counts', w=len(st['whitelist']), p=len(st['penalties']), o=len(st['owners']))}\n"
               f"<i>{t('bk_tg_nosec')}</i>")

    fields = {"chat_id": tg["chat_id"], "caption": caption, "parse_mode": "HTML"}
    thread = str(tg.get("backup_thread_id") or tg.get("thread_id") or "").strip()
    if thread:
        fields["message_thread_id"] = thread

    body, ctype = _multipart(fields, backup_filename(data.get("node")), blob)
    url = f"https://api.telegram.org/bot{tg['token']}/sendDocument"
    try:
        return _post(url, body, tg.get("proxy", ""), ctype) == 200, "ok"
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:200]
        return False, scrub(f"HTTP {e.code}: {detail}", {"telegram": tg})
    except Exception as e:
        # Подсказку про прокси даём только на сетевые ошибки. Раньше она
        # висела на любом исключении, и ошибка в самом Shape выглядела как
        # блокировка Telegram — диагностика уходила не туда.
        # OSError покрывает и URLError, и SSLError, и таймаут сокета.
        hint = "" if tg.get("proxy") or not isinstance(e, OSError) \
            else "\n  " + t("tg_need_proxy")
        return False, scrub(f"{e}{hint}", {"telegram": tg})


def backup_due(cfg, now=None):
    """
    Раз в цикл сторожа: не пора ли отправить недельную копию.

    Отправляем в назначенный день недели, не раньше времени сводки, и не
    чаще раза в сутки. Если нода была выключена и день пропущен — ждём
    следующего: догонять пропущенную копию смысла нет, состояние всё равно
    берётся текущее, а не то, что было в понедельник.
    """
    tg = cfg["telegram"]
    if not (tg.get("enabled") and tg.get("backup")):
        return False
    now = now if now is not None else time.time()
    lt = time.localtime(now)
    try:
        want_day = int(tg.get("backup_day", 1))
    except (TypeError, ValueError):
        want_day = 1
    if not 1 <= want_day <= 7:
        want_day = 1
    if lt.tm_wday + 1 != want_day:
        return False

    h, m = parse_hhmm(tg.get("digest_at", "09:00"))
    if (lt.tm_hour, lt.tm_min) < (h, m):
        return False

    today = time.strftime("%Y-%m-%d", lt)
    state = {}
    try:
        with open(BACKUP_STATE) as f:
            state = json.load(f)
        if not isinstance(state, dict):
            state = {}
    except Exception:
        state = {}
    if state.get("last_sent") == today:
        return False
    if now < float(state.get("retry_at") or 0):
        return False

    ok, err = tg_backup(cfg)
    if ok:
        state = {"last_sent": today}
    else:
        # Связи нет — пробуем через час, а не каждые десять секунд.
        print(f"telegram backup: {err}", flush=True)
        state["retry_at"] = now + BACKUP_RETRY
    try:
        os.makedirs(VAR_DIR, exist_ok=True)
        tmp = BACKUP_STATE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp, BACKUP_STATE)
    except OSError:
        pass
    return ok


def cmd_telegram(a):
    cfg = load_config()
    tg = cfg["telegram"]
    if a.action == "show":
        print()
        state = f"{C['grn']}{t('guard_on')}{C['r']}" if tg["enabled"] \
            else f"{C['gry']}{t('guard_off')}{C['r']}"
        print(f"  {t('tg_state')}   : {state}")
        print(f"  {t('tg_node')}    : {node_label(tg)}")
        print(f"  {t('tg_chat')}    : {tg['chat_id'] or '—'}"
              f"{'  · ' + t('tg_thread') + ' ' + str(tg['thread_id']) if tg['thread_id'] else ''}")
        print(f"  {t('tg_proxy')}   : {tg['proxy'] or t('tg_direct')}")
        print(f"  {t('tg_at')}   : {tg.get('digest_at', '09:00')}")
        if tg.get("backup"):
            day = t("dow%d" % max(1, min(7, int(tg.get("backup_day", 1) or 1))))
            extra = ""
            if str(tg.get("backup_thread_id") or "").strip():
                extra = f"  · {t('tg_bk_thread')} {tg['backup_thread_id']}"
            print(f"  {t('tg_bk_state')}   : {C['grn']}"
                  f"{t('tg_bk_when', day=day, at=tg.get('digest_at', '09:00'))}"
                  f"{C['r']}{extra}")
        else:
            print(f"  {t('tg_bk_state')}   : {C['gry']}{t('guard_off')}{C['r']}")
        print()
        return
    if a.action == "test":
        ok, err = tg_send(
            f"🦨 <b>{node_label(tg)}</b>\n{t('tg_test_text')}", cfg, force=True)
        print(f"{C['grn']}✓ {t('tg_sent')}{C['r']}" if ok
              else f"{C['red']}✗ {err}{C['r']}")
        return
    if a.action == "backup":
        ok, err = tg_backup(cfg, force=True)
        print(f"{C['grn']}✓ {t('bk_tg_sent')}{C['r']}" if ok
              else f"{C['red']}✗ {err}{C['r']}")
        return
    if a.action == "digest":
        # Сводка по горячим следам: сторож пишет daily.json раз в минуту.
        snap = load_daily()
        if not snap:
            print(f"{C['gry']}{t('tg_no_data')}{C['r']}")
            return
        ok, err = tg_send(digest_text(cfg, time.strftime("%Y-%m-%d"), snap,
                                      partial=True), cfg, force=True)
        print(f"{C['grn']}✓ {t('tg_sent')}{C['r']}" if ok
              else f"{C['red']}✗ {err}{C['r']}")
        return
    # set
    if a.at is not None:
        v = a.at.strip()
        if parse_hhmm(v, None) is None:
            die(t("tg_bad_time"))
        tg["digest_at"] = "%02d:%02d" % parse_hhmm(v)
    if a.proxy is not None:
        p = a.proxy.strip()
        # MTProto-прокси из ссылки t.me/proxy умеет только протокол мессенджера.
        # Bot API — обычный HTTPS, через такой прокси он не пройдёт.
        if p and ("t.me/proxy" in p or "secret=" in p or p.startswith("tg://")):
            die(t("tg_mtproto") + "\n  " + t("tg_mtproto2") + "\n  " + t("tg_mtproto3"))
        if p and not p.startswith(("socks5://", "socks5h://", "http://", "https://")):
            die(t("tg_proxy_scheme"))
        # Адрес прокси уходит в socket.create_connection и в ProxyHandler.
        # Мусор вместо хоста или порта должен отсекаться здесь, а не всплывать
        # исключением внутри сторожа раз в десять секунд.
        if p:
            try:
                u = urllib.parse.urlsplit(p)
                if not u.hostname or (u.port is not None and not 1 <= u.port <= 65535):
                    raise ValueError
            except ValueError:
                die(t("tg_bad_proxy"))

    # Токен уходит прямо в путь URL: /bot<TOKEN>/sendMessage. Символ «/» или
    # пробел в нём увёл бы запрос на другой метод API, поэтому формат строгий.
    if a.token is not None and a.token.strip() \
            and not re.fullmatch(r"\d{5,}:[A-Za-z0-9_-]{20,}", a.token.strip()):
        die(t("tg_bad_token_fmt"))
    if a.chat is not None and a.chat.strip() \
            and not re.fullmatch(r"-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31}", a.chat.strip()):
        die(t("tg_bad_chat_fmt"))
    if a.thread is not None and a.thread.strip() \
            and not re.fullmatch(r"\d{1,19}", a.thread.strip()):
        die(t("tg_bad_thread_fmt"))
    if a.backup_thread is not None and a.backup_thread.strip() \
            and not re.fullmatch(r"\d{1,19}", a.backup_thread.strip()):
        die(t("tg_bad_thread_fmt"))
    if a.backup_day is not None and not 1 <= a.backup_day <= 7:
        die(t("tg_bad_day"))
    if a.name is not None and len(a.name.strip()) > 64:
        die(t("tg_name_long"))

    for key, val in (("token", a.token), ("chat_id", a.chat), ("thread_id", a.thread),
                     ("node_name", a.name), ("proxy", a.proxy),
                     ("backup_thread_id", a.backup_thread)):
        if val is not None:
            tg[key] = val.strip()
    if a.backup_day is not None:
        tg["backup_day"] = int(a.backup_day)
    if a.backup is not None:
        tg["backup"] = a.backup == "on"
    if a.enable:
        tg["enabled"] = True
    if a.disable:
        tg["enabled"] = False
    if a.events is not None:
        tg["events"] = a.events == "on"
    if a.daily is not None:
        tg["daily"] = a.daily == "on"
    cfg["telegram"] = tg
    save_config(cfg)
    if not a.quiet:
        cmd_telegram(argparse.Namespace(action="show"))


# ────────────────────────────── whitelist ──────────────────────────────

def ip_key(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return ip.packed + b"\x00" * 12 if ip.version == 4 else ip.packed



# ────────────────────────── факты о ноде ──────────────────────────
# Ими пользуются и метрики, и API: имя интерфейса, версия, состояние
# движка и сервисов. Здесь они без кэша — кэширует тот, кому это нужно.

# ────────────── кто эта нода и чем её настройки отличаются ──────────────

def node_id():
    """
    Постоянный идентификатор ноды. Пустая строка, если создать не удалось.

    Зачем вообще: при сотне узлов ноду переносят на другой сервер, меняют ей
    имя хоста и адрес. Всё это ломает привязку метрик к узлу, и годовой
    график превращается в две половины от «разных» нод. Идентификатор живёт
    в /var/lib/shape и переживает и переезд, и переустановку Shape.

    Почему не machine-id: ноды разворачивают из образа, и у клонов он
    одинаковый — то есть ровно в том случае, ради которого всё и затевалось,
    он бы и подвёл.
    """
    try:
        with open(NODE_ID_FILE) as f:
            value = f.read().strip()
        if re.fullmatch(r"[0-9a-f]{16}", value):
            return value
    except OSError:
        pass

    fresh = os.urandom(8).hex()
    try:
        os.makedirs(VAR_DIR, exist_ok=True)
        tmp = NODE_ID_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w") as f:
            f.write(fresh + "\n")
        os.replace(tmp, NODE_ID_FILE)
        return fresh
    except OSError:
        # Записать некуда — например, метрики читают без root, а каталога ещё
        # нет. Возвращать каждый раз новое случайное значение нельзя: в
        # Prometheus это плодило бы новый ряд на каждый замер. Лучше честно
        # признаться, что идентификатора нет.
        return ""


# Поля автоограничения, которые в отпечаток не входят. watch_interval — это
# настройка нагрузки на процессор, а не политики: на слабой VPS его штатно
# поднимают, и держать такую ноду вечно «разъехавшейся» значит приучить себя
# не смотреть на этот показатель вообще.
GUARD_HASH_SKIP = ("watch_interval",)


def config_hash(cfg=None):
    """
    Двенадцать шестнадцатеричных знаков от политики ноды: порты и настройки
    автоограничения.

    Смысл один: при сотне нод кто-нибудь однажды поправит пороги руками на
    одной из них, и узнать об этом будет неоткуда — жалоба придёт через
    месяц. Одинаковый отпечаток означает одинаковую политику, разный виден
    в мониторинге сразу.

    Чего здесь нет намеренно:

      • скорость — она у каждой ноды своя по замыслу, каналы разные. В
        отпечатке она давала бы столько групп, сколько тарифов, и сигнал
        «где-то разъехалось» тонул бы в них. Смотреть её удобнее числом:
        для этого есть отдельная метрика shape_speed_limit_mbps;

      • раздел telegram — подпись ноды и тема там разные по замыслу, и
        отпечаток стал бы уникальным на каждой ноде, то есть бесполезным;

      • watch_interval — см. GUARD_HASH_SKIP.
    """
    cfg = cfg if cfg is not None else load_config()
    guard = cfg.get("guard") or {}
    payload = {
        "ports": sorted(cfg.get("ports") or []),
        "guard": {k: guard[k] for k in sorted(guard) if k not in GUARD_HASH_SKIP},
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()[:12]


def app_dir():
    return os.environ.get("SHAPE_APP_DIR", "/opt/shaper")


def engine_loaded():
    return os.path.exists(map_path("config_map"))


def shape_version():
    try:
        with open(os.path.join(app_dir(), "VERSION")) as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def active_iface():
    try:
        with open(os.path.join(ETC_DIR, ".active_iface")) as f:
            m = re.search(r'IFACE="([A-Za-z0-9._@-]{1,15})"', f.read())
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def systemd_active(unit):
    """Только заранее известные имена юнитов — параметр не приходит извне."""
    if unit not in ("shaper", "shaper-watch", "shape-api"):
        return "unknown"
    try:
        p = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True, timeout=5)
        return p.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def engine_started_at():
    """Когда движок поднялся: из журнала событий, иначе по времени карт."""
    events, _ = read_events(limit=1, etype="engine_started")
    if events:
        return events[0].get("ts")
    try:
        return os.path.getmtime(map_path("config_map"))
    except OSError:
        return None


# ─────────────────────────── метрики Prometheus ───────────────────────────
# Текст собирается здесь, а не в API: без API метрики тоже должны быть
# доступны — через `shaperctl.py metrics` и textfile collector node_exporter.

def _metrics_rate(down_total, up_total):
    """
    Текущая скорость канала по разнице с прошлым замером.

    Замер лежит в файле, а не в памяти процесса: иначе одноразовый запуск
    из CLI никогда бы не смог посчитать скорость. Файл общий, поэтому
    неважно, кто мерил в прошлый раз — API или таймер.
    """
    now = time.time()
    prev = None
    try:
        with open(METRICS_STATE) as f:
            prev = json.load(f)
        if not isinstance(prev, dict):
            prev = None
    except Exception:
        prev = None

    dl = ul = None
    if prev:
        dt = now - float(prev.get("t", 0))
        # Счётчики обнуляются при перезапуске движка: отрицательная разница
        # означает не отрицательную скорость, а новый отсчёт.
        if METRICS_MIN_GAP / 4 <= dt <= METRICS_MAX_GAP \
                and down_total >= prev.get("down", 0) \
                and up_total >= prev.get("up", 0):
            dl = (down_total - prev["down"]) * 8 / 1e6 / dt
            ul = (up_total - prev["up"]) * 8 / 1e6 / dt

    if not prev or now - float(prev.get("t", 0)) >= METRICS_MIN_GAP:
        try:
            os.makedirs(VAR_DIR, exist_ok=True)
            tmp = METRICS_STATE + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            with os.fdopen(fd, "w") as f:
                json.dump({"t": now, "down": down_total, "up": up_total}, f)
            os.replace(tmp, METRICS_STATE)
        except Exception:
            pass
    return dl, ul


def metrics_escape(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def build_metrics(users=None, unit_state=None, started=None, events=None):
    """
    Текст в формате Prometheus.

    Аргументы нужны только API: он держит собственный кэш тяжёлых чтений и
    передаёт готовое. При вызове из CLI всё читается на месте.
    """
    cfg = load_config()
    pens = load_penalties()
    limited = {ip: p for ip, p in pens.items() if not is_personal(p)}
    personal = {ip: p for ip, p in pens.items() if is_personal(p)}
    loaded = engine_loaded()
    node = node_label(cfg["telegram"])
    iface = active_iface() or ""

    # Без root карты не прочитать. Тогда честно поднимаем флаг, а не выдаём
    # нули за правду: «ноль трафика» и «мы не смогли посмотреть» — разные вещи.
    complete = 1
    if users is None:
        if loaded and os.geteuid() != 0:
            users, complete = {}, 0
        else:
            users = read_users() if loaded else {}
    if started is None:
        started = engine_started_at()
    if unit_state is None:
        unit_state = systemd_active("shaper-watch")
    if events is None:
        rows, _ = read_events(limit=1000, since=time.time() - 86400)
        events = {}
        for r in rows:
            key = r.get("type", "unknown")
            events[key] = events.get(key, 0) + 1

    down_total = sum(c["down"] for c in users.values())
    up_total = sum(c["up"] for c in users.values())
    dl, ul = _metrics_rate(down_total, up_total)

    now_ns = mono_ns() if loaded else 0
    active = sum(1 for c in users.values()
                 if c["seen"] and (now_ns - c["seen"]) / NS < 60)

    out = []

    def labels(extra=None):
        pairs = [("node", node)] + sorted((extra or {}).items())
        return "{" + ",".join(f'{k}="{metrics_escape(v)}"' for k, v in pairs) + "}"

    def add(name, kind, help_text, value, extra=None):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        out.append(f"{name}{labels(extra)} {value}")

    def series(name, kind, help_text, rows):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        for extra, value in rows:
            out.append(f"{name}{labels(extra)} {value}")

    add("shape_up", "gauge", "1 if metrics were produced", 1)
    add("shape_metrics_complete", "gauge",
        "1 if BPF maps could be read; 0 means the numbers are incomplete",
        complete)
    # node_id и config_hash живут метками info-метрики, а не отдельными
    # показателями: значение у них строковое, а Prometheus хранит числа.
    # Запрос вида count by (config_hash) (shape_info) сразу показывает,
    # сколько нод разъехалось по политике. Скорость в отпечаток не входит
    # и живёт рядом числом — shape_speed_limit_mbps.
    add("shape_info", "gauge", "Static node information", 1,
        {"version": shape_version(), "metrics_version": METRICS_VERSION,
         "interface": iface, "node_id": node_id(),
         "config_hash": config_hash(cfg)})
    add("shape_engine_loaded", "gauge", "1 if eBPF maps are pinned", int(loaded))
    add("shape_watchdog_active", "gauge", "1 if the watchdog service runs",
        int(unit_state == "active"))
    add("shape_uptime_seconds", "gauge", "Seconds since the engine started",
        round(time.time() - started) if started else 0)
    add("shape_speed_limit_mbps", "gauge", "Shared per-IP limit in Mbit/s",
        f"{cfg['speed_mbps']:g}")
    add("shape_guard_enabled", "gauge", "1 if auto-limiting is on",
        int(bool(cfg["guard"]["enabled"])))

    series("shape_traffic_bytes_total", "counter",
           "Bytes since the engine started",
           [({"direction": "download"}, down_total),
            ({"direction": "upload"}, up_total)])

    if dl is not None:
        series("shape_channel_mbps", "gauge", "Current channel load in Mbit/s",
               [({"direction": "download"}, f"{dl:.3f}"),
                ({"direction": "upload"}, f"{ul:.3f}")])

    add("shape_ips_known", "gauge", "Addresses seen since the engine started",
        len(users))
    add("shape_ips_active", "gauge", "Addresses with traffic in the last minute",
        active)
    add("shape_ips_limited", "gauge", "Addresses under an auto or temporary limit",
        len(limited))
    add("shape_ips_personal", "gauge", "Addresses with a personal speed",
        len(personal))
    add("shape_ips_whitelisted", "gauge", "Addresses on the whitelist",
        len(whitelist_ips()))
    add("shape_owners_known", "gauge", "Addresses with a known owner",
        len(load_owners()))

    series("shape_events_24h", "gauge", "Events written in the last 24 hours",
           [({"type": etype}, events.get(etype, 0))
            for etype in sorted(EVENT_TYPES)])

    hist = read_history(limit=1)
    if hist:
        series("shape_last_day_bytes", "gauge", "Traffic of the last closed day",
               [({"direction": "download"}, hist[-1].get("down", 0)),
                ({"direction": "upload"}, hist[-1].get("up", 0))])

    return "\n".join(out) + "\n"


def cmd_metrics(a):
    """
    Метрики в stdout или в файл для textfile collector node_exporter.

    Запись в файл — обязательно через временный и переименование: иначе
    node_exporter однажды прочитает половину файла и отдаст мусор.
    """
    text = build_metrics()
    if not a.out:
        sys.stdout.write(text)
        return
    path = os.path.abspath(a.out)
    if not path.endswith(".prom"):
        die(t("met_need_prom"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)
    if not a.quiet:
        print(t("met_written", p=path, n=text.count("\n")))


def cmd_history(a):
    rows = read_history(limit=max(1, min(a.days, HISTORY_MAX_DAYS)))
    if a.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return
    if not rows:
        print(f"\n  {C['gry']}{t('hist_none')}{C['r']}\n")
        return
    print(f"\n{C['gry']}  {t('hist_day'):<12}{t('downloaded'):>12}{t('uploaded'):>12}"
          f"{t('total_ips'):>10}{t('hist_limited'):>12}{C['r']}")
    print("  " + "─" * 60)
    for r in rows:
        print(f"  {r['day']:<12}{fmt_bytes(r.get('down', 0)):>12}"
              f"{fmt_bytes(r.get('up', 0)):>12}{r.get('ips', 0):>10}"
              f"{r.get('limited', 0):>12}")
    total = sum(r.get("down", 0) + r.get("up", 0) for r in rows)
    print(f"\n  {C['gry']}{t('hist_total', n=len(rows))}: "
          f"{fmt_bytes(total)}{C['r']}\n")


def cmd_personal(a):
    """Постоянная скорость для адреса — выше или ниже общего лимита."""
    if a.action == "list":
        items = personal_list()
        if a.json:
            print(json.dumps([dict(limit_row(ip, p)) for ip, p in items.items()],
                             ensure_ascii=False, indent=2))
            return
        if not items:
            print(f"\n  {C['gry']}{t('pers_none')}{C['r']}\n")
            return
        print(f"\n{C['gry']}  {'IP':<24}{t('speed'):>12}   {t('lim_why')}{C['r']}")
        print("  " + "─" * 60)
        for ip, p in sorted(items.items()):
            who = (p.get("subject") or {}).get("label") or \
                  (owner_of(ip) or {}).get("label") or ""
            note = p.get("reason") or ""
            tail = " · ".join(x for x in (who, note) if x)
            print(f"  {C['b']}{ip:<24}{C['r']}{p['mbps']:>9g} Mbit/s   "
                  f"{C['gry']}{tail}{C['r']}")
        print()
        return

    ip = valid_ip(a.ip)
    if ip is None:
        die(t("bad_ip", ip=str(a.ip)[:60]))

    if a.action == "del":
        if personal_clear(ip) is None:
            die(t("pers_absent", ip=ip))
        print(f"{C['grn']}✓ {t('pers_removed', ip=ip)}{C['r']}")
        return

    require_engine()
    if a.speed is None:
        die(t("pers_need_speed"))
    if a.speed != a.speed or a.speed in (float("inf"), float("-inf")):
        die(t("neg_speed"))
    if not 0.05 <= a.speed <= MAX_MBPS:
        die(t("pers_range", lo=0.05, hi=MAX_MBPS))
    personal_set(ip, a.speed, a.note or "")
    print(f"{C['grn']}✓ {t('pers_set', ip=ip, s=a.speed)}{C['r']}")


def cmd_owners(a):
    """Кто стоит за адресом. Наполняется вручную или извне через API."""
    if a.action == "list":
        owners = load_owners()
        if a.json:
            print(json.dumps(owners, ensure_ascii=False, indent=2))
            return
        if not owners:
            print(f"\n  {C['gry']}{t('own_none')}{C['r']}\n")
            return
        print()
        for ip, _rec in sorted(owners.items()):
            who = owner_of(ip, owners) or {}
            print(f"  {ip:<24}{who.get('label', '—')}"
                  f"{'  tg:' + str(who['telegram_id']) if who.get('telegram_id') else ''}")
        print()
        return

    ip = valid_ip(a.ip)
    if ip is None:
        die(t("bad_ip", ip=str(a.ip)[:60]))
    if a.action == "del":
        owners_update(lambda o: o.pop(ip, None))
        print(f"{C['grn']}✓ {t('own_removed', ip=ip)}{C['r']}")
        return

    rec = {"updated": round(time.time())}
    if a.label:
        rec["label"] = a.label.strip()[:64]
    if a.user_id:
        rec["user_id"] = a.user_id.strip()[:64]
    if a.telegram_id:
        if not str(a.telegram_id).isdigit():
            die(t("own_bad_tg"))
        rec["telegram_id"] = int(a.telegram_id)
    owners_update(lambda o: o.__setitem__(ip, rec))
    print(f"{C['grn']}✓ {t('own_set', ip=ip)}{C['r']}")


def limit_row(ip, p):
    """Одна запись в машинном виде. Используется и CLI, и API."""
    return {"ip": ip, "mbps": float(p.get("mbps", 0)),
            "kind": p.get("kind", "auto"), "source": p.get("source", "watchdog"),
            "since": p.get("since"), "until": p.get("until"),
            "reason": p.get("reason"), "subject": p.get("subject")}


def cmd_event(a):
    """Записать событие в журнал. Вызывается из engine.sh при старте и стопе."""
    ip = valid_ip(a.ip) if a.ip else None
    log_event(a.type, ip=ip, source=a.source, message=a.message)


def cmd_whitelist(a):
    require_engine()

    if a.action == "add":
        # Проверяем и нормализуем до записи: в файл не должно попасть ничего,
        # кроме адреса. Иначе строка вернётся при sync и будет отвергнута.
        ip = valid_ip(a.ip)
        if ip is None:
            die(t("bad_ip", ip=str(a.ip)[:60]))
        if ip not in whitelist_ips():
            with open(WL_FILE, "a") as f:
                f.write(ip + "\n")
        map_update("whitelist_map", ip_key(ip), b"\x01")
        print(f"{C['grn']}✓ {t('wl_added', ip=ip)}{C['r']}")

    elif a.action == "del":
        ip = valid_ip(a.ip)
        if ip is None:
            die(t("bad_ip", ip=str(a.ip)[:60]))
        if os.path.exists(WL_FILE):
            with open(WL_FILE) as f:
                kept = [l for l in f if valid_ip(l.split("#")[0].strip()) != ip]
            with open(WL_FILE, "w") as f:
                f.writelines(kept)
        map_delete("whitelist_map", ip_key(ip))
        print(f"{C['grn']}✓ {t('wl_removed', ip=ip)}{C['r']}")

    elif a.action == "sync":
        for k, _ in map_dump("whitelist_map"):
            _ip, kb = parse_ip_key(k)
            if kb:
                map_delete("whitelist_map", kb)
        n = 0
        if os.path.exists(WL_FILE):
            for line in open(WL_FILE):
                s = line.split("#")[0].strip()
                if not s:
                    continue
                try:
                    map_update("whitelist_map", ip_key(s), b"\x01")
                    n += 1
                except ValueError:
                    print(f"{C['yel']}⚠ {t('wl_bad', ip=s)}{C['r']}")
        print(t("wl_loaded", n=n))

    elif a.action == "list":
        found = False
        if os.path.exists(WL_FILE):
            for line in open(WL_FILE):
                if line.strip() and not line.startswith("#"):
                    print("  " + line.strip())
                    found = True
        if not found:
            print(f"  {C['gry']}{t('wl_empty')}{C['r']}")


# ─────────────────── резервная копия состояния ноды ───────────────────
# Всё, что делает ноду именно этой нодой, в одном файле: настройки, белый
# список, персональные скорости и действующие ограничения, владельцы
# адресов и суточная история.
#
# Зачем это нужно: перенос ноды на новый сервер, восстановление после
# смерти диска и разворачивание новых нод из готового образца. При сотне
# узлов третье важнее первых двух — руками повторять настройку негде.
#
# Чего здесь нет намеренно:
#   • журнал событий — это лог, а не состояние, и он на четыре мегабайта;
#   • metrics.state — пересчитается сам при первом же замере;
#   • суточные счётчики — переносить половину дня в другой день бессмысленно.

EXPORT_SCHEMA = 1
EXPORT_KIND = "shape-node-state"
EXPORT_SECTIONS = ("config", "whitelist", "penalties", "owners", "history")

# Поля конфига, в которых лежат секреты: токен даёт полный доступ к боту,
# а в строке прокси почти всегда есть пароль. По умолчанию не выгружаются.
SECRET_PATHS = (("telegram", "token"), ("telegram", "proxy"))


def _strip_secrets(cfg):
    """Копия конфига без токена и прокси. Оригинал не трогает."""
    out = json.loads(json.dumps(cfg))
    for section, field in SECRET_PATHS:
        if isinstance(out.get(section), dict) and out[section].get(field):
            out[section][field] = ""
    return out


def build_export(with_secrets=False):
    cfg = load_config()
    if not with_secrets:
        cfg = _strip_secrets(cfg)
    return {
        "kind": EXPORT_KIND,
        "schema": EXPORT_SCHEMA,
        "shape_version": shape_version(),
        "node": socket.gethostname(),
        "exported_at": int(time.time()),
        "exported_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "secrets_included": bool(with_secrets),
        "state": {
            "config": cfg,
            "whitelist": sorted(whitelist_ips()),
            "penalties": load_penalties(),
            "owners": load_owners(),
            "history": read_history(limit=HISTORY_MAX_DAYS),
        },
    }


def cmd_export(a):
    data = build_export(with_secrets=a.with_secrets)
    text = json.dumps(data, ensure_ascii=False, indent=2)

    if a.out in (None, "-"):
        print(text)
        return

    path = os.path.abspath(a.out)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    # Права до записи, а не после: с --with-secrets в файле лежит токен, и
    # окна, в котором он доступен на чтение кому угодно, быть не должно.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text + "\n")
    os.replace(tmp, path)

    st = data["state"]
    print(f"{C['grn']}✓ {t('exp_done', path=path)}{C['r']}")
    print("  " + t("exp_counts", w=len(st["whitelist"]), p=len(st["penalties"]),
                   o=len(st["owners"]), h=len(st["history"])))
    if a.with_secrets:
        print(f"{C['yel']}⚠ {t('exp_secrets')}{C['r']}")
    else:
        print(f"  {C['gry']}{t('exp_no_secrets')}{C['r']}")


def _finite(v):
    """Число или None. nan и inf не проходят, bool тоже не число."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if v != v or v in (float("inf"), float("-inf")):
        return None
    return v


def _clean_like(src, defaults, label, problems):
    """
    Оставляет только знакомые ключи, тип которых совпадает с умолчанием.

    Разделы guard и telegram попадают из файла прямо в load_config(), где
    ложатся поверх умолчаний. Строка вместо числа в пороге сторожа уронила
    бы не импорт, а сторож — через час, в цикле и без внятной причины.
    """
    out = {}
    for key, default in defaults.items():
        if key not in src:
            continue
        val = src[key]
        ok = False
        if isinstance(default, bool):
            ok = isinstance(val, bool)
        elif isinstance(default, (int, float)):
            ok = _finite(val) is not None
        elif isinstance(default, str):
            ok = isinstance(val, str) and len(val) <= 512
        else:
            ok = True
        if ok:
            out[key] = val
        else:
            problems.append(t("imp_bad_field", s=label, k=key))
    unknown = sorted(k for k in src if k not in defaults)
    if unknown:
        problems.append(t("imp_unknown_keys", s=label,
                          k=", ".join(unknown[:5])))
    return out


def validate_export(data):
    """
    Разбирает выгрузку и возвращает (состояние, список замечаний).

    Импорт не доверяет файлу ничего: он мог прийти с чужой ноды, из другой
    версии или быть поправлен руками. Всё, что не проходит те же проверки,
    что и обычный ввод, отбрасывается и попадает в замечания — вместо того
    чтобы уронить команду на середине записи, оставив половину состояния.
    """
    problems = []
    if not isinstance(data, dict):
        die(t("imp_not_object"))
    if data.get("kind") != EXPORT_KIND:
        die(t("imp_not_shape"))
    try:
        schema = int(data.get("schema", 0))
    except (TypeError, ValueError):
        schema = 0
    if schema < 1:
        die(t("imp_no_schema"))
    if schema > EXPORT_SCHEMA:
        die(t("imp_newer", got=schema, ours=EXPORT_SCHEMA))
    raw = data.get("state")
    if not isinstance(raw, dict):
        die(t("imp_no_state"))

    state = {}

    # ── настройки ──
    cfg = raw.get("config")
    if isinstance(cfg, dict):
        clean = {}
        if "speed_mbps" in cfg:
            sp = _finite(cfg["speed_mbps"])
            if sp is None or not 0 <= sp <= MAX_MBPS:
                problems.append(t("imp_bad_speed", v=str(cfg["speed_mbps"])[:40]))
            else:
                clean["speed_mbps"] = float(sp)
        ports = cfg.get("ports")
        if isinstance(ports, list):
            good = []
            for p in ports:
                if isinstance(p, bool) or not isinstance(p, int) \
                        or not 0 <= p <= 65535:
                    problems.append(t("imp_bad_port", v=str(p)[:20]))
                elif p not in good:
                    good.append(p)
            if len(good) > MAX_PORTS:
                problems.append(t("imp_many_ports", n=MAX_PORTS))
                good = good[:MAX_PORTS]
            if good:
                clean["ports"] = good
        elif ports is not None:
            problems.append(t("imp_bad_ports"))
        for name, defaults in (("guard", GUARD_DEFAULT), ("telegram", TG_DEFAULT)):
            sect = cfg.get(name)
            if isinstance(sect, dict):
                clean[name] = _clean_like(sect, defaults, name, problems)
            elif sect is not None:
                problems.append(t("imp_bad_section", s=name))
        state["config"] = clean
    elif cfg is not None:
        problems.append(t("imp_bad_section", s="config"))

    # ── белый список ──
    wl = raw.get("whitelist")
    if isinstance(wl, list):
        good = []
        for item in wl:
            ip = valid_ip(item) if isinstance(item, str) else None
            if ip is None:
                problems.append(t("imp_bad_ip", v=str(item)[:60]))
            elif ip not in good:
                good.append(ip)
        state["whitelist"] = good
    elif wl is not None:
        problems.append(t("imp_bad_section", s="whitelist"))

    # ── ограничения, включая персональные скорости ──
    pens = raw.get("penalties")
    if isinstance(pens, dict):
        good = {}
        for ip_raw, rec in pens.items():
            ip = valid_ip(ip_raw)
            if ip is None:
                problems.append(t("imp_bad_ip", v=str(ip_raw)[:60]))
                continue
            if not isinstance(rec, dict):
                problems.append(t("imp_bad_entry", v=ip))
                continue
            mbps = _finite(rec.get("mbps"))
            until = _finite(rec.get("until"))
            if mbps is None or not 0 < mbps <= MAX_MBPS or until is None:
                problems.append(t("imp_bad_entry", v=ip))
                continue
            entry = {"mbps": float(mbps), "until": float(until)}
            for key in ("since", "kind", "source", "reason", "subject"):
                if rec.get(key) is not None:
                    entry[key] = rec[key]
            good[ip] = entry
        state["penalties"] = good
    elif pens is not None:
        problems.append(t("imp_bad_section", s="penalties"))

    # ── владельцы адресов ──
    owners = raw.get("owners")
    if isinstance(owners, dict):
        good = {}
        for ip_raw, rec in owners.items():
            ip = valid_ip(ip_raw)
            if ip is None:
                problems.append(t("imp_bad_ip", v=str(ip_raw)[:60]))
                continue
            if not isinstance(rec, dict):
                problems.append(t("imp_bad_entry", v=ip))
                continue
            entry = {}
            for key in OWNER_FIELDS:
                val = rec.get(key)
                if val in (None, ""):
                    continue
                entry[key] = str(val)[:200]
            if entry:
                entry["updated"] = int(_finite(rec.get("updated")) or time.time())
                good[ip] = entry
        state["owners"] = good
    elif owners is not None:
        problems.append(t("imp_bad_section", s="owners"))

    # ── суточная история ──
    hist = raw.get("history")
    if isinstance(hist, list):
        good = []
        for rec in hist:
            if isinstance(rec, dict) and isinstance(rec.get("day"), str) \
                    and re.fullmatch(r"\d{4}-\d{2}-\d{2}", rec["day"]):
                good.append(rec)
            else:
                problems.append(t("imp_bad_entry", v=str(rec)[:40]))
        state["history"] = good[-HISTORY_MAX_DAYS:]
    elif hist is not None:
        problems.append(t("imp_bad_section", s="history"))

    return state, problems


def _write_whitelist(ips):
    """Переписывает файл, сохраняя шапку с пояснением от установщика."""
    head = []
    try:
        with open(WL_FILE) as f:
            for line in f:
                if line.lstrip().startswith("#"):
                    head.append(line.rstrip("\n"))
                elif line.strip():
                    break
    except OSError:
        pass
    os.makedirs(ETC_DIR, exist_ok=True)
    tmp = WL_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        for line in head:
            f.write(line + "\n")
        for ip in ips:
            f.write(ip + "\n")
    os.replace(tmp, WL_FILE)


def apply_import(state, only=None, replace_wl=False, keep_secrets=True):
    """
    Пишет разобранное состояние — через штатные функции записи, не в файлы.

    Именно через штатные: в save_config уже есть слияние с диском, в
    penalties_update и owners_update — блокировка файла. Импорт, пишущий
    напрямую, обошёл бы всё, что защищает эти файлы от одновременной
    правки сторожем, и делал бы это ровно в тот момент, когда состояние
    меняется целиком.
    """
    want = set(only or EXPORT_SECTIONS)
    done = {}

    if "config" in want and "config" in state:
        cfg = json.loads(json.dumps(state["config"]))
        if keep_secrets:
            # В файле секретов нет. Затирать пустой строкой то, что на этой
            # ноде уже настроено, нельзя: уведомления молча замолчали бы.
            current = load_config()
            for section, field in SECRET_PATHS:
                incoming = (cfg.get(section) or {}).get(field, "")
                have = (current.get(section) or {}).get(field, "")
                if not incoming and have:
                    cfg.setdefault(section, {})[field] = have
        save_config(cfg)
        done["config"] = 1

    if "whitelist" in want and "whitelist" in state:
        ips = list(state["whitelist"])
        if not replace_wl:
            ips = sorted(set(ips) | whitelist_ips())
        _write_whitelist(ips)
        done["whitelist"] = len(ips)

    if "penalties" in want and "penalties" in state:
        incoming = state["penalties"]
        penalties_update(lambda pens: pens.update(incoming))
        done["penalties"] = len(incoming)

    if "owners" in want and "owners" in state:
        incoming = state["owners"]
        owners_update(lambda ow: ow.update(incoming))
        done["owners"] = len(incoming)

    if "history" in want and "history" in state:
        incoming = state["history"]
        if incoming:
            with file_lock(HISTORY_FILE + ".lock"):
                by_day = {r.get("day"): r for r in read_history(limit=HISTORY_MAX_DAYS)}
                for rec in incoming:
                    by_day[rec["day"]] = rec
                rows = sorted(by_day.values(), key=lambda r: r.get("day", ""))
                rows = rows[-HISTORY_MAX_DAYS:]
                os.makedirs(VAR_DIR, exist_ok=True)
                tmp = HISTORY_FILE + ".tmp"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
                with os.fdopen(fd, "w") as f:
                    for rec in rows:
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                os.replace(tmp, HISTORY_FILE)
        done["history"] = len(incoming)

    return done


def import_to_kernel(done):
    """
    Доводит восстановленное до ядра, если движок сейчас загружен.

    Если не загружен — ничего страшного и ничего не делаем: config.json
    заливается в карты при старте службы, этим занимается cmd_restore.
    """
    if not engine_loaded():
        return False
    if "config" in done:
        write_to_kernel(load_config())
    if "whitelist" in done:
        for k, _ in map_dump("whitelist_map"):
            _ip, kb = parse_ip_key(k)
            if kb:
                map_delete("whitelist_map", kb)
        for ip in whitelist_ips():
            try:
                map_update("whitelist_map", ip_key(ip), b"\x01")
            except ValueError:
                pass
    if "penalties" in done:
        restore_penalties()
    return True


def cmd_import(a):
    try:
        with open(a.file) as f:
            data = json.load(f)
    except OSError as e:
        die(t("imp_no_file", path=str(a.file)[:120], err=e.strerror or ""))
    except ValueError as e:
        die(t("imp_bad_json", err=str(e)[:120]))

    only = None
    if a.only:
        only = [s.strip() for s in a.only.split(",") if s.strip()]
        bad = [s for s in only if s not in EXPORT_SECTIONS]
        if bad:
            die(t("imp_bad_only", s=", ".join(bad),
                  all=", ".join(EXPORT_SECTIONS)))

    state, problems = validate_export(data)
    want = set(only or EXPORT_SECTIONS)

    counts = {"config": len(state.get("config", {})),
              "whitelist": len(state.get("whitelist", [])),
              "penalties": len(state.get("penalties", {})),
              "owners": len(state.get("owners", {})),
              "history": len(state.get("history", []))}

    print()
    print("  " + t("imp_from",
                   node=str(data.get("node", "?"))[:40],
                   v=str(data.get("shape_version", "?"))[:20],
                   when=str(data.get("exported_at_iso", "?"))[:20]))
    if not data.get("secrets_included"):
        print(f"  {C['gry']}{t('imp_no_secrets')}{C['r']}")
    print()

    for name in EXPORT_SECTIONS:
        if name not in state:
            continue
        on = name in want
        col = C["b"] if on else C["gry"]
        flag = t("imp_yes") if on else t("imp_skip")
        print(f"  {col}{t('sec_' + name):<20}{C['r']}"
              f"{counts[name]:>6}   {col}{flag}{C['r']}")

    if problems:
        print()
        for p in problems[:20]:
            print(f"  {C['yel']}⚠ {p}{C['r']}")
        if len(problems) > 20:
            print(f"  {C['yel']}⚠ {t('imp_more_problems', n=len(problems) - 20)}{C['r']}")

    print()
    if a.dry_run:
        print(f"  {C['gry']}{t('imp_dry')}{C['r']}")
        return

    done = apply_import(state, only=only, replace_wl=a.replace,
                        keep_secrets=not data.get("secrets_included"))
    live = import_to_kernel(done)
    log_event("config_changed", source="cli",
              message="import " + ",".join(sorted(done)))
    print(f"{C['grn']}✓ {t('imp_done', s=', '.join(sorted(done)) or '—')}{C['r']}")
    print(f"  {C['gry']}{t('imp_live') if live else t('imp_offline')}{C['r']}")


# ──────────────────────────────── CLI ────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="shaperctl",
        description=t("desc"))
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("apply", help=t("h_apply"))
    a.add_argument("--ports", default=None, help=t("h_ports"))
    a.add_argument("--speed", type=float, default=None,
                   help=t("h_speed"))
    a.add_argument("--quiet", action="store_true")
    a.set_defaults(func=cmd_apply)

    sub.add_parser("show", help=t("h_show")).set_defaults(func=cmd_show)
    sub.add_parser("restore", help=t("h_restore")).set_defaults(func=cmd_restore)

    m = sub.add_parser("monitor", help=t("h_monitor"))
    m.add_argument("--interval", type=int, default=2, help=t("h_interval"))
    m.add_argument("--top", type=int, default=20)
    m.set_defaults(func=cmd_monitor)

    st = sub.add_parser("status", help=t("h_status"))
    st.add_argument("--live", action="store_true", help=t("h_live"))
    st.add_argument("--interval", type=int, default=3)
    st.add_argument("--top", type=int, default=20)
    st.add_argument("--full", action="store_true", help=t("h_full"))
    st.add_argument("--json", action="store_true", help=t("h_json"))
    st.set_defaults(func=cmd_status)

    g = sub.add_parser("guard", help=t("h_guard"))
    g.add_argument("--enable", action="store_true")
    g.add_argument("--disable", action="store_true")
    g.add_argument("--score", type=int, default=None, help=t("h_score"))
    g.add_argument("--both-min", type=int, default=None, help=t("h_both_min"))
    g.add_argument("--both-dl", type=float, default=None, help=t("h_both_dl"))
    g.add_argument("--both-ul", type=float, default=None, help=t("h_both_ul"))
    g.add_argument("--percent", type=float, default=None, help=t("h_percent"))
    g.add_argument("--sustain", type=int, default=None, help=t("h_sustain"))
    g.add_argument("--penalty-mbps", type=float, default=None, help=t("h_pen_mbps"))
    g.add_argument("--penalty-min", type=int, default=None, help=t("h_pen_min"))
    g.add_argument("--hours", type=float, default=None, help=t("h_hours"))
    g.add_argument("--upload-gb", type=float, default=None, help=t("h_upload_gb"))
    g.add_argument("--download-gb", type=float, default=None, help=t("h_download_gb"))
    g.add_argument("--download-gbh", type=float, default=None, help=t("h_download_gbh"))
    g.add_argument("--interval", type=int, default=None, help=t("h_watch_iv"))
    g.add_argument("--packet", type=int, default=None, help=t("h_packet"))
    g.add_argument("--require-packet", dest="require_packet",
                   choices=["on", "off"], default=None, help=t("h_req_packet"))
    g.add_argument("--quiet", action="store_true")
    g.set_defaults(func=cmd_guard)

    sub.add_parser("watch", help=t("h_watch")).set_defaults(func=cmd_watch)

    li = sub.add_parser("limited", help=t("h_limited"))
    li.add_argument("--json", action="store_true", help=t("h_json"))
    li.set_defaults(func=cmd_limited)

    rl = sub.add_parser("release", help=t("h_release"))
    rl.add_argument("ip", nargs="?", default="")
    rl.add_argument("--all", action="store_true")
    rl.set_defaults(func=cmd_release)

    tg = sub.add_parser("telegram", help=t("h_telegram"))
    tg.add_argument("action", choices=["show", "set", "test", "digest", "backup"],
                    nargs="?", default="show")
    tg.add_argument("--at", default=None, help=t("h_tg_at"))
    tg.add_argument("--token", default=None)
    tg.add_argument("--chat", default=None)
    tg.add_argument("--thread", default=None)
    tg.add_argument("--name", default=None, help=t("h_tg_name"))
    tg.add_argument("--proxy", default=None, help=t("h_tg_proxy"))
    tg.add_argument("--enable", action="store_true")
    tg.add_argument("--disable", action="store_true")
    tg.add_argument("--events", choices=["on", "off"], default=None)
    tg.add_argument("--daily", choices=["on", "off"], default=None)
    tg.add_argument("--backup", choices=["on", "off"], default=None,
                    help=t("h_tg_backup"))
    tg.add_argument("--backup-thread", dest="backup_thread", default=None,
                    help=t("h_tg_bk_thread"))
    tg.add_argument("--backup-day", dest="backup_day", type=int, default=None,
                    help=t("h_tg_bk_day"))
    tg.add_argument("--quiet", action="store_true")
    tg.set_defaults(func=cmd_telegram)

    pr = sub.add_parser("personal", help=t("h_personal"))
    pr.add_argument("action", choices=["set", "del", "list"])
    pr.add_argument("ip", nargs="?", default="")
    pr.add_argument("--speed", type=float, default=None, help=t("h_pers_speed"))
    pr.add_argument("--note", default=None)
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(func=cmd_personal)

    ow = sub.add_parser("owners", help=t("h_owners"))
    ow.add_argument("action", choices=["set", "del", "list"])
    ow.add_argument("ip", nargs="?", default="")
    ow.add_argument("--label", default=None)
    ow.add_argument("--user-id", dest="user_id", default=None)
    ow.add_argument("--telegram-id", dest="telegram_id", default=None)
    ow.add_argument("--json", action="store_true")
    ow.set_defaults(func=cmd_owners)

    mt = sub.add_parser("metrics", help=t("h_metrics"))
    mt.add_argument("--out", default=None, help=t("h_met_out"))
    mt.add_argument("--quiet", action="store_true")
    mt.set_defaults(func=cmd_metrics)

    hs = sub.add_parser("history", help=t("h_history"))
    hs.add_argument("--days", type=int, default=30)
    hs.add_argument("--json", action="store_true")
    hs.set_defaults(func=cmd_history)

    ev = sub.add_parser("event", help=t("h_event"))
    ev.add_argument("type", choices=sorted(EVENT_TYPES))
    ev.add_argument("--ip", default=None)
    ev.add_argument("--source", default="cli")
    ev.add_argument("--message", default=None)
    ev.set_defaults(func=cmd_event)

    ex = sub.add_parser("export", help=t("h_export"))
    ex.add_argument("--out", default=None, help=t("h_exp_out"))
    ex.add_argument("--with-secrets", dest="with_secrets", action="store_true",
                    help=t("h_exp_secrets"))
    ex.set_defaults(func=cmd_export)

    im = sub.add_parser("import", help=t("h_import"))
    im.add_argument("file")
    im.add_argument("--dry-run", dest="dry_run", action="store_true",
                    help=t("h_imp_dry"))
    im.add_argument("--only", default=None, help=t("h_imp_only"))
    im.add_argument("--replace", action="store_true", help=t("h_imp_replace"))
    im.set_defaults(func=cmd_import)

    w = sub.add_parser("whitelist", help=t("h_whitelist"))
    w.add_argument("action", choices=["add", "del", "sync", "list"])
    w.add_argument("ip", nargs="?", default="")
    w.set_defaults(func=cmd_whitelist)

    return p


# Команды, которым root не обязателен. Карты BPF без него не прочитать, но
# метрики всё равно стоит отдать: в них есть shape_metrics_complete, по
# которому мониторинг увидит, что цифры неполные. Иначе таймер пришлось бы
# гонять от root ради одного чтения.
NO_ROOT_OK = {"metrics", "history"}


def main():
    args = build_parser().parse_args()
    if os.geteuid() != 0 and args.cmd not in NO_ROOT_OK:
        die(t("root"))
    args.func(args)


if __name__ == "__main__":
    main()
