# amavis-milter

Milter-модуль для amavisd на Python 3.10, выполняющий спам-анализ по следующим критериям:

1. **Возраст домена отправителя** — WHOIS-запрос к `whois.nic.ru`, срабатывание при возрасте домена ниже порога
2. **Ложный ответ** — наличие префикса `Re:`/`Fw:` в теме при отсутствии валидного заголовка `In-Reply-To` или `References`
3. **Fuzzy-анализ домена** — определение похожести домена отправителя на известные/ранее встречавшиеся домены (typosquatting)

## Архитектура

```
amavis_milter/
├── __init__.py          # Пакет
├── __main__.py          # Точка входа CLI
├── config.py            # Загрузчик TOML-конфигурации
├── engine.py            # Движок правил и групп
├── milter.py            # Milter-демон (протокол MTA)
├── whois_client.py      # Асинхронный WHOIS-клиент для whois.nic.ru
└── checks/
    ├── __init__.py
    ├── base.py           # Базовый класс проверки
    ├── domain_age.py     # Проверка возраста домена
    ├── false_reply.py    # Проверка ложного ответа
    └── fuzzy_domain.py   # Fuzzy-анализ домена
```

## Установка

```bash
cd mini-services/amavis-milter
pip install -r requirements.txt
```

## Запуск

```bash
python -m amavis_milter config.toml
# или
amavis-milter config.toml
```

## Конфигурация

Все настройки хранятся в `config.toml`. См. подробные комментарии в файле `config.toml`.

### Триггеры

Каждый триггер определяет:
- `type` — тип проверки (`domain_age`, `false_reply`, `fuzzy_domain`)
- `enabled` — включён/выключен
- `params` — параметры конкретной проверки
- `action` — действия при срабатывании:
  - `header_name` / `header_value` — добавляемый X-header
  - `spam_score_increase` — величина увеличения спам-балла
  - `subject_prefix` — опциональный префикс в теме письма

### Группы (комбинированные правила)

Группы объединяют несколько триггеров и срабатывают по условию:
- `mode = "all"` — все перечисленные триггеры должны сработать
- `mode = "any"` — хотя бы один триггер должен сработать
- `mode = "majority"` — больше половины триггеров должны сработать

Действия группы применяются **дополнительно** к индивидуальным действиям триггеров.

## Интеграция с amavisd

В `amavisd.conf`:

```perl
# Включить milter-подключение
$interface_policy{'8899'} = 'AMAVIS-MILTER';
$policy_bank{'AMAVIS-MILTER'} = {
    protocol => 'AM.PDP',
    inet_acl => [qw(127.0.0.1)],
};
```

В Postfix `main.cf`:

```
smtpd_milters = inet:127.0.0.1:8899
milter_default_action = accept
```

## Пример расчёта спам-балла

Письмо с молодым доменом (5 дней) и `Re:` без `In-Reply-To`:

| Правило                    | Спам-балл |
|---------------------------|-----------|
| domain_age_young          | +3.0      |
| false_reply               | +2.5      |
| Группа young+fake_reply   | +5.0      |
| Группа any_suspicious     | +1.0      |
| Группа majority_suspicious| +8.0      |
| **Итого**                 | **+19.5** |

## Зависимости

- `Milter` — Python milter интерфейс (libmilter)
- `tomli` — TOML-парсер для Python 3.10
- `levenshtein` — быстрая функция расстояния Левенштейна (опционально, fallback на difflib)
