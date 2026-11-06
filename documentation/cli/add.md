# `add`

Добавляет новый секрет.

```
gophkeeper [глобальные опции] add <тип> --name <имя> [--meta k=v]... [--file <путь>]
```

`<тип>` — один из `login`, `text`, `binary`, `card`; он должен идти **первым**, до флагов.

## Опции

| Флаг | Обязателен | Значение |
|---|---|---|
| `--name` | да | Имя секрета. Имена не обязаны быть уникальными, но поиск по `<id\|name>` работает только с уникальными. |
| `--meta k=v` | нет | Пара метаданных. Для нескольких пар повторите флаг. Значение может быть пустым (`k=`), ключ — нет. |
| `--file` | только для `binary` | Путь к сохраняемому файлу. Для других типов игнорируется. |

## Поведение по типам

Всё, кроме флагов, запрашивается интерактивно (приглашения идут в stderr). При скрытом вводе символы не
отображаются.

| Тип | Запросы |
|---|---|
| `login` | `Login:`, затем `Password:` (скрытый) |
| `text` | `Your text:` — **одна строка** |
| `binary` | нет; файл читается из `--file` и сохраняется под своим базовым именем |
| `card` | `Number:` (скрытый), `Holder:`, `Expiry:`, `CVV:` (скрытый) |

При успехе печатает `record <имя> added with id <uuid>`. Сохраните id для скриптов или позже обращайтесь по
имени.

Содержимое шифруется на вашем компьютере до отправки. Файл больше лимита в 1 МиБ отклоняется с ошибкой
`record size is bigger than limits, …`.

Если stdin — канал, приглашения читают последовательные строки из него:

```sh
printf 'alice\nhunter2\n' | gophkeeper add login --name github
```

## Примеры

```sh
gophkeeper add login  --name github --meta url=https://github.com --meta 2fa=totp
gophkeeper add text   --name wifi-note
gophkeeper add binary --name ssh-key --file ~/.ssh/id_ed25519
gophkeeper add card   --name visa --meta bank=acme
```

## Ошибки (код 2, если не указано иное)

- `missing type argument` — после `add` ничего нет.
- `unknown secret type: X`.
- `empty secret name is not allowed`.
- `binary add requires valid --file`.
- `invalid meta "X", expected key=value`.
- Нечитаемый `--file` — код 1.

См. также: [`get`](get.md), [`update`](update.md).
