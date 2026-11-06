# `delete`

Удаляет секрет.

```
gophkeeper [глобальные опции] delete [--yes] <id|name>
```

Опции должны идти **перед** `<id|name>`.

## Опции

| Флаг | По умолчанию | Значение |
|---|---|---|
| `--yes` | выкл. | Не запрашивать подтверждение |

## Поведение

1. Получает секрет (чтобы опечатка сразу давала `record not found`).
2. Если нет `--yes`, спрашивает `Are you sure you want to delete record <id> - <name>? (y/n):`.
   Подтверждают только `y`, `Y`, `yes` и `YES`; любой другой ответ, включая пустой, печатает
   `Cancelling operation` и завершает команду с кодом 0 без удаления.
3. Удаляет секрет и печатает `successfully deleted record <id>`.

Удалённый секрет пропадает из [`list`](list.md) на всех ваших клиентах. Из CLI удаление отменить нельзя.

В скриптах `--yes` обязателен, если stdin — не терминал и ответ не подан через канал.

## Примеры

```sh
gophkeeper delete github
gophkeeper delete --yes 6f1c0b1e-0000-0000-0000-000000000000
```

## Ошибки

- `record not found`, `id or name X returned multiple values: [...]` (код 1).
- `no record reference provided` — позиционных аргументов не ровно один (код 2).

См. также: [`list`](list.md).
