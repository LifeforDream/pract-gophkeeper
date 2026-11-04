# `register`

Создаёт новый аккаунт на сервере и выполняет вход.

```
gophkeeper [глобальные опции] register [--login <логин>]
```

## Опции

| Флаг | По умолчанию | Значение |
|---|---|---|
| `--login` | *(запрос)* | Логин аккаунта |

## Поведение

1. Берёт логин из `--login` или, если флага нет, запрашивает `Login:`. Если stdin — не терминал,
   `--login` **обязателен**.
2. Берёт пароль из `GOPHKEEPER_PASSWORD` или запрашивает `Password:`, а затем `Confirm password:` (без
   отображения символов). Если два ввода различаются, команда завершается ошибкой `passwords are different`.
3. Выводит ключи локально и отправляет серверу только производный ключ аутентификации, но не пароль.
4. Сохраняет сессию (см. [файл сессии](README.md#файл-сессии)). Вы сразу авторизованы, отдельный `login`
   не нужен.

Если задана `GOPHKEEPER_PASSWORD`, подтверждение пароля не запрашивается.

## Примеры

```sh
gophkeeper register --login alice

# без диалога
GOPHKEEPER_PASSWORD='correct horse battery staple' gophkeeper register --login alice
```

## Ошибки

- `login is taken by another user, please try something else` — выберите другой логин (код 1).
- `passwords are different` — введите пароль заново (код 2).

Помните: восстановления пароля нет (см. [предупреждение](README.md)).

См. также: [`login`](login.md), [`logout`](logout.md).
