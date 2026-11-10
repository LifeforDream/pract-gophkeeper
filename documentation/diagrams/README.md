# Диаграммы

Диаграммы последовательностей в формате [PlantUML](https://plantuml.com/).

| Файл | О чём |
|---|---|
| [register.puml](register.puml) | Регистрация: генерация соли, вывод ключей, создание пользователя, сохранение сессии |
| [login.puml](login.puml) | Вход: получение параметров KDF, вывод ключей, проверка `auth_key`, сохранение сессии |

Отрисовка в PNG: `plantuml -tpng documentation/diagrams/*.puml` (или плагин PlantUML в IDE).
