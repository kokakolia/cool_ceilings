# Локальный Compose Ceilings

Актуально на 24 ноября 2026 года.

## Запуск с нуля

Нужны Docker с Compose и Linux-контейнерами, Python 3.12 или новее и [`mkcert`](https://github.com/FiloSottile/mkcert). На Windows запустите Docker Desktop и дождитесь, пока `docker version` покажет секцию Server.

На машине разработчика откройте файл `hosts` с правами администратора. На Windows это `%SystemRoot%\System32\drivers\etc\hosts`. Добавьте строку:

```text
127.0.0.1 app.ceilings.test mailpit.ceilings.test
```

Если в Windows включён ручной прокси, добавьте `app.ceilings.test` и `mailpit.ceilings.test` в его список исключений. Оба адреса должны открываться напрямую на `127.0.0.1`.

Из корня проекта выполните:

```powershell
python scripts/local.py prepare
python scripts/local.py up
python scripts/local.py compose run --rm --no-deps admin create-first-admin --email admin@example.org
```

`prepare` создаёт секреты и браузерный CA в `~/.ceilings-local` вне проекта, устанавливает доверие к нему для текущего пользователя и выпускает сертификат на оба адреса. Если `mkcert` лежит вне `PATH`, укажите `prepare --mkcert <путь-к-mkcert>`. Если нужен другой каталог данных, перед каждой командой указывайте `python scripts/local.py --directory <внешний-каталог> ...`. При повторном запуске используйте тот же каталог и Compose-проект, поскольку пароли первоначально загружаются в базы при создании их томов.

`ca_password` открывает промежуточный ключ при запуске `step-ca`. `operator_password` открывает отдельный ключ подписи разрешений и монтируется только в `pki-operator`. При переходе со старой конфигурации `up` или `recover` создаёт новый пароль оператора при необходимости и заменяет ключ, который был защищён паролем CA. Существующие корневой и промежуточный ключи CA и тома сохраняются.

`up` собирает образы, готовит ключи JWT, поднимает `step-ca`, готовит внутренние сертификаты и CRL, дожидается PostgreSQL и RabbitMQ, затем выполняет три миграции и поднимает приложения. Auth хранит учётные записи, коды и сессии. Обработчик `noti-codes` сохраняет состояние доставки кода в базе Noti. Команда админа возвращает его ID. Повтор с тем же email возвращает тот же ID, а другой email отклоняется.

Состояние и подключение каждого сервиса к своей БД можно проверить отдельно:

```powershell
python scripts/local.py compose ps
python scripts/local.py compose exec auth python -m ceilings check-db auth
python scripts/local.py compose exec order python -m ceilings check-db order
python scripts/local.py compose exec noti python -m ceilings check-db noti
```

Ожидаются базы `ceilings_auth`, `ceilings_order`, `ceilings_noti`, роль `app_user`, `tls: true` и соответствующие ревизии `auth_002`, `order_001` и `noti_002`. Остановка `python scripts/local.py compose down` сохраняет тома.

## Проверка браузера

1. Откройте `https://app.ceilings.test:8443` и `https://mailpit.ceilings.test:8443` в обычном браузере. Оба адреса должны открыться без предупреждений. При необходимости перезапустите браузер после установки CA.
2. На главной странице запросите код клиента, найдите письмо в Mailpit и введите код. В DevTools у ответа `POST /auth/verify` проверьте две cookie `ceilings_access` и `ceilings_refresh` с `Secure` и `HttpOnly` без `Domain`. Для входа в панель откройте `/admin` и запросите код на email уже созданного админа.
3. В той же сессии откройте Mailpit. В DevTools у запроса документа проверьте, что cookie входа Ceilings отсутствуют в заголовке `Cookie`.
4. Проверьте отклонение неизвестного HTTP-хоста с корректным TLS-именем. Ответ должен быть `421`, а проверка сертификата у `curl` должна оставаться включённой.

```powershell
curl.exe --ssl-revoke-best-effort -i -H "Host: unknown.ceilings.test" https://app.ceilings.test:8443/
```

У системного `curl.exe` с Schannel этот флаг разрешает отсутствие источника данных об отзыве у локального `mkcert`. Проверка цепочки доверия и имени остаётся включённой.

В форме входа можно указать кириллический домен, например `person@пример.рф`. В Mailpit домен получателя будет показан в форме Punycode. Часть адреса до `@` должна состоять из ASCII-символов.

## Ручное обслуживание сертификатов

Команды обновляют один Envoy за раз. На локальном этапе оператор запускает `rekey` до истечения сертификатов и вручную загружает действующий CRL. Статус можно посмотреть с помощью `status` вместо `rekey`. Автоматический запуск и оповещения относятся к приёмке выпуска.

```powershell
python scripts/local.py compose run --rm --no-deps pki-web rekey
python scripts/local.py compose run --rm --no-deps pki-auth rekey
python scripts/local.py compose run --rm --no-deps pki-order rekey
python scripts/local.py compose run --rm --no-deps pki-web crl
python scripts/local.py compose run --rm --no-deps pki-auth crl
python scripts/local.py compose run --rm --no-deps pki-order crl
```

`rekey` выпускает новую пару и публикует её через файловый SDS. После истечения сервисного сертификата `rekey` заменяется первичной выдачей, например `python scripts/local.py compose run --rm --no-deps pki-operator issue auth`. Если истёк корневой CRL, запустите `python scripts/local.py compose up -d ca`, затем `python scripts/local.py compose run --rm --no-deps pki-operator root-crl`. Команда подписывает корневой список и загружает свежий сервисный CRL для трёх Envoy. При аварийном отзыве закрытие существующих соединений выполняют по [процедуре отзыва](first-scenario-design.md#отзыв-сервисного-сертификата-при-утечке-ключа).

Для PostgreSQL и RabbitMQ оператор выдаёт новый комплект через `pki-operator issue <имя-сервиса>` и перезапускает этот сервер. Например:

```powershell
python scripts/local.py compose run --rm --no-deps pki-operator issue pg-auth
python scripts/local.py compose restart pg-auth
python scripts/local.py compose exec auth python -m ceilings check-db auth
```

Другие допустимые имена — `pg-order`, `pg-noti` и `rabbitmq`. При перезапуске том данных сохраняется.

## Запуск после истечения сертификатов

Запустите Docker Desktop. Используйте прежний каталог с секретами и прежнее имя Compose-проекта. Для окружения из прогона добавьте `--directory C:/Users/razun/Documents/Codex/ceilings-stage2` сразу после `scripts/local.py`. Если срок внутренних сертификатов истёк, выполните вручную:

```powershell
python scripts/local.py recover
python scripts/local.py compose ps
python scripts/local.py compose exec auth python -m ceilings check-db auth
```

`recover` останавливает оставшиеся контейнеры, запускает `step-ca` на прежнем томе, выпускает новые сертификаты взамен истёкших и загружает CRL для Envoy. Затем запускает PostgreSQL и RabbitMQ, дожидается их готовности, повторяет миграции и поднимает приложения. Все тома остаются на месте. Проверить запись первого админа можно повтором команды `create-first-admin` с прежним email. Она должна вернуть сохранённый ID и `created: false`.

Если `recover` остановился из-за истёкшего корневого CRL, `step-ca` уже запущен. Выпустите новый корневой список и повторите запуск:

```powershell
python scripts/local.py compose run --rm --no-deps pki-operator root-crl
python scripts/local.py recover
```

Для сертификатов, срок которых ещё не истёк, применяется обычный ручной `rekey` Envoy. Автоматическое расписание и оповещения остаются частью приёмки выпуска.
