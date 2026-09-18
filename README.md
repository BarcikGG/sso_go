# SSO для Octopus и других веб-приложений

SSO хранит общий аккаунт, профиль и доступы к проектам. Каждый проект создаёт собственную сессию после OIDC-входа и хранит локальную копию пользователей и ролей. Общие страницы регистрации, входа и центральной админки обслуживает отдельный фронтенд.

Интерфейс находится в отдельном проекте [`../sso_frontend`](../sso_frontend): React/Vite и Nginx. Go-сервис отдаёт OIDC и JSON API, а внешний адрес `localhost:8080` обслуживает фронтенд-прокси. Страницы и стили больше не лежат в Go-пакете.

**Начать здесь:** [как работает SSO и как подключить новое приложение](docs/integration.ru.md). [Целевая схема Octopus и конструктора](docs/target-architecture.ru.md) объясняет принятые продуктовые решения.

[Архитектура кода](docs/code-architecture.ru.md) показывает границы HTTP/gRPC, сервисов и репозитория и правила добавления новых сценариев.

Локальный запуск из корня рабочего каталога:

```sh
docker compose up --wait -d --build
```

- SSO: <http://localhost:8080/register> и <http://localhost:8080/login>.
- Центральная админка: <http://localhost:8080/admin>.
- Пилотное приложение: <http://localhost:8081>.
- Письма Mailpit: <http://localhost:8025>.

Локальный глобальный администратор: `admin@example.local`, пароль из `SSO_ADMIN_PASSWORD` (значение по умолчанию в Compose только для разработки). Новый пользователь подтверждает email, затем администратор активирует аккаунт и назначает роль проекту. Пароль можно изменить в `/settings/password` или восстановить через `/password/forgot`.

SSO использует отдельную PostgreSQL БД и версионированные миграции. Клиенты регистрируются с точными redirect URI; Authorization Code требует PKCE S256. Access JWT живёт пять минут, содержит аудиторию одного проекта и подписан RS256. Открытые ключи доступны через JWKS. Новый Go API Octopus подключён через OIDC и `/sync/snapshot` + `/sync/changes`. Kafka и gRPC остаются в SSO для других интеграций.

Проверка из корня рабочего каталога:

```sh
(cd sso && go test ./...)
(cd octopus_api && go test ./...)
python3 scripts/smoke.py
python3 scripts/sso_identity.py
python3 scripts/recovery.py
python3 scripts/key_rotation.py
```

Браузерный сценарий `scripts/browser.py` запускается в CI с Playwright. Перед боевым запуском прочитайте раздел ограничений и требований к эксплуатации в [инструкции](docs/integration.ru.md#перед-боевым-развёртыванием).
