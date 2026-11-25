# PDA relay

Ретранслятор для застосунку PDA Network. Через нього телефони обмінюються повідомленнями й мітками.
Ретранслятор нічого не зберігає: маршрути живуть лише в пам'яті, а пакети шифрують і підписують самі телефони,
тож він бачить тільки зашифровані байти.

[English below](#english)

## Свій ретранслятор за 10 хвилин

Знадобиться:

- сервер на Linux із публічною IPv4-адресою, наприклад найдешевший VPS у Hetzner, DigitalOcean чи будь-якого іншого хостера;
- відкриті порти **80** і **443**;
- [Docker із плагіном Compose](https://docs.docker.com/engine/install/);
- ім'я сервера: свій домен із записом A на IP сервера або безкоштовне `IP-адреса.sslip.io`, наприклад `203.0.113.10.sslip.io`.
  Для sslip.io нічого реєструвати не треба.

### 1. Завантаж код

```sh
git clone https://github.com/kaydanko/pda-relay.git
cd pda-relay
```

### 2. Вкажи ім'я сервера

```sh
cp .env.example .env
nano .env   # RELAY_DOMAIN=203.0.113.10.sslip.io
```

### 3. Запусти

```sh
docker compose up -d --build
```

Перша збірка триває кілька хвилин. Caddy сам отримає й оновлюватиме TLS-сертифікат.

### 4. Перевір

```sh
docker compose logs relay
```

У журналі мають бути рядки `PDA_RELAY_V2=enabled` і `PDA_RELAY_V2_TRUST_PROXY=enabled`.
Запит `curl -i https://ТВІЙ_ДОМЕН/` має відповісти `404`: так і має бути, ретранслятор відповідає лише на `/v2/ws`.

### 5. Підключи застосунок

У застосунку відкрий вкладку **PDA → Relay address** і впиши:

```
wss://ТВІЙ_ДОМЕН/v2/ws
```

Можна вписати адресу як основну або як запасну (Fallback relay). Пам'ятай: двоє людей бачать одне одного,
лише якщо підключені до того самого ретранслятора. Тож дай адресу своїм контактам.

### Оновлення й зупинка

```sh
git pull && docker compose up -d --build   # оновити
docker compose down                        # зупинити
```

Перезапуск скидає маршрути в пам'яті. Телефони самі перепідключаться й повторять відправку.

### Без Docker

Збірку з Rust, systemd і nginx або Caddy описано в [DEPLOYMENT.md](DEPLOYMENT.md).
Модель загроз описано в [SECURITY.md](SECURITY.md), протокол у [docs/PROTOCOL.md](docs/PROTOCOL.md).

---

## English

A relay for the PDA Network app: phones exchange messages and map points through it. The relay stores nothing.
Routes live in memory only, and packets are encrypted and signed by the phones, so the relay sees opaque bytes.

### Run your own

You need a Linux server with a public IPv4 address, ports **80** and **443** open, Docker with the Compose plugin,
and a name for the server: your own domain with an A record, or a free `IP.sslip.io` name such as `203.0.113.10.sslip.io`.

```sh
git clone https://github.com/kaydanko/pda-relay.git
cd pda-relay
cp .env.example .env          # set RELAY_DOMAIN
docker compose up -d --build
docker compose logs relay     # expect PDA_RELAY_V2=enabled and PDA_RELAY_V2_TRUST_PROXY=enabled
```

Caddy obtains and renews the TLS certificate. Only `/v2/ws` is served; every other path returns 404.

In the app, open **PDA → Relay address** and enter `wss://YOUR_DOMAIN/v2/ws`, as the main or a fallback relay.
People reach each other only through the same relay, so share the address with your contacts.

Update with `git pull && docker compose up -d --build`, stop with `docker compose down`. A restart drops in-memory
routes; phones reconnect and resend.

Manual builds (Rust, systemd, nginx or Caddy) are in [DEPLOYMENT.md](DEPLOYMENT.md), the threat model is in
[SECURITY.md](SECURITY.md), and the wire protocol is in [docs/PROTOCOL.md](docs/PROTOCOL.md).

### Layout

- `protocol/`: `no_std + alloc` CBOR codec with strict bounds.
- `linux/`: the relay binary (axum/Tokio) and its tests.
- `test-vectors/`: cross-language vectors used by the tests.
- `docker-compose.yml`, `Caddyfile`, `Dockerfile`: the deployment above.

Licensed under MIT or Apache-2.0.
