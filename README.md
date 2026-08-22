# osclientcerts (fork): PKCS#11-модуль для S/MIME в Thunderbird с непереносимыми ключами Windows

**TL;DR (English):** This is a fork of [mozkeeler/osclientcerts](https://github.com/mozkeeler/osclientcerts) (deprecated upstream) that adds **PKCS#11 `C_Decrypt`/`C_Encrypt` support on Windows** so that **Thunderbird/NSS can perform S/MIME message decryption and encryption using non-exportable private keys stored in Windows CNG** (including hardware-backed keys). Upstream development "moved into Firefox", but Firefox/Thunderbird never shipped a working replacement for S/MIME decryption through OS key stores — so this fork fills that gap. It also builds cleanly with modern Rust toolchains.

## Зачем нужен этот форк

Оригинальный проект `osclientcerts` (автор Dana Keeler / mozkeeler) объявлен устаревшим: «разработка перенесена непосредственно в Firefox». Однако на практике это не так:

* В Mozilla была реализована только **клиентская аутентификация TLS** через системные хранилища сертификатов.
* **Расшифровка S/MIME-сообщений** (операция `C_Decrypt` в терминах PKCS#11) в Thunderbird через Windows CNG **не работает вообще**: встроенные механизмы NSS не умеют использовать непереносимые (non-exportable) приватные ключи из хранилища Windows, а оригинальный `osclientcerts` поддерживал только подписание (`C_Sign`).
* В результате почта, зашифрованная на сертификат, приватный ключ которого хранится в CNG (в том числе в аппаратном токене), не может быть прочитана в Thunderbird.

Этот форк добавляет недостающие операции, оставаясь обычным PKCS#11-модулем, который подключается к Thunderbird как «модуль защиты».

## Что добавлено по сравнению с оригиналом

| Операция PKCS#11 | Статус | Реализация |
|---|---|---|
| `C_SignInit` / `C_Sign` | было | RSA PKCS#1 v1.5 и RSA-PSS (SHA-256 и др. — NSS сам считает хэш), ECDSA через `NCryptSignHash` |
| `C_DecryptInit` / `C_Decrypt` | **новое** | RSA PKCS#1 v1.5 через `NCryptDecrypt` (`NCRYPT_PAD_PKCS1_FLAG`) — расшифровка S/MIME |
| `C_EncryptInit` / `C_Encrypt` | **новое** | RSA PKCS#1 v1.5 через `BCryptEncrypt` с публичным ключом, импортированным из сертификата (`CryptImportPublicKeyInfoEx2`) |

Прочие изменения:

* Совместимость с современными версиями Rust: зависимость `pkcs11` обновлена до 0.5 (типы `BlankPadded*String*`), `addr_of_mut!` вместо `&mut static mut`, bindgen обновлён до 0.72 (`allowlist_*`).
* В `C_GetTokenInfo` теперь выставлены флаги `CKF_SIGN`, `CKF_ENCRYPT`, `CKF_DECRYPT`, чтобы NSS видел возможности токена.
* Расширенное журналирование через `log`/`env_logger`.

Поддерживаются RSA-ключи (для decrypt/encrypt) и RSA/EC-ключи (для подписи). Ключи должны быть доступны через CNG (`NCrypt`); классический CryptoAPI (CAPI) не используется.

## Сборка

### На Windows (нативно)

Требуются Rust (MSVC toolchain) и Visual Studio Build Tools:

```
cargo build --release
```

Результат: `target/release/osclientcerts.dll`.

### Кросс-компиляция из Linux

Используется docker-образ со скрещённым тулчейном (clang/lld-link + MSVC SDK), см. скрипт `build-fork-osclientcerts.sh` в рабочем каталоге проекта (за основу взят образ `mozilla-win-cross-builder`). Итоговый файл копируется в `out/osclientcerts.dll`.

## Установка в Thunderbird

1. Скопируйте `osclientcerts.dll` в постоянное место (путь должен быть стабильным).
2. `Настройки → Конфиденциальность и защита → Управление сертификатами → Устройства защиты` (или `about:preferences#advanced` в старых версиях).
3. Нажмите **Загрузить**, укажите путь к DLL и имя модуля (например, `Windows Certificates`).
4. Сертификаты из хранилища Windows появятся в списке. В настройках аккаунта выберите их для S/MIME подписи и шифрования.

## Отладка

Модуль пишет журнал через `env_logger`. Чтобы увидеть его при запуске Thunderbird из консоли:

```
set RUST_LOG=osclientcerts=debug   (cmd)
$env:RUST_LOG="debug"              (PowerShell)
thunderbird.exe
```

В лог попадают вызовы `C_*`, выбор механизмов, результаты `NCryptDecrypt`/`BCryptEncrypt` и коды ошибок CNG.

## Статус

Проект экспериментальный. Базовая цель — работающая расшифровка S/MIME в Thunderbird с непереносимыми ключами Windows CNG и диагностика проблем через журнал. Возможны ограничения (например, не поддерживаются EC-ключи для расшифрования, multi-part операции `C_EncryptUpdate`/`C_DecryptUpdate` возвращают `CKR_FUNCTION_NOT_SUPPORTED`).

Лицензия — MPL-2.0, как у оригинала.
