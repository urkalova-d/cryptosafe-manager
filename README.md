# CryptoSafe Manager 

**CryptoSafe Manager** — это кроссплатформенный менеджер паролей с графическим интерфейсом на базе Tkinter. Проект ориентирован на максимальную безопасность: локальная база данных SQLite хранит только зашифрованные данные, а работа с конфиденциальной информацией (например, буфером обмена) строго регламентирована.

##  Цель проекта
Разработать надежное хранилище секретов (паролей, ключей, токенов), обеспечивающее:
 **Конфиденциальность:** хранение данных в зашифрованном виде.
 **Целостность:** защита данных от несанкционированного изменения.
 **Удобство:** интуитивно понятный интерфейс для управления записями.

---

##  Архитектура системы

Проект построен по итеративной модели (8 спринтов). Ниже представлена схема взаимодействия компонентов:



```mermaid
graph TD
    subgraph VIEW [GUI Interface]
        LW[login_window]
        MW[main_window]
        ARW[add_record_window]
        SD[settings_dialog]
    end

    subgraph CONTROLLER [Logic Layer]
        SM[state_manager]
        EV[events]
        AL[audit_logger]
        KM[key_manager]
    end

    subgraph CRYPTO [Security Layer]
        ES[EncryptionService abstract]
        AP[AES256Placeholder]
    end

    subgraph MODEL [Data Layer]
        DB[db.py]
        MOD[models.py]
    end

    VIEW -->|user actions| CONTROLLER
    CONTROLLER -->|encryption requests| CRYPTO
    CRYPTO -->|store and load data| MODEL

## Дорожная карта разработки (Sprints)
 **Sprint 1 — Project Architecture and Setup**
Цель: Создание каркаса и определение архитектуры.

Настройка репозитория и структуры проекта.

Реализация базовых модулей и интерфейсов криптографии.

Подготовка документации и базовых тестов.

Результат: Рабочий модульный каркас приложения.

 **Sprint 2 — Threat Modeling and Security Design**
Цель: Определение угрозов и проектирование защиты.

Анализ моделей атак и выявление уязвимостей.

Разработка Security Architecture.

Документирование Threat Model и требований безопасности.

Результат: Стратегия защиты и подробная модель угроз.



## Структура проекта
Plaintext

cryptosafe-manager
│
├ main.py                   # Точка входа в приложение
├ README.md                 # Документация
├ requirements.txt          # Зависимости проекта
│
├ src
│   ├ core                  # Ядро системы
│   │   ├ audit_logger.py   # Логирование действий
│   │   ├ config.py         # Конфигурация и настройки
│   │   ├ events.py         # Обработка событий
│   │   ├ key_manager.py    # Управление ключами
│   │   ├ state_manager.py  # Состояние приложения
│   │   └ crypto            # Криптографический слой
│   │       ├ abstract.py
│   │       └ placeholder.py
│   │
│   ├ database              # Работа с данными
│   │   ├ db.py             # Подключение и PRAGMA
│   │   └ models.py         # Схемы таблиц (SQL)
│   │
│   └ gui                   # Графический интерфейс (Tkinter)
│       ├ login_window.py
│       ├ main_window.py
│       ├ add_record_window.py
│       └ widgets           # Кастомные компоненты
│
└ tests                     # Тестирование (Pytest)
    ├ test_crypto.py
    ├ test_database.py
    ├ test_integration.py
    └ test_modules.py
 ##Установка и запуск
1. Клонирование репозитория
git clone [https://github.com/urkalova-d/cryptosafe-manager.git](https://github.com/urkalova-d/cryptosafe-manager.git)
cd cryptosafe-manager

2. Создание виртуального окружения
Windows:

python -m venv venv
venv\Scripts\activate
Linux / Mac:

python3 -m venv venv
source venv/bin/activate

3. Установка зависимостей и запуск
pip install -r requirements.txt
python main.py
 Тестирование
Для запуска набора unit-тестов используйте команду:
pytest