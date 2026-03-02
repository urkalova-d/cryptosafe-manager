CryptoSafe Password ManagerКроссплатформенный менеджер паролей с графическим интерфейсом (Tkinter), локальной зашифрованной базой данных (SQLite) и защищенной работой с буфером обмена.Статус: В разработке (Спринт 2)Архитектура проектаПриложение построено на модульной архитектуре, разделяющей логику, данные и интерфейс.Фрагмент кодаflowchart LR
    GUI[GUI Layer<br>src/gui] --> CORE[Core Layer<br>src/core]
    CORE --> DB[Database Layer<br>src/database]
    CORE --> EVT[Event Bus<br>src/core/events.py]
    EVT --> GUI
Ожидания от проектаЦель проекта — создать бескомпромиссно защищенное локальное хранилище данных. Основной упор сделан не на облачную синхронизацию, а на максимальную локальную безопасность:AES-256-GCM шифрование.Защита памяти от дампов (обнуление данных).Автономная работа (No-Cloud).Контроль целостности через журналы аудита с подписью.План разработкиСпринтСтатусЦель1ЗавершеноАрхитектура и основа: Структура проекта, SQLite, EventBus, GUI-заглушка.2В работеАутентификация: Hashing (salt+PBKDF2), Key derivation, Login window.3ОжидаетсяШифрование: Замена XOR заглушек на AES-256-GCM.4ОжидаетсяБезопасное хранилище: Шифрование записей, разделение метаданных и данных.5ОжидаетсяБезопасность: Brute-force protection, audit logging.6ОжидаетсяUX улучшения: Автоблокировка, clipboard timeout.7ОжидаетсяТестирование: Unit tests, edge-case testing, code cleanup.8ОжидаетсяФинальный обзор: Threat modeling, security checklist.Документация спринтовСпринт 1 — Фундамент и База данныхЧто сделано:Архитектура MVC: Разделение логики (core), интерфейса (gui) и данных (database).Схема БД: Реализована на SQLite. Подготовлены таблицы для записей, настроек и будущего журнала аудита.Crypto-Layer: Создан абстрактный класс EncryptionService. Используется AES256Placeholder (XOR-шифрование) для отладки потоков данных.GUI Shell: Базовый интерфейс на Tkinter с поддержкой меню и табличного вывода. Реализована "заглушка" мастера настройки.Система событий: Внедрена шина событий для разделения компонентов.Инструкция по установке1. Клонирование репозиторияBashgit clone https://github.com/urkalova-d/cryptosafe-manager.git
cd cryptosafe-manager
2. Настройка окруженияBash# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
3. Установка зависимостейBashpip install -r requirements.txt
4. Запуск приложенияBashpython main.py
