Учебный проект:Кроссплатформенный менеджер паролей 
Кроссплатформенный менеджер паролей с графическим интерфейсом (Tkinter), локальной зашифрованной базой данных (SQLite) и защищенной работой с буфером обмена.

Архитектура проекта
Приложение построено на модульной архитектуре, разделяющей логику, данные и интерфейс.

```mermaid
flowchart LR
    GUI[GUI Layer<br>src/gui] --> CORE[Core Layer<br>src/core]
    CORE --> DB[Database Layer<br>src/database]
    CORE --> EVT[Event Bus<br>src/core/events.py]
    EVT --> GUI

Ожидания от проекта:
Цель проекта — создать бескомпромиссно защищенное локальное хранилище данных. Основной упор сделан не на облачную синхронизацию, а на максимальную локальную безопасность:
Шифрование AES-256-GCM.
Защита памяти от дампов (обнуление данных).
Автономная работа (No-Cloud).
Контроль целостности через журналы аудита с подписью.

Спринт,Цель
1,"Архитектура и основа: Структура проекта, SQLite, EventBus, GUI-заглушка."
2,"Аутентификация: Hashing (salt+PBKDF2), Key derivation, Login window."
3,Шифрование: Замена XOR заглушек на AES-256-GCM.
4,"Безопасное хранилище: Шифрование записей, разделение метаданных и данных."
5,"Безопасность: Brute-force protection, audit logging."
6,"UX улучшения: Автоблокировка, clipboard timeout."
7,"Тестирование: Unit tests, edge-case testing, code cleanup."
8,"Финальный обзор: Threat modeling, security checklist."


Документация: 
Спринт 1 — Фундамент и База данных
Что сделано:
Архитектура MVC: Разделение логики (core), интерфейса (gui) и данных (database).
Схема БД: Реализована на SQLite. Подготовлены таблицы для записей, настроек и будущего журнала аудита (согласно ДБ-1).
Crypto-Layer: Создан абстрактный класс EncryptionService. На данный момент используется AES256Placeholder (XOR-шифрование) для отладки потоков данных.
GUI Shell: Базовый интерфейс на Tkinter с поддержкой меню и табличного вывода. Реализована "заглушка" мастера настройки.
Система событий: Внедрена шина событий для разделения компонентов (например, обновление таблицы при добавлении записи в БД).

Инструкция по установке:
Клонирование репозитория
Bash

git clone [https://github.com/urkalova-d/cryptosafe-manager.git](https://github.com/urkalova-d/cryptosafe-manager.git)
cd cryptosafe-manager

Настройка окружения
Bash

# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
Установка зависимостей
Bash

pip install -r requirements.txt
Запуск приложения
Bash

python main.py