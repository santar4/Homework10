# FastAPI Проєкт з HTTP Basic Аутентифікацією

Цей FastAPI проєкт демонструє використання HTTP Basic аутентифікації з ролями користувачів.

## Функціонал

- **Аутентифікація:** Перевірка користувачів через HTTP Basic.
- **Доступ за ролями:** Тільки користувачі з роллю `admin` мають доступ до спеціальних маршрутів.

## Маршрути

### Головна сторінка
- **GET /**  
  Переадресація на документацію API за адресою `/docs`.

### Захищені дані
- **GET /secure-data/**
  - Доступно тільки автентифікованим користувачам.
  - **Відповідь:**
    ```json
    {
      "username": "<ім'я користувача>",
      "role": "<роль>"
    }
    ```

### Список користувачів (тільки для адміністраторів)
- **GET /admin/users/**
  - Доступно тільки автентифікованим адміністраторам.
  - **Відповідь:**
    ```json
    {
      "users": ["user1", "admin1"]
    }
    ```

## Як запустити

1. Встановіть залежності:
   ```bash
   pip install -r requirenments
   ```
2. Запустіть додаток:
   ```bash
   python main.py
   ```
3. Перейдіть за адресою [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).


### Очікувані помилки
- **Неавторизовано:** Некоректні облікові дані.
- **Заборонено:** Недостатньо прав.

---
Готово до використання FastAPI додатку!

