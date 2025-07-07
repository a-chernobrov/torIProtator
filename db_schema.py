import sqlite3

# Подключаемся к базе данных
conn = sqlite3.connect('ip_database.sqlite')
cursor = conn.cursor()

# Получаем список таблиц
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("Таблицы в базе данных:")
for table in tables:
    print(f"Таблица: {table[0]}")
    # Получаем информацию о столбцах таблицы
    cursor.execute(f"PRAGMA table_info({table[0]})")
    columns = cursor.fetchall()
    for column in columns:
        print(f"  - {column[1]} ({column[2]})")

    # Выведем несколько строк
    cursor.execute(f"SELECT * FROM {table[0]} LIMIT 3")
    rows = cursor.fetchall()
    if rows:
        print(f"  Примеры данных:")
        for row in rows:
            print(f"    {row}")
    print()

# Закрываем соединение
conn.close() 