import logging
import sys
import time
import os
import requests
import pycountry
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.layout import Layout

# Настройка логирования (только в файл, без вывода в консоль)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("exit_nodes_speed_api.log")
    ]
)
logger = logging.getLogger(__name__)

# Инициализация rich консоли
console = Console()

# API для получения данных об узлах Tor
ONIONOO_URL = "https://onionoo.torproject.org/details?type=relay&running=true"

# Интервал обновления (в секундах)
UPDATE_INTERVAL = 300  # 5 минут

def get_nodes_by_country():
    """Получает список узлов через API Onionoo, группирует по странам."""
    try:
        response = requests.get(ONIONOO_URL, timeout=10)
        if response.status_code != 200:
            logger.error(f"Не удалось получить данные от Onionoo: {response.status_code}")
            return {}

        data = response.json()
        logger.info(f"Получено {len(data.get('relays', []))} узлов от Onionoo API")

        # Группируем узлы по странам: отдельно все релеи и отдельно выходные
        nodes_by_country = {}
        for relay in data.get("relays", []):
            country_code = relay.get("country", "unknown").lower()
            if country_code not in nodes_by_country:
                nodes_by_country[country_code] = {"all_nodes": 0, "exit_nodes": [], "speeds": []}
            
            # Считаем общее количество узлов
            nodes_by_country[country_code]["all_nodes"] += 1

            # Проверяем, является ли узел выходным
            flags = relay.get("flags", [])
            if "Exit" in flags and "BadExit" not in flags:
                nodes_by_country[country_code]["exit_nodes"].append({
                    "nickname": relay.get("nickname", "Unnamed"),
                    "fingerprint": relay.get("fingerprint"),
                    "observed_bandwidth": relay.get("observed_bandwidth", 0)
                })
                # Сохраняем скорость узла (в байтах/с)
                if relay.get("observed_bandwidth"):
                    nodes_by_country[country_code]["speeds"].append(relay.get("observed_bandwidth"))

        logger.info(f"Найдено {sum(len(country['exit_nodes']) for country in nodes_by_country.values())} выходных узлов")
        for country, info in nodes_by_country.items():
            logger.info(f"Страна {country.upper()}: {info['all_nodes']} релеев, {len(info['exit_nodes'])} выходных узлов")
        return nodes_by_country

    except Exception as e:
        logger.error(f"Ошибка получения данных от Onionoo: {e}")
        return {}

def get_country_name(country_code):
    """Возвращает полное название страны по её коду."""
    if country_code == "unknown":
        return "Unknown"
    try:
        country = pycountry.countries.get(alpha_2=country_code.upper())
        return country.name if country else country_code.upper()
    except Exception as e:
        logger.warning(f"Не удалось определить название страны для кода {country_code}: {e}")
        return country_code.upper()

def create_table(data, start_idx, end_idx, target_height):
    """Создаёт таблицу с данными о странах и узлах для заданного диапазона строк."""
    table = Table(show_edge=True, header_style="bold magenta", border_style="yellow")

    # Определяем столбцы таблицы
    table.add_column("Код страны", justify="center")
    table.add_column("Название страны", justify="left")
    table.add_column("Релеи", justify="center")
    table.add_column("Выходные узлы", justify="center")
    table.add_column("Скорость (МБ/с)", justify="center")

    # Добавляем строки в таблицу с цветами
    for i in range(start_idx, end_idx):
        row = data[i]
        if i < 3:  # Топ-3 — зелёный
            style = "bold green"
        elif i < 6:  # Следующие 3 — жёлтый
            style = "bold yellow"
        else:
            style = None
        table.add_row(
            str(row[0]),
            str(row[1]),
            str(row[2]),
            str(row[3]),
            str(row[4]),
            style=style
        )

    # Добавляем пустые строки, чтобы выровнять высоту таблицы
    current_rows = end_idx - start_idx
    if current_rows < target_height:
        for _ in range(target_height - current_rows):
            table.add_row("", "", "", "", "")

    return table

def create_split_tables(nodes_by_country):
    """Создаёт две таблицы, разделяя данные пополам."""
    # Подготовка данных для таблицы
    table_data = []
    for country_code, info in nodes_by_country.items():
        # Пропускаем, если нет выходных узлов
        if not info["exit_nodes"]:
            continue

        # Вычисляем среднюю скорость для выходных узлов (в МБ/с)
        if info["speeds"]:
            avg_speed_bps = sum(info["speeds"]) / len(info["speeds"])  # Средняя скорость в байтах в секунду
            avg_speed_mbps = avg_speed_bps / 1_000_000  # Переводим в МБ/с
            avg_speed_mbps = round(avg_speed_mbps, 2)
        else:
            avg_speed_mbps = "N/A"

        # Добавляем данные в список для сортировки
        table_data.append([
            country_code.upper(),
            get_country_name(country_code),
            info["all_nodes"],
            len(info["exit_nodes"]),
            avg_speed_mbps
        ])

    # Сортируем по количеству выходных узлов (4-й столбец, индекс 3) по убыванию
    table_data.sort(key=lambda x: x[3], reverse=True)

    # Делим данные пополам
    total_rows = len(table_data)
    mid_point = total_rows // 2

    # Определяем максимальную высоту таблицы (для выравнивания)
    target_height = max(mid_point, total_rows - mid_point)

    # Создаём две таблицы
    table1 = create_table(table_data, 0, mid_point, target_height)
    table2 = create_table(table_data, mid_point, total_rows, target_height)

    return table1, table2

def main():
    try:
        console.print("[bold green]Запуск мониторинга выходных узлов Tor...[/bold green]")
        console.print(f"Обновление каждые {UPDATE_INTERVAL} секунд. Нажмите Ctrl+C для выхода.\n")

        while True:
            # Получаем данные
            logger.info("Получение списка узлов через API...")
            nodes_by_country = get_nodes_by_country()
            table1, table2 = create_split_tables(nodes_by_country)

            # Создаём layout для отображения двух таблиц
            layout = Layout()
            layout.split_row(
                Layout(name="left", minimum_size=50),
                Layout(name="right", minimum_size=50)
            )
            layout["left"].update(table1)
            layout["right"].update(table2)

            # Очищаем экран и выводим таблицы
            console.clear()
            console.print(layout)

            # Ожидание до следующего обновления с отсчётом
            with console.status("[bold white]Следующее обновление...[/bold white]") as status:
                for remaining in range(UPDATE_INTERVAL, 0, -1):
                    status.update(f"[bold white]Следующее обновление через: {remaining} сек[/bold white]")
                    time.sleep(1)
            console.print()

    except KeyboardInterrupt:
        console.print("\n[bold red]Остановлено пользователем.[/bold red]")
        logger.info("Скрипт остановлен пользователем")
    except Exception as e:
        console.print(f"\n[bold red]Произошла ошибка: {e}[/bold red]")
        logger.error(f"Неожиданная ошибка: {e}")

if __name__ == "__main__":
    main()