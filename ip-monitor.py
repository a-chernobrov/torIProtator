import requests
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table

# Список портов твоих Tor-контейнеров
TOR_PORTS = [32781, 32782, 32783, 32784, 32785]

# Интервал между запросами (в секундах)
CHECK_INTERVAL = 30

# URL для получения IP
IP_CHECK_URL = "http://api.ipify.org"

# URL для определения страны по IP
GEOIP_URL = "http://ip-api.com/json/{}"

# Инициализация консоли rich
console = Console()

def get_ip_and_country(socks_port):
    proxies = {
        "http": f"socks5://127.0.0.1:{socks_port}",
        "https": f"socks5://127.0.0.1:{socks_port}"
    }
    try:
        # Принудительно создаём новую сессию для каждого запроса
        with requests.Session() as session:
            session.proxies = proxies
            response = session.get(IP_CHECK_URL, timeout=5)
            if response.status_code != 200:
                return None, None
            ip = response.text.strip()

            geo_response = session.get(GEOIP_URL.format(ip), timeout=5)
            if geo_response.status_code != 200:
                return ip, "Unknown"
            geo_data = geo_response.json()
            country = geo_data.get("country", "Unknown")
            return ip, country
    except Exception:
        return None, None

def create_table(data):
    table = Table(title="Мониторинг IP-адресов Tor-контейнеров", show_lines=True)
    table.add_column("Время", style="cyan")
    table.add_column("Порт", style="magenta")
    table.add_column("IP", style="green")
    table.add_column("Страна", style="yellow")
    table.add_column("Статус", style="blue")

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for port, (ip, country, status) in data.items():
        ip_str = ip if ip else "Ошибка"
        country_str = country if country else "-"
        table.add_row(current_time, str(port), ip_str, country_str, status)

    return table

def main():
    last_ips = {port: None for port in TOR_PORTS}
    console.print("[bold green]Запуск мониторинга IP-адресов...[/bold green]")
    console.print(f"Проверка каждые {CHECK_INTERVAL} секунд. Нажмите Ctrl+C для выхода.\n")

    while True:
        data = {}

        # Получаем IP и страну для каждого порта
        for port in TOR_PORTS:
            ip, country = get_ip_and_country(port)
            status = "Ошибка"
            if ip:
                if last_ips[port] != ip:
                    if last_ips[port] is None:
                        status = "Новый"
                    else:
                        status = "Изменился"
                    last_ips[port] = ip
                else:
                    status = "Без изменений"
            data[port] = (ip, country, status)

        # Очищаем экран и выводим таблицу
        console.clear()
        table = create_table(data)
        console.print(table)

        # Ожидание до следующей проверки с отсчётом
        with console.status("[bold white]Следующая проверка...[/bold white]") as status:
            for remaining in range(CHECK_INTERVAL, 0, -1):
                status.update(f"[bold white]Следующая проверка через: {remaining} сек[/bold white]")
                time.sleep(1)
        console.print("\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Остановлено пользователем.[/bold red]")
