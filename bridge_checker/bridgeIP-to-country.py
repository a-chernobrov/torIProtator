import geoip2.database
import subprocess
import sys
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# Количество потоков для параллельной обработки
MAX_WORKERS = 30  # Настрой здесь количество потоков (рекомендуется 20–100)

# Проверяем, передан ли аргумент
if len(sys.argv) != 2:
    print("Использование: python ip_to_country.py <путь_к_файлу_с_мостами>")
    sys.exit(1)

# Путь к файлу с мостами
bridge_file = sys.argv[1]

# Проверяем, существует ли файл
if not os.path.isfile(bridge_file):
    print(f"Ошибка: Файл {bridge_file} не найден.")
    sys.exit(1)

# Читаем строки мостов из файла
try:
    with open(bridge_file, "r") as file:
        bridge_lines = [line.strip() for line in file if line.strip()]
except Exception as e:
    print(f"Ошибка при чтении файла {bridge_file}: {str(e)}")
    sys.exit(1)

# Путь к базе GeoLite2-Country
database_path = "GeoLite2-Country.mmdb"

# Путь к папке bridges
bridges_dir = "bridges"

# Создаем папку bridges, если она не существует
if not os.path.exists(bridges_dir):
    os.makedirs(bridges_dir)

# Открываем базу данных
try:
    reader = geoip2.database.Reader(database_path)
except FileNotFoundError:
    print("Ошибка: Файл GeoLite2-Country.mmdb не найден. Скачайте его с сайта MaxMind.")
    sys.exit(1)

# Регулярное выражение для извлечения IP и порта
bridge_pattern = r"obfs4 (\d+\.\d+\.\d+\.\d+):(\d+)"

# Замок для синхронизации записи в файлы
file_lock = threading.Lock()

# Функция для обработки одного моста
def process_bridge(line):
    try:
        # Извлекаем IP и порт
        match = re.match(bridge_pattern, line)
        if not match:
            return f"Некорректный формат строки: {line}", None
        
        ip, port = match.groups()
        
        # Проверяем живучесть моста
        try:
            result = subprocess.run(
                ["nc", "-zv", ip, port],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                status = "Alive"
            else:
                status = f"Dead - {result.stderr.strip()}"
        except subprocess.TimeoutExpired:
            status = "Dead - Timeout"
        except Exception as e:
            status = f"Error - {str(e)}"
        
        # Если мост жив, определяем страну и сохраняем
        if status == "Alive":
            try:
                response = reader.country(ip)
                country = response.country.name if response.country.name else "Unknown"
                # Очищаем имя страны от недопустимых символов
                country = re.sub(r'[^\w\s-]', '', country).replace(' ', '_')
                
                # Создаем папку для страны
                country_dir = os.path.join(bridges_dir, country)
                with file_lock:
                    if not os.path.exists(country_dir):
                        os.makedirs(country_dir)
                
                # Путь к файлу bridges.txt
                bridge_file_path = os.path.join(country_dir, "bridges.txt")
                
                # Добавляем строку моста в файл (режим append)
                with file_lock:
                    with open(bridge_file_path, "a") as f:
                        f.write(f"{line}\n")
                
                return f"{ip}:{port} : {status}", None
            except geoip2.errors.AddressNotFoundError:
                country = "Unknown"
                country_dir = os.path.join(bridges_dir, country)
                with file_lock:
                    if not os.path.exists(country_dir):
                        os.makedirs(country_dir)
                bridge_file_path = os.path.join(country_dir, "bridges.txt")
                with file_lock:
                    with open(bridge_file_path, "a") as f:
                        f.write(f"{line}\n")
                return f"{ip}:{port} : {status}", None
            except Exception as e:
                return f"{ip}:{port} : Error determining country - {str(e)}", None
        else:
            return f"{ip}:{port} : {status}", None
    
    except Exception as e:
        return f"Ошибка обработки строки {line}: {str(e)}", None

# Параллельная обработка мостов
with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    # Используем tqdm для индикатора прогресса
    results = list(tqdm(executor.map(process_bridge, bridge_lines), total=len(bridge_lines), desc="Обработка мостов"))

# Выводим результаты
for result, _ in results:
    if result:
        print(result)

# Закрываем базу данных
reader.close()
