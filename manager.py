import json
import time
import threading
import logging
import sys
import requests
import socket
import os
import geoip2.database
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, render_template, request, jsonify
from stem.control import Controller
import stem
import docker
import socks
import tempfile
import tarfile
import io

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/app/manager.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

logger.info(f"Используемая версия stem: {stem.__version__}")

app = Flask(__name__, static_folder='static')

CONFIG_PATH = "/app/config.json"
config = {}
tor_containers = []
last_config_mtime = 0
controllers = {}
last_circuits = {}
last_ips = {}
node_locations = {}

TOR_CONTROL_PASSWORD = "mypassword"

client = docker.DockerClient(base_url='unix://var/run/docker.sock')

def create_default_config():
    default_config = {
        "tor_containers": {
            "my-tor-ip-changer-tor-1": {
                "socks_port": 9050,
                "control_port": 9051,
                "exclude_exit_countries": ["ru", "cn"],
                "exit_nodes": ["us"],
                "circuit_change_interval": 300
            },
            "my-tor-ip-changer-tor-2": {
                "socks_port": 9050,
                "control_port": 9051,
                "exclude_exit_countries": ["ru", "cn"],
                "exit_nodes": ["de"],
                "circuit_change_interval": 300
            },
            "my-tor-ip-changer-tor-3": {
                "socks_port": 9050,
                "control_port": 9051,
                "exclude_exit_countries": ["ru", "cn"],
                "exit_nodes": ["uk"],
                "circuit_change_interval": 300
            }
        }
    }
    with open(CONFIG_PATH, 'w') as f:
        json.dump(default_config, f, indent=2)
    logger.info(f"Создан файл конфигурации по умолчанию: {CONFIG_PATH}")
    return default_config

def load_config():
    global config, last_config_mtime
    if not os.path.isfile(CONFIG_PATH):
        logger.warning(f"Файл {CONFIG_PATH} отсутствует или не является файлом. Создаём файл по умолчанию.")
        config = create_default_config()
    else:
        try:
            with open(CONFIG_PATH, 'r') as f:
                new_config = json.load(f)
                config = new_config
                logger.info("Конфигурация загружена.")
                stat = os.stat(CONFIG_PATH)
                last_config_mtime = stat.st_mtime
        except Exception as e:
            logger.error(f"Ошибка загрузки конфигурации: {e}. Создаём файл по умолчанию.")
            config = create_default_config()

def check_port(host, port, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        sock.close()

def get_controller(control_host, control_port):
    key = f"{control_host}:{control_port}"
    if key in controllers and controllers[key].is_alive():
        return controllers[key]
    
    try:
        controller = Controller.from_port(address=control_host, port=control_port)
        controller.authenticate(password=TOR_CONTROL_PASSWORD)
        controllers[key] = controller
        logger.info(f"Создано новое соединение с {control_host}:{control_port}")
        return controller
    except Exception as e:
        logger.error(f"Не удалось создать Controller для {control_host}:{control_port}: {e}")
        return None

def wait_for_tor_ready(container_name, control_host, control_port, retries=20, delay=15, max_stuck_time=180):
    last_progress = 0
    stuck_since = None
    
    for attempt in range(retries):
        if not check_port(control_host, control_port, timeout=2):
            logger.warning(f"Порт {control_port} на {control_host} недоступен, попытка {attempt + 1}/{retries}")
            time.sleep(delay)
            continue
        controller = get_controller(control_host, control_port)
        if not controller:
            time.sleep(delay)
            continue
        try:
            response = controller.get_info("status/bootstrap-phase")
            logger.info(f"Tor bootstrap response: {response}")
            
            # Извлекаем текущий прогресс
            current_progress = 0
            if "PROGRESS=" in response:
                progress_part = response.split("PROGRESS=")[1].split(" ")[0]
                try:
                    current_progress = int(progress_part)
                except ValueError:
                    pass
            
            if "PROGRESS=100" in response:
                logger.info(f"Tor на {control_host}:{control_port} готов.")
                return True
            else:
                logger.info(f"Tor на {control_host}:{control_port} ещё не готов: {response}")
                
                # Проверяем, застрял ли прогресс
                if current_progress == last_progress:
                    if stuck_since is None:
                        stuck_since = time.time()
                    elif time.time() - stuck_since > max_stuck_time:
                        # Если застрял больше max_stuck_time секунд, перезапускаем контейнер
                        logger.warning(f"Tor на {control_host}:{control_port} застрял на {current_progress}% более {max_stuck_time} секунд. Перезапуск контейнера...")
                        try:
                            container = client.containers.get(container_name)
                            container.restart(timeout=30)
                            logger.info(f"Контейнер {container_name} перезапущен.")
                            # Сбрасываем счетчик застревания и даем контейнеру время на перезапуск
                            stuck_since = None
                            time.sleep(30)  # Ждем, пока контейнер перезапустится
                        except Exception as restart_error:
                            logger.error(f"Ошибка при перезапуске контейнера {container_name}: {restart_error}")
                else:
                    # Если прогресс изменился, сбрасываем счетчик застревания
                    stuck_since = None
                    last_progress = current_progress
                
        except Exception as e:
            logger.warning(f"Ошибка проверки готовности Tor на {control_host}:{control_port}: {e}")
        time.sleep(delay)
    logger.error(f"Tor на {control_host}:{control_port} не готов после {retries} попыток.")
    return False

def write_torrc_with_bridges(container_info, config):
    """Генерирует torrc с мостами и копирует в контейнер."""
    bridges = config.get('bridges', [])
    name = container_info['name']
    base_torrc = [
        f"SocksPort 0.0.0.0:{config.get('socks_port', 9050)}",
        f"ControlPort 0.0.0.0:{config.get('control_port', 9051)}",
        "HashedControlPassword 16:677115EE610BDA1160B76BC49868A2D4EB2402BB7ADF65D8231B5621B1"
    ]
    if bridges and len(bridges) > 0:
        base_torrc.append("UseBridges 1")
        base_torrc.append("ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy")
        for bridge in bridges:
            base_torrc.append(f"Bridge {bridge}")
    torrc_content = "\n".join(base_torrc) + "\n"
    
    # Создаём tar-архив в памяти
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
        # Создаём tarinfo для файла torrc
        torrc_data = torrc_content.encode('utf-8')
        tarinfo = tarfile.TarInfo(name="torrc")
        tarinfo.size = len(torrc_data)
        tarinfo.mtime = int(time.time())
        tarinfo.mode = 0o644  # Права доступа
        tar.addfile(tarinfo, io.BytesIO(torrc_data))
    
    # Перемещаем указатель в начало потока
    tar_stream.seek(0)
    
    # Копируем tar-архив в контейнер
    container = client.containers.get(name)
    # Создаём резервную копию torrc (опционально)
    exit_code, output = container.exec_run("cp /etc/tor/torrc /etc/tor/torrc.bak || true")
    if exit_code != 0:
        logger.warning(f"Не удалось создать резервную копию torrc в {name}: {output.decode()}")
    
    # Загружаем torrc в /etc/tor
    try:
        container.put_archive("/etc/tor", tar_stream)
        logger.info(f"torrc успешно загружен в {name}")
    except Exception as e:
        logger.error(f"Ошибка загрузки torrc в {name}: {e}")
        return
    
    # Перезапускаем Tor
    exit_code, output = container.exec_run("pkill -HUP tor || killall -HUP tor || supervisorctl restart tor || true")
    if exit_code != 0:
        logger.warning(f"Не удалось перезапустить Tor в {name}: {output.decode()}")
    else:
        logger.info(f"Tor перезапущен в {name}")

def apply_tor_config(container_info, config):
    name = container_info['name']
    control_host = container_info['control_host']
    control_port = container_info['control_port']
    
    if not check_port(control_host, control_port, timeout=2):
        logger.error(f"Порт {control_port} на {control_host} недоступен.")
        return False
    
    # Если есть bridges — пишем torrc с мостами
    if config.get('bridges') and len(config['bridges']) > 0:
        write_torrc_with_bridges(container_info, config)
        logger.info(f"torrc с мостами применён для {name}")
        return True
    
    controller = get_controller(control_host, control_port)
    if not controller:
        return False
    
    try:
        # Сбрасываем настройки, если они пустые
        if "exclude_exit_countries" in config and config["exclude_exit_countries"]:
            # Убираем пустые строки из списка
            exclude_list = [country for country in config["exclude_exit_countries"] if country]
            if exclude_list:
                exclude_str = "{" + "},{".join(exclude_list) + "}"
                logger.info(f"Установка ExcludeExitNodes для {name}: {exclude_str}")
                controller.set_conf("ExcludeExitNodes", exclude_str)
            else:
                logger.info(f"Сброс ExcludeExitNodes для {name}")
                controller.reset_conf("ExcludeExitNodes")
        else:
            logger.info(f"Сброс ExcludeExitNodes для {name}")
            controller.reset_conf("ExcludeExitNodes")
        
        if "exit_nodes" in config and config["exit_nodes"]:
            exit_list = [node for node in config["exit_nodes"] if node]
            if exit_list:
                exit_str = "{" + "},{".join(exit_list) + "}"
                logger.info(f"Установка ExitNodes для {name}: {exit_str}")
                controller.set_conf("ExitNodes", exit_str)
            else:
                logger.info(f"Сброс ExitNodes для {name}")
                controller.reset_conf("ExitNodes")
        else:
            logger.info(f"Сброс ExitNodes для {name}")
            controller.reset_conf("ExitNodes")
        
        controller.set_conf("StrictNodes", "1")
        controller.signal("NEWNYM")
        
        logger.info(f"Контейнер {name} настроен: ExitNodes={config.get('exit_nodes')}, ExcludeExitNodes={config.get('exclude_exit_countries')}")
        return True
    except Exception as e:
        logger.error(f"Ошибка применения конфигурации к {name}: {e}")
        return False

def get_tor_containers():
    containers = client.containers.list(filters={"name": "my-tor-ip-changer-tor"})
    tor_containers = []
    for container in containers:
        name = container.name
        network_settings = container.attrs["NetworkSettings"]
        networks = network_settings["Networks"]
        ip_address = None
        for network_name, network_info in networks.items():
            ip_address = network_info["IPAddress"]
            if ip_address:
                break
        if not ip_address:
            logger.error(f"Не удалось определить IP-адрес для контейнера {name}")
            continue
        
        ports = network_settings["Ports"]
        socks_port = None
        if "9050/tcp" in ports and ports["9050/tcp"]:
            socks_port = int(ports["9050/tcp"][0]["HostPort"])
        
        tor_containers.append({
            "name": name,
            "socks_port": socks_port,
            "control_host": ip_address,
            "control_port": 9051
        })
    return tor_containers

def measure_speed(container_ip, internal_socks_port=9050):
    try:
        proxies = {
            "http": f"socks5://{container_ip}:{internal_socks_port}",
            "https": f"socks5://{container_ip}:{internal_socks_port}"
        }
        start_time = time.time()
        response = requests.get("http://checkip.amazonaws.com", proxies=proxies, timeout=10)
        latency = (time.time() - start_time) * 1000
        if response.status_code == 200:
            external_ip = response.text.strip()
            return int(latency), external_ip
        return None, None
    except Exception as e:
        logger.warning(f"Ошибка измерения скорости через {container_ip}:{internal_socks_port}: {e}")
        return None, None

def get_country_center(country_code):
    centers = {
        "US": {"lat": 39.8283, "lon": -98.5795},
        "DE": {"lat": 51.1657, "lon": 10.4515},
        "FR": {"lat": 46.6034, "lon": 1.8883},
        "GB": {"lat": 55.3781, "lon": -3.4360},
        "CA": {"lat": 56.1304, "lon": -106.3468},
        "JP": {"lat": 36.2048, "lon": 138.2529},
        "AU": {"lat": -25.2744, "lon": 133.7751},
        "BR": {"lat": -14.2350, "lon": -51.9253},
        "RU": {"lat": 61.5240, "lon": 105.3188},
        "IN": {"lat": 20.5937, "lon": 78.9629},
        "UA": {"lat": 48.3794, "lon": 31.1656},
        "Unknown": {"lat": 0, "lon": 0}
    }
    return centers.get(str(country_code).upper(), centers["Unknown"])

def get_ip_location(ip_address):
    try:
        db_path = "/app/GeoLite2-City.mmdb"
        country = "Unknown"
        lat = lon = None
        if os.path.exists(db_path):
            with geoip2.database.Reader(db_path) as reader:
                try:
                    response = reader.city(ip_address)
                    lat = response.location.latitude
                    lon = response.location.longitude
                    country = response.country.iso_code or response.country.name or "Unknown"
                except Exception:
                    pass
        if lat is None or lon is None:
            try:
                resp = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        country = data.get("countryCode") or data.get("country") or country
                        lat = data.get("lat")
                        lon = data.get("lon")
            except Exception as e:
                logger.warning(f"ip-api.com error for {ip_address}: {e}")
        # Если координаты валидны — возвращаем их
        if lat is not None and lon is not None:
            return {"lat": lat, "lon": lon, "country": country}
        # Если страна определена — возвращаем центр страны
        if country and country != "Unknown":
            center = get_country_center(country)
            return {"lat": center["lat"], "lon": center["lon"], "country": country}
        # Если ничего не найдено — не строим маркер
        return None
    except Exception as e:
        logger.warning(f"Ошибка получения геолокации для IP {ip_address}: {e}")
        return {"lat": 48.3794, "lon": 31.1656, "country": "UA"}

def get_circuit(container_info):
    controller = get_controller(container_info['control_host'], container_info['control_port'])
    if not controller:
        return "Ошибка: не удалось подключиться"
    
    try:
        circuits = controller.get_circuits()
        if circuits:
            circuit = circuits[0]
            nodes = []
            node_details = []
            
            for node in circuit.path:
                fingerprint = node[0]
                try:
                    # Получаем информацию о ноде по её fingerprint
                    node_info = controller.get_network_status(fingerprint)
                    ip_address = node_info.address
                    name = node[1]
                    
                    # Получаем геолокацию IP-адреса
                    location = get_ip_location(ip_address)
                    
                    # Добавляем информацию о ноде для отображения в текстовом виде
                    nodes.append(f"{ip_address} ({name})")
                    
                    # Добавляем детальную информацию о ноде для карты
                    node_detail = {
                        "ip": ip_address,
                        "name": name,
                        "fingerprint": fingerprint
                    }
                    
                    if location:
                        node_detail.update(location)
                    
                    node_details.append(node_detail)
                    
                except Exception as node_error:
                    # Если не удалось получить IP, используем только имя
                    logger.warning(f"Не удалось получить IP для ноды {node[1]}: {node_error}")
                    nodes.append(f"{node[1]} ({fingerprint})")
                    node_details.append({
                        "name": node[1],
                        "fingerprint": fingerprint
                    })
            
            # Сохраняем детальную информацию о нодах для API
            global node_locations
            node_locations[container_info['name']] = {
                "nodes": node_details
            }
            
            return " -> ".join(nodes)
        return "Нет активной цепочки"
    except Exception as e:
        logger.warning(f"Ошибка получения цепочки для {container_info['name']}: {e}")
        return "Ошибка"

def change_circuit(container_info):
    controller = get_controller(container_info['control_host'], container_info['control_port'])
    if not controller:
        return False
    
    try:
        controller.signal("NEWNYM")
        logger.info(f"Цепочка обновлена для {container_info['name']}")
        return True
    except Exception as e:
        logger.error(f"Ошибка смены цепочки для {container_info['name']}: {e}")
        return False

def ensure_exit_country(container_info, max_attempts=10):
    """Меняет цепочку, пока ни одна нода не принадлежит exclude_exit_countries и выходная страна совпадает с exit_nodes."""
    name = container_info['name']
    allowed_countries = [c.lower() for c in config['tor_containers'][name].get('exit_nodes', [])]
    excluded_countries = [c.lower() for c in config['tor_containers'][name].get('exclude_exit_countries', [])]
    for attempt in range(max_attempts):
        get_circuit(container_info)  # обновить node_locations
        nodes = node_locations.get(name, {}).get('nodes', [])
        if nodes:
            # Проверяем, что ни одна нода не из исключённых стран
            has_excluded = False
            for node in nodes:
                country = node.get('country', '').lower()
                if country in excluded_countries:
                    has_excluded = True
                    break
            exit_node = nodes[-1]
            exit_country = exit_node.get('country', '').lower()
            if not has_excluded and exit_country in allowed_countries:
                logger.info(f"Цепочка для {name} подходит: нет исключённых стран, выходная страна {exit_country}")
                return True
        logger.info(f"Попытка смены цепочки для {name}, не подходит (есть исключённые страны или не тот exit): {[node.get('country','') for node in nodes] if nodes else 'нет нод'}")
        change_circuit(container_info)
        time.sleep(3)
    logger.warning(f"Не удалось получить подходящую цепочку для {name} за {max_attempts} попыток")
    return False

def circuit_change_loop():
    while True:
        for container in tor_containers:
            name = container['name']
            if name not in config['tor_containers']:
                continue
            interval = config['tor_containers'][name].get('circuit_change_interval', 300)
            time.sleep(interval)
            logger.info(f"Автоматическая смена цепочки для {name}")
            ensure_exit_country(container)

def update_node_locations():
    global node_locations
    reader = None
    try:
        # Путь к базе данных GeoIP2
        db_path = "/app/GeoLite2-City.mmdb"
        if os.path.exists(db_path):
            reader = geoip2.database.Reader(db_path)
        else:
            logger.warning(f"База данных GeoIP2 не найдена по пути: {db_path}")
            return
        
        for container in tor_containers:
            name = container['name']
            current_circuit = get_circuit(container)
            
            if not current_circuit:
                continue
                
            # Получаем информацию о нодах в цепочке
            nodes = []
            circuit_parts = current_circuit.split(',')
            
            for part in circuit_parts:
                node_info = part.strip()
                if '~' in node_info:
                    node_name, node_ip = node_info.split('~')
                    node_data = {"name": node_name.strip(), "ip": node_ip.strip()}
                    
                    # Получаем геоданные для IP
                    try:
                        response = reader.city(node_ip.strip())
                        node_data["country"] = response.country.name
                        node_data["city"] = response.city.name if response.city.name else ""
                        node_data["latitude"] = response.location.latitude
                        node_data["longitude"] = response.location.longitude
                    except Exception as e:
                        logger.warning(f"Не удалось получить геоданные для IP {node_ip}: {e}")
                    
                    nodes.append(node_data)
            
            # Сохраняем информацию о нодах для контейнера
            if nodes:
                node_locations[name] = {
                    "nodes": nodes,
                    "exit_node": nodes[-1] if nodes else None
                }
    except Exception as e:
        logger.error(f"Ошибка при обновлении геоданных: {e}")
    finally:
        if reader:
            reader.close()

def monitor_circuits_and_ips():
    global last_circuits, last_ips
    while True:
        for container in tor_containers:
            name = container['name']
            current_circuit = get_circuit(container)
            latency, current_ip = measure_speed(container['control_host'])

            if name in last_circuits and last_circuits[name] != current_circuit:
                logger.info(f"Цепочка изменилась для {name}: {current_circuit}")
            last_circuits[name] = current_circuit

            if current_ip:
                if name in last_ips and last_ips[name] != current_ip:
                    logger.info(f"Внешний IP изменился для {name}: {current_ip} (задержка: {latency} мс)")
                last_ips[name] = current_ip
            else:
                logger.warning(f"Не удалось получить IP для {name}")
        
        # Обновляем геоданные нод
        update_node_locations()

        time.sleep(60)

class ConfigWatcher(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path != CONFIG_PATH:
            return
        stat = os.stat(event.src_path)
        global last_config_mtime
        if stat.st_mtime <= last_config_mtime:
            return
        logger.info("Обнаружено изменение config.json, перезагрузка конфигурации...")
        load_config()
        for container in tor_containers:
            name = container['name']
            if name in config['tor_containers']:
                apply_tor_config(container, config['tor_containers'][name])

def get_real_exit_ip_and_location(container):
    control_host = container.get('control_host')
    socks_port = 9050
    if not control_host:
        return None
    proxies = {
        "http": f"socks5://{control_host}:{socks_port}",
        "https": f"socks5://{control_host}:{socks_port}"
    }
    try:
        ip_resp = requests.get("http://api.ipify.org", proxies=proxies, timeout=15)
        if ip_resp.status_code != 200:
            return None
        real_ip = ip_resp.text.strip()
        # Определяем страну и координаты через ip-api.com
        geo_resp = requests.get(f"http://ip-api.com/json/{real_ip}", timeout=7)
        if geo_resp.status_code != 200:
            return {"ip": real_ip}
        geo = geo_resp.json()
        if geo.get("status") == "success":
            return {
                "ip": real_ip,
                "country": geo.get("countryCode") or geo.get("country"),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "city": geo.get("city"),
                "isp": geo.get("isp")
            }
        return {"ip": real_ip}
    except Exception as e:
        logger.warning(f"Ошибка получения реального IP для {container['name']}: {e}")
        return None

def get_my_real_ip_and_location():
    import requests
    try:
        ip_resp = requests.get("http://api.ipify.org", timeout=7)
        if ip_resp.status_code != 200:
            return None
        real_ip = ip_resp.text.strip()
        geo_resp = requests.get(f"http://ip-api.com/json/{real_ip}", timeout=7)
        if geo_resp.status_code != 200:
            return {"ip": real_ip}
        geo = geo_resp.json()
        if geo.get("status") == "success":
            return {
                "ip": real_ip,
                "country": geo.get("countryCode") or geo.get("country"),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "city": geo.get("city"),
                "isp": geo.get("isp")
            }
        return {"ip": real_ip}
    except Exception as e:
        logger.warning(f"Ошибка получения реального IP пользователя: {e}")
        return None

def get_entry_and_middle_nodes(container):
    # Получаем цепочку через контроллер Tor
    controller = get_controller(container['control_host'], container['control_port'])
    if not controller:
        return []
    try:
        circuits = controller.get_circuits()
        if not circuits:
            return []
        circuit = circuits[0]
        nodes = []
        for idx, node in enumerate(circuit.path):
            fingerprint = node[0]
            name = node[1]
            try:
                node_info = controller.get_network_status(fingerprint)
                ip_address = node_info.address
                # Определяем координаты через GeoLite2/ip-api
                geo = get_ip_location(ip_address)
                if geo:
                    node_type = 'entry' if idx == 0 else ('exit' if idx == len(circuit.path)-1 else 'middle')
                    nodes.append({
                        "ip": ip_address,
                        "country": geo.get("country"),
                        "lat": geo.get("lat"),
                        "lon": geo.get("lon"),
                        "city": geo.get("city", None),
                        "type": node_type,
                        "name": name
                    })
            except Exception as e:
                logger.warning(f"Ошибка получения координат для {name}: {e}")
        return nodes
    except Exception as e:
        logger.warning(f"Ошибка получения цепочки для {container['name']}: {e}")
        return []

# Инициализация
load_config()
tor_containers = get_tor_containers()

for container in tor_containers:
    name = container['name']
    if name in config['tor_containers']:
        logger.info(f"Ожидание готовности {name}...")
        if wait_for_tor_ready(name, container['control_host'], container['control_port']):
            apply_tor_config(container, config['tor_containers'][name])

threading.Thread(target=circuit_change_loop, daemon=True).start()
threading.Thread(target=monitor_circuits_and_ips, daemon=True).start()

observer = Observer()
observer.schedule(ConfigWatcher(), path=CONFIG_PATH, recursive=False)
observer.start()

@app.route('/')
def index():
    return render_template('index.html', containers=tor_containers)

@app.route('/api/circuits', methods=['GET'])
def get_circuits():
    circuits = {}
    for container in tor_containers:
        circuits[container['name']] = get_circuit(container)
    return jsonify(circuits)

@app.route('/api/speeds', methods=['GET'])
def get_speeds():
    speeds = {}
    for container in tor_containers:
        if container.get('control_host'): # Используем IP контейнера
            latency, _ = measure_speed(container['control_host']) # Передаем IP контейнера, внутренний порт по умолчанию 9050
            speeds[container['name']] = latency
    return jsonify(speeds)

@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify(config['tor_containers'])

@app.route('/api/update_config', methods=['POST'])
def update_config():
    data = request.json
    container_name = data['name']
    if container_name not in config['tor_containers']:
        return jsonify({"error": "Контейнер не найден"}), 404
    
    new_config = config['tor_containers'][container_name]
    new_config['circuit_change_interval'] = int(data.get('circuit_change_interval', new_config['circuit_change_interval']))

    # Обрабатываем exclude_exit_countries
    exclude_input = data.get('exclude_exit_countries', ','.join(new_config['exclude_exit_countries']))
    if exclude_input:
        new_config['exclude_exit_countries'] = [country.strip() for country in exclude_input.split(',') if country.strip()]
    else:
        new_config['exclude_exit_countries'] = []

    # Обрабатываем exit_nodes
    exit_input = data.get('exit_nodes', ','.join(new_config['exit_nodes']))
    if exit_input:
        new_config['exit_nodes'] = [node.strip() for node in exit_input.split(',') if node.strip()]
    else:
        new_config['exit_nodes'] = []

    logger.info(f"Обновление конфигурации для {container_name}: {new_config}")
    
    config['tor_containers'][container_name] = new_config
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)
    
    container = next(c for c in tor_containers if c['name'] == container_name)
    if apply_tor_config(container, new_config):
        logger.info(f"Конфигурация успешно применена для {container_name}")
    else:
        logger.error(f"Не удалось применить конфигурацию для {container_name}")
    
    return jsonify({"status": "success"})

@app.route('/api/new_circuit', methods=['POST'])
def new_circuit():
    data = request.json
    container_name = data['name']
    container = next((c for c in tor_containers if c['name'] == container_name), None)
    if not container:
        return jsonify({"error": "Контейнер не найден"}), 404
    if ensure_exit_country(container):
        return jsonify({"status": "success"})
    return jsonify({"error": "Ошибка смены цепочки"}), 500

@app.route('/api/node_locations', methods=['GET'])
def get_node_locations():
    # Возвращаем реальный внешний IP пользователя и координаты, а также для каждого контейнера
    result = {}
    # Сначала определяем реальный IP пользователя
    my_info = get_my_real_ip_and_location()
    if my_info and my_info.get("lat") is not None and my_info.get("lon") is not None:
        result["my_real_ip"] = {"nodes": [{
            "ip": my_info.get("ip"),
            "country": my_info.get("country"),
            "city": my_info.get("city"),
            "lat": my_info.get("lat"),
            "lon": my_info.get("lon"),
            "isp": my_info.get("isp"),
            "type": "me"
        }]}
    else:
        result["my_real_ip"] = {"nodes": []}
    # Теперь для каждого контейнера
    for container in tor_containers:
        name = container['name']
        # Получаем entry/middle/exit ноды
        nodes = get_entry_and_middle_nodes(container)
        # Заменяем exit-ноду на реальные данные
        if nodes:
            real_exit = get_real_exit_ip_and_location(container)
            if real_exit and real_exit.get("lat") is not None and real_exit.get("lon") is not None:
                # Удаляем старую exit-ноду
                nodes = [n for n in nodes if n.get("type") != "exit"]
                # Добавляем реальную exit-ноду
                nodes.append({
                    "ip": real_exit.get("ip"),
                    "country": real_exit.get("country"),
                    "city": real_exit.get("city"),
                    "lat": real_exit.get("lat"),
                    "lon": real_exit.get("lon"),
                    "isp": real_exit.get("isp"),
                    "type": "exit",
                    "name": "real_exit"
                })
        result[name] = {"nodes": nodes}
    return jsonify(result)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
