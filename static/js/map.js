// Инициализация карты Leaflet
window.map = null;
window.markers = {};
console.log('window.markers initialized', window.markers);
let polylines = {};
window.lines = [];
const containerColors = [
    '#e74c3c', // красный
    '#3498db', // синий
    '#27ae60', // зеленый
    '#f1c40f', // желтый
    '#9b59b6', // фиолетовый
    '#e67e22', // оранжевый
    '#1abc9c', // бирюзовый
    '#34495e', // темно-синий
];
function getContainerColor(containerId) {
    // Простой хеш для выбора цвета
    let hash = 0;
    for (let i = 0; i < containerId.length; i++) hash += containerId.charCodeAt(i);
    return containerColors[hash % containerColors.length];
}
function getNodeIcon(type, color) {
    let iconHtml = '';
    if (type === 'entry') iconHtml = '<span class="marker-dot marker-entry"></span>';
    else if (type === 'exit') iconHtml = '<span class="marker-dot marker-exit"></span>';
    else iconHtml = '<span class="marker-dot marker-middle"></span>';
    return L.divIcon({
        className: 'custom-marker',
        html: iconHtml,
        iconSize: [18, 18],
        iconAnchor: [9, 9],
        popupAnchor: [0, -9],
        bgPos: [0, 0],
        style: `background:${color}`
    });
}

// Инициализация карты
function initMap() {
    // Создаем карту и устанавливаем начальный вид
    window.map = L.map('map-container').setView([30, 10], 2);
    
    // Добавляем слой OpenStreetMap
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(window.map);
}

// Обновление маркеров на карте
async function updateMapMarkers() {
    try {
        const response = await fetch('/api/node_locations');
        const nodeLocations = await response.json();
        // Полностью удаляем все старые маркеры
        for (const containerId in window.markers) {
            window.markers[containerId].forEach(m => window.map.removeLayer(m));
        }
        window.markers = {};
        // Полностью удаляем все старые линии
        if (window.lines && Array.isArray(window.lines)) {
            window.lines.forEach(line => window.map.removeLayer(line));
        }
        window.lines = [];
        // Добавляем маркер пользователя (зелёный)
        let myLatLng = null;
        if (nodeLocations.my_real_ip && nodeLocations.my_real_ip.nodes && nodeLocations.my_real_ip.nodes.length > 0) {
            const node = nodeLocations.my_real_ip.nodes[0];
            if (typeof node.lat === 'number' && typeof node.lon === 'number' && !isNaN(node.lat) && !isNaN(node.lon)) {
                myLatLng = [node.lat, node.lon];
                let marker = L.marker(myLatLng, {
                    icon: L.divIcon({
                        className: 'custom-marker',
                        html: '<span class="marker-dot marker-me"></span>',
                        iconSize: [22, 22],
                        iconAnchor: [11, 11],
                        popupAnchor: [0, -11],
                        style: 'background:#2ecc40;'
                    })
                }).bindPopup(`<strong>Ваш IP</strong><br>${node.ip}${node.country ? ' - ' + node.country : ''}<br>Тип: вы`);
                window.markers['my_real_ip'] = [marker.addTo(window.map)];
            }
        }
        // Добавляем маркеры цепочки (entry, middle, exit) и соединяем их линиями
        for (const containerId in nodeLocations) {
            if (containerId === 'my_real_ip') continue;
            const containerData = nodeLocations[containerId];
            const color = getContainerColor(containerId);
            window.markers[containerId] = [];
            let chainLatLngs = [];
            if (containerData.nodes && containerData.nodes.length > 0) {
                // Оставляем только exit-ноду
                const exitNode = containerData.nodes.find(n => n.type === 'exit');
                if (exitNode && typeof exitNode.lat === 'number' && typeof exitNode.lon === 'number' && !isNaN(exitNode.lat) && !isNaN(exitNode.lon)) {
                    let latlng = [exitNode.lat, exitNode.lon];
                    let marker = L.marker(latlng, {
                        icon: getNodeIcon('exit', color)
                    }).bindPopup(`<strong>${containerId}</strong><br>${exitNode.name ? exitNode.name : ''} (${exitNode.ip})${exitNode.country ? ' - ' + exitNode.country : ''}<br>Тип: exit`);
                    window.markers[containerId].push(marker.addTo(window.map));
                    chainLatLngs.push(latlng);
                    // Линия от пользователя к exit-ноде
                    if (myLatLng) {
                        let line = L.polyline([myLatLng, latlng], {color: color, weight: 2, opacity: 0.7, dashArray: '5, 5'}).addTo(window.map);
                        window.lines.push(line);
                    }
                }
            }
        }
        // Автоматически приближаем карту к маркерам
        let allLatLngs = [];
        for (const containerId in window.markers) {
            window.markers[containerId].forEach(m => {
                if (m.getLatLng) allLatLngs.push([m.getLatLng().lat, m.getLatLng().lng]);
            });
        }
        if (allLatLngs.length > 0) {
            window.map.fitBounds(allLatLngs, {padding: [30, 30]});
        }
    } catch (error) {
        console.error('Ошибка при обновлении маркеров:', error);
    }
}

// Инициализация карты при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    // Проверяем, существует ли контейнер для карты
    const mapContainer = document.getElementById('map-container');
    if (mapContainer) {
        initMap();
        
        // Обновляем маркеры сразу и затем каждые 10 секунд
        updateMapMarkers();
        setInterval(updateMapMarkers, 10000);
    }
});