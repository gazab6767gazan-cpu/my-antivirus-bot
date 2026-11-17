from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse
import hashlib
import requests
import zipfile
import io

app = FastAPI()

# ВСТАВЬ СВОЙ КЛЮЧ ОТ VIRUSTOTAL!
VT_API_KEY = 'ТВОЙ_КЛЮЧ_VIRUSTOTAL'

# Словарь опасных строк, которые мы ищем внутри файлов
MALICIOUS_STRINGS = {
    b'com.template.shellapp': '⚠️ Найдена пустая оболочка (ShellApp). Это не игра, а шаблон для показа фишинга.',
    b'BlockVpnService': '🚨 Найден BlockVpnService! Вирус пытается отключить Google Play Protect (создает локальный VPN).',
    b'payload.db': '🚨 Найдена база payload.db! Используется для кражи кэша Telegram и ваших данных.',
    b'QUERY_ALL_PACKAGES': '⚠️ Запрос доступа ко всем приложениям. Вирус ищет банковские приложения.',
    b'REQUEST_INSTALL_PACKAGES': '🚨 Разрешение на установку других приложений. Вирус может скачать еще больше малвари.',
    b'BootReceiver': '🚨 Автозагрузка! Вирус запустится снова после перезагрузки телефона.'
}

html_page = """
<!DOCTYPE html>
<html>
<head><title>Ультра-Антивирус</title></head>
<body style="font-family: Arial; text-align: center; padding: 50px; background: #1a1a1a; color: white;">
    <h1>🛡 Мой Ультра-Антивирус</h1>
    <p>Загрузите подозрительный APK или ZIP файл для анализа</p>
    <form action="/scan" enctype="multipart/form-data" method="post">
        <input name="file" type="file" style="padding: 10px; background: #333; color: white; border: 1px solid #555; margin-bottom: 20px;"><br>
        <input type="submit" value="Проверить файл" style="padding: 10px 20px; background: #34A853; color: white; border: none; cursor: pointer; font-size: 16px;">
    </form>
</body>
</html>
"""

@app.get("/")
async def main():
    return HTMLResponse(html_page)

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    contents = await file.read()
    filename = file.filename.lower()
    
    # 1. СЧИТАЕМ ХЭШ И ИДЕМ В VIRUSTOTAL
    file_hash = hashlib.sha256(contents).hexdigest()
    headers = {"x-apikey": VT_API_KEY}
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    vt_response = requests.get(vt_url, headers=headers)
    
    vt_report = "<h3 style='color:gray;'>VirusTotal: Файл неизвестен базе.</h3>"
    
    if vt_response.status_code == 200:
        data = vt_response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        bad = stats.get('malicious', 0) + stats.get('suspicious', 0)
        
        if bad > 0:
            vt_report = f"<h3 style='color:red;'>🚨 VirusTotal: Файл опасен! Обнаружено {bad} детектов.</h3>"
        else:
            vt_report = "<h3 style='color:green;'>✅ VirusTotal: Файл чист.</h3>"

    # 2. СТАТИЧЕСКИЙ АНАЛИЗ (Ищем строки внутри APK/ZIP)
    found_threats = []
    
    if filename.endswith('.apk') or filename.endswith('.zip'):
        try:
            # Открываем файл как архив в памяти
            with zipfile.ZipFile(io.BytesIO(contents)) as z:
                for file_in_zip in z.namelist():
                    # Нас интересуют только dex файлы (код) и манифест
                    if file_in_zip.endswith('.dex') or file_in_zip == 'AndroidManifest.xml':
                        file_data = z.read(file_in_zip)
                        # Ищем опасные строки
                        for bad_str, description in MALICIOUS_STRINGS.items():
                            if bad_str in file_data:
                                found_threats.append(description)
        except Exception as e:
            found_threats.append(f"⚠️ Не удалось распаковать архив: {e}")
    else:
        found_threats.append("⚠️ Это не APK/ZIP. Глубокий анализ кода не проведен (только проверка хэша).")

    # Убираем дубликаты из списка найденных угроз
    found_threats = list(set(found_threats))

    # 3. ФОРМИРУЕМ ИТОГОВЫЙ ОТЧЕТ
    if found_threats:
        analysis_report = "<h3 style='color:orange;'>🔍 Анализ кода показал:</h3><ul style='text-align:left; display:inline-block;'>"
        for threat in found_threats:
            analysis_report += f"<li>{threat}</li>"
        analysis_report += "</ul>"
    else:
        analysis_report = "<h3 style='color:green;'>✅ Внутри кода не найдено известных вредоносных строк (это не значит, что файл безопасен, если VT его не знает).</h3>"

    return HTMLResponse(f"""
        <body style="font-family: Arial; text-align: center; padding: 50px; background: #1a1a1a; color: white;">
            <h2>Отчет по файлу: {file.filename}</h2>
            {vt_report}
            <hr style="border-color: #333; width: 50%;">
            {analysis_report}
            <br><br>
            <a href="/" style="color: #34A853; text-decoration: none; font-size: 18px;">⬅ Вернуться к загрузке</a>
        </body>
    """)
