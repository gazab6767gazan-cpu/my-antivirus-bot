from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse
import hashlib
import requests

app = FastAPI()

# Твой бесплатный ключ от VirusTotal
VT_API_KEY = 'ТВОЙ_КЛЮЧ_VIRUSTOTAL'

# HTML код страницы (просто и красиво)
html_page = """
<!DOCTYPE html>
<html>
<head><title>Антивирус-Сканер</title></head>
<body style="font-family: Arial; text-align: center; padding: 50px; background: #1a1a1a; color: white;">
    <h1>🛡 Бесплатный сканер файлов</h1>
    <p>Загрузите подозрительный файл (APK, ZIP, EXE) для проверки</p>
    <form action="/scan" enctype="multipart/form-data" method="post">
        <input name="file" type="file" style="padding: 10px; background: #333; color: white; border: 1px solid #555;">
        <input type="submit" value="Проверить" style="padding: 10px 20px; background: #34A853; color: white; border: none; cursor: pointer;">
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
    
    # Считаем хэш файла
    file_hash = hashlib.sha256(contents).hexdigest()
    
    # Идем в VirusTotal
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        bad = stats.get('malicious', 0) + stats.get('suspicious', 0)
        
        if bad > 0:
            result = f"<h2 style='color:red;'> ВИРУС! Обнаружено {bad} угрозами.</h2>"
        else:
            result = "<h2 style='color:green;'> Файл чист!</h2>"
    else:
        result = "<h2 style='color:orange;'> Файла нет в базе. Возможно, он новый.</h2>"
        
    return HTMLResponse(f"""
        <body style="font-family: Arial; text-align: center; padding: 50px; background: #1a1a1a; color: white;">
            {result}
            <p>Файл: {file.filename}</p>
            <a href="/" style="color: #34A853;">Вернуться назад</a>
        </body>
    """)