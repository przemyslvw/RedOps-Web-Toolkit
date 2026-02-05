from flask import Flask, jsonify

app = Flask(__name__)

# Przykładowa struktura odpowiedzi pogodowej (do dostosowania po zobaczeniu prawdziwego JSONa)
fake_weather_data = {
    "latitude": 52.52,
    "longitude": 13.41,
    "generationtime_ms": 0.123,
    "utc_offset_seconds": 0,
    "timezone": "GMT",
    "timezone_abbreviation": "GMT",
    "elevation": 38.0,
    "current_weather": {
        "temperature": 99.9,  # HACKED
        "windspeed": 100.0,   # HACKED
        "winddirection": 0,
        "weathercode": 0,     # Clear sky
        "is_day": 1,
        "time": "2024-01-01T12:00"
    },
    "hourly": {
        "time": ["2024-01-01T12:00", "2024-01-01T13:00", "2024-01-01T14:00"],
        "temperature_2m": [99.9, 99.9, 99.9],
        "relativehumidity_2m": [10, 10, 10],
        "weathercode": [0, 0, 0]
    },
    "daily": {
        "time": ["2024-01-01"],
        "weathercode": [0],
        "temperature_2m_max": [100.0],
        "temperature_2m_min": [90.0]
    }
}

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    print(f"[+] Received Request for /{path}")
    print(f"    (Returning Fake Open-Meteo Data)")
    # Aura korzysta z API Open-Meteo, więc zwracamy strukturę pasującą do tego API
    return jsonify(fake_weather_data)

if __name__ == '__main__':
    # Uruchamiamy na porcie 80, dostępny dla wszystkich
    print("[*] Starting Fake Weather Server on port 80...")
    app.run(host='0.0.0.0', port=80)
