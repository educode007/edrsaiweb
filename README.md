# EDR SAI — Electronic Drilling Recorder

Sistema de registro electrónico de perforación estilo Pason para oil & gas.

## Stack
- **Backend**: Python + Flask + Flask-SocketIO
- **Frontend**: HTML/CSS/JS + Chart.js + Socket.IO
- **Desktop**: Electron + Electron Builder

## Parámetros monitoreados

| Parámetro | WITS Code | Mostrado | Graficado |
|-----------|-----------|----------|-----------|
| Hole Depth | 0108 | ✅ | ✅ |
| Bit Depth | 0110 | ✅ | ✅ |
| Weight on Bit | 0113 | ✅ | — |
| Rotary RPM | 0117 | ✅ | — |
| Standpipe Pressure | 0128 | ✅ | — |
| Total Pump Output | 0130 | ✅ | — |
| On Bottom ROP | 0143 | ✅ | — |
| Gamma Ray | 0160 | ✅ | — (pendiente) |

## Instalación desarrollo

```bash
cd C:\edusurf\edrsai
pip install -r requirements.txt
python app.py
# Abrir http://127.0.0.1:5051
```

## Build desktop

```bash
cd C:\edusurf\edrsai\desktop
npm install
npm run dist
```

## Formato WITS esperado

Cada línea: `CCCCVVVV...` donde CCCC = código de 4 dígitos, seguido del valor.

Ejemplo:
```
0108 1250.50
0110 1248.30
0113 18.50
0117 120.0
```
