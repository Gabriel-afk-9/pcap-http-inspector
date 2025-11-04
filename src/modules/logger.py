from pathlib import Path
from datetime import datetime

LOG_PATH = Path(__file__).resolve().parent.parent / "log.txt"

def logger(log: str):
    try:
      LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
      timestamp = datetime.now().isoformat()
      line = f"[{timestamp}] - {log}\n"
      with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(line)
        
    except Exception as e:
      print("Erro ao gravar log:", e)
