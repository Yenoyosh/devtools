# DevTools Render Starter

## Start lokal
```bash
pip install -r requirements.txt
python app.py
```

## Render
Dieses Repo enthaelt bereits eine `render.yaml`.

### Schnell
1. Repo auf GitHub hochladen
2. In Render `New > Web Service`
3. Repo auswaehlen
4. Falls Render die Werte nicht direkt uebernimmt:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`

## Hinweise
- ArchiveReader funktioniert bereits als Webversion.
- Conv-erter ist als Desktop-Tool sinnvoller.
- Image-n / Torch ist auf Free-Instanzen oft zu schwer.
