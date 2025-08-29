import importlib
mods = ['app.database','ingest.runner']
for m in mods:
    try:
        importlib.import_module(m)
        print(m, 'import OK')
    except Exception as e:
        print(m, 'IMPORT ERROR:', e)
