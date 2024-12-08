import PyInstaller.__main__

PyInstaller.__main__.run([
    'encdectool.py',
    '--onefile',
    '--clean',
    "--name=AES_AV_TESTER"
])