import PyInstaller.__main__

PyInstaller.__main__.run([
    'encdectool.py',
    '--onefile',
    '--clean',
    "--windowed",
    "--name=AES_AV_TESTER"
])