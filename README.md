# Butler

Веб-панель управления доступом к сервисам через nftables.

## Быстрый старт

### Сборка дистрибутива (на машине разработчика)

```bash
./build.sh
# Результат: ../butler-YYYYMMDD-HHMMSS.tar.gz
```

Для сервера с конкретной версией Python:
```bash
./build.sh --python-version 3.12 --abi cp312
```

### Деплой на сервер

```bash
# Перекинуть архив
scp butler-*.tar.gz user@server:~/serv/

# На сервере
cd ~/serv && tar -xzf butler-*.tar.gz
cd butler

# Настроить конфиг (пароль, порт)
cp butler.env.example butler.env
nano butler.env

# Установить как службу
./install.sh

# Настроить sudoers (для управления nftables и conntrack)
./sudoers.sh
```

### Проверка без установки службы

```bash
./butler          # запускает gunicorn прямо в терминале, Ctrl+C — стоп
```

### Обновление

```bash
# Перекинуть новый архив, распаковать поверх
cd ~/serv && tar -xzf butler-new.tar.gz

# butler.env и БД не трогаются — они вне .butler/
./install.sh      # переустанавливает службу с новыми файлами
```

## Структура папки на сервере

```
~/serv/butler/
├── butler.env          ← конфиг (трогаешь руками)
├── butler              ← тестовый запуск
├── install.sh          ← установка службы
├── sudoers.sh          ← настройка sudoers
└── .butler/            ← подкапотное (не трогать)
    ├── app/
    ├── wheels/
    ├── wsgi.py
    ├── requirements.txt
    ├── butler-log-import.py
    └── instance/       ← база данных (создаётся при install.sh)
```

## Управление службой

```bash
sudo systemctl status butler
sudo systemctl restart butler
sudo journalctl -u butler -f
```

## Стек

- **Flask** — веб-интерфейс
- **SQLite** — хранение данных
- **nftables** — фильтрация трафика
- **Gunicorn** — production WSGI-сервер
- **systemd** — управление процессом
