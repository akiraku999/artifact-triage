# SentinelTriage

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)
![Purpose](https://img.shields.io/badge/Purpose-InfoSec%20%7C%20SOC%20%7C%20DFIR-red.svg)

**SentinelTriage** — это автономный CLI-инструмент для быстрого статического экспресс-анализа подозрительных файлов и извлечения индикаторов компрометации (IOC). Разработан для специалистов по информационной безопасности, SOC-аналитиков и DFIR-команд.

## Возможности

- **Вычисление хэшей**: MD5, SHA1, SHA256 для идентификации файлов
- **Анализ энтропии**: Расчет энтропии Шеннона для обнаружения упаковки/шифрования (> 7.0)
- **Извлечение IOC**:
  - IPv4-адреса
  - URL-адреса
  - Email-адреса
  - Подозрительные Base64-строки с попыткой декодирования
- **Красивый вывод**: Цветные таблицы и бейджи через библиотеку Rich
- **Экспорт результатов**: Сохранение отчета в JSON
- **Тестовый режим**: Генерация тестовых файлов с внедренными IOC

## Требования

- Python 3.7+
- Библиотека Rich

## Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/akiraku999/artifact-triage.git
cd artifact-triage
```

2. Установите зависимости:
```bash
pip install -r requirements.txt
```

## Использование

### Анализ файла

```bash
python sentinel.py analyze suspicious.exe
```

### Анализ с экспортом в JSON

```bash
python sentinel.py analyze suspicious.exe --json report.json
```

### Генерация тестового файла

```bash
python sentinel.py generate-test --output test_sample.bin
```

### Использование с легаси-флагом

```bash
python sentinel.py --generate-test --output test_malware.bin
```

## Архитектура

```
sentinel-triage/
├── sentinel.py              # Входная точка CLI (argparse)
├── core/
│   ├── __init__.py
│   ├── analyzer.py          # Хэши и энтропия
│   ├── extractors.py        # Регулярки для IOC
│   └── reporter.py          # Вывод через Rich
├── requirements.txt         # Зависимости
├── .gitignore              # Git ignore
└── README.md               # Документация
```

## Схема работы

```
┌─────────────────┐
│  sentinel.py    │
│  (CLI Entry)    │
└────────┬────────┘
         │
         ├─────────────────────────────────────────┐
         │                                         │
         ▼                                         ▼
┌─────────────────┐                    ┌─────────────────┐
│  analyzer.py    │                    │ extractors.py   │
│  • Hashes       │                    │  • IPv4         │
│  • Entropy      │                    │  • URLs         │
│  • File Size    │                    │  • Emails       │
└────────┬────────┘                    │  • Base64       │
         │                             └────────┬────────┘
         │                                      │
         └──────────────┬───────────────────────┘
                        ▼
               ┌─────────────────┐
               │  reporter.py    │
               │  • Rich Tables  │
               │  • Color Badges │
               │  • JSON Export  │
               └─────────────────┘
```

## Пример вывода

```
╭─────────────────────────────────────────╮
│ 🔍 SentinelTriage - Static File Analysis │
╰─────────────────────────────────────────╯

┌──────────────────────────────────────┐
│          File Information            │
├──────────────────┬───────────────────┤
│ Property         │ Value             │
├──────────────────┼───────────────────┤
│ Path             │ suspicious.exe    │
│ Size             │ 45,678 bytes      │
└──────────────────┴───────────────────┘

┌──────────────────────────────────────┐
│            File Hashes               │
├──────────────────┬───────────────────┤
│ Algorithm        │ Hash              │
├──────────────────┼───────────────────┤
│ MD5              │ d41d8cd98f00b...  │
│ SHA1             │ 0cc175b9c0f1b...  │
│ SHA256           │ e3b0c44298fc1...  │
└──────────────────┴───────────────────┘

┌──────────────────────────────────────┐
│         Entropy Analysis              │
├──────────────────┬───────────────────┤
│ Metric           │ Value             │
├──────────────────┼───────────────────┤
│ Shannon Entropy  │ 7.8432            │
│ Status           │ [SUSPICIOUS]      │
└──────────────────┴───────────────────┘

┌──────────────────────────────────────┐
│          Extracted IOCs               │
├─────────┬───────┬─────────────────────┤
│ Type    │ Count │ Findings            │
├─────────┼───────┼─────────────────────┤
│ IPv4    │ 2     │ 192.168.1.100...    │
│ URLs    │ 1     │ http://evil-c2...   │
│ Emails  │ 2     │ attacker@evil...    │
│ Base64  │ 2     │ 2 found             │
└─────────┴───────┴─────────────────────┘

╭─────────────────────────────────────────╮
│         FINAL ASSESSMENT                 │
│                                          │
│ Overall Verdict: [SUSPICIOUS]            │
│                                          │
│ Reason: High entropy (>7.0), IOCs       │
│ detected (7)                             │
╰─────────────────────────────────────────╯
```

## 🔧 Пороговые значения

- **Энтропия**: > 7.0 = вероятная упаковка или шфрование
- **Base64**: строки длиной > 20 символов
- **Статус**: [SAFE] или [SUSPICIOUS] на основе энтропии и наличия IOC

## JSON-экспорт

При использовании флага `--json` создается структурированный отчет:

```json
{
  "file_path": "suspicious.exe",
  "file_size": 45678,
  "hashes": {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "0cc175b9c0f1b6a831c399e269772661",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb924"
  },
  "entropy": {
    "value": 7.8432,
    "is_suspicious": true
  },
  "iocs": {
    "ipv4": ["192.168.1.100"],
    "urls": ["http://evil-c2-server.com/command"],
    "emails": ["attacker@evil-domain.com"],
    "base64_strings": [...]
  }
}
```

## Тестирование

Инструмент включает режим генерации тестовых файлов:

```bash
# Генерация тестового файла
python sentinel.py generate-test --output test_sample.bin

# Анализ сгенерированного файла
python sentinel.py analyze test_sample.bin --json test_report.json
```

Тестовый файл содержит:
- Фальшивые URL C2-серверов
- Подозрительные IP-адреса
- Email-адреса злоумышленников
- Base64-строки
- Шифрованную секцию с высокой энтропией

## Безопасность

- Инструмент выполняет только статический анализ
- Не запускает анализируемые файлы
- Все операции выполняются локально
- Не отправляет данные во внешние сервисы

## Вклад в разработку

Contributions are welcome! Пожалуйста, создавайте pull requests для улучшения функциональности.

## 📄 Лицензия

MIT License - см. файл LICENSE для деталей

## Контакты

Для вопросов и предложений: [akirakusec@gmail.com]

## ⚠️ Disclaimer

Этот инструмент предназначен для использования в законных целях: анализ файлов в рамках расследования инцидентов, исследований безопасности и тестирования на проникновение с соответствующими разрешениями.

---

**Made with ❤️ for InfoSec Community**
