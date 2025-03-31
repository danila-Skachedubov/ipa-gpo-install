import argparse
import sys
import logging

def main():
    parser = argparse.ArgumentParser(
        description="CLI-утилита для настройки GPO в FreeIPA"
    )

    parser.add_argument(
        "--debuglevel", type=int, choices=range(0, 3), default=0,
        help="Уровень логирования (0-3)"
    )
    parser.add_argument(
        "--version", action="store_true",
        help="Вывести версию утилиты"
    )

    args = parser.parse_args()

    if args.version:
        print("ipa-gpo-install 0.0.1")
        sys.exit(0)

    logging.basicConfig(
        level=logging.DEBUG if args.debuglevel > 0 else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    logging.info("Запуск ipa-gpo-install")

    logging.info("Здесь будут проверки и настройка")

if __name__ == "__main__":
    main()
