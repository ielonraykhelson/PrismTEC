from prismtec.utils.general.time import get_timezone_utc
from prismtec.utils.general.path import append_to_reports_path

import json
from pathlib import Path
import re

__all__ = [
    ''
]

def write_data(data: dict, file_path: str, use_reports_path: bool = True) -> None:
    # get report path
    if use_reports_path:
        file_path = append_to_reports_path(path=file_path)

    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # avoid overwriting existing reports
    if path.exists():
        original_path = path
        match = re.match(r'^(.*)-(\d+)$', path.stem)

        if match:
            base_name = match.group(1)
            counter = int(match.group(2)) + 1
        else:
            base_name = path.stem
            counter = 1

        while path.exists():
            path = original_path.with_name(
                f'{base_name}-{counter}{original_path.suffix}'
            )
            counter += 1

    with path.open('w', encoding='utf-8') as file:
        json.dump(data, file, indent=4, ensure_ascii=False)

    return str(path)

def generate_report(data: dict,
                    file_path: str,
                    extension: str = '.json',
                    use_reports_path: bool = True) -> str:
    # supports relative pathing in file_path
    if extension[0] != '.':
        extension = f'.{extension}'

    if extension not in ['.json', '.txt', '.md']:
        print(f'/!\\ Caution: Unknown report generation behavior with extension {extension}. Supported: (.json, .txt, .md).')

    timestamp = get_timezone_utc()
    full_path = f'{file_path}-{timestamp}{extension}'
    return write_data(
        data=data,
        file_path=full_path,
        use_reports_path=use_reports_path
    )

def change_extension(json_path: str, extension: str) -> None:
    # Caution, unknown behavior with some extensions.
    if extension[0] != '.':
        extension = f'.{extension}'
    output_path = f'{json_path}{extension}'

    with open(json_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(json.dumps(data, indent=4, ensure_ascii=False))

if __name__ == '__main__':
    print('generation.py module loaded')

    # TESTING FUNCTIONALITY
    # report = {
    #     "indicator": "8.8.8.8",
    #     "type": "ip",
    #     "timestamp": "135742-28102026-EDT",
    #     "results": {
    #         "VirusTotal": {"malicious": 0, "harmless": 85},
    #         "AbuseIPDB": {"abuseConfidenceScore": 0}
    #     }
    # }

    # generate_report(
    #     data=report,
    #     file_path='\\x\\test1',
    #     extension='.json'
    # )