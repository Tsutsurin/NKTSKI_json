import json
import os
import re
import glob
import pandas as pd
from datetime import datetime


def cvss_edited(cvss):
    try:
        if float(cvss) < 4:
            return f'{cvss} Low'
        elif float(cvss) < 7:
            return f'{cvss} Medium'
        elif float(cvss) < 9:
            return f'{cvss} High'
        else:
            return f'{cvss} Critical'
    except Exception:
        return '-----'


def product(text):
    pattern_and = r'(.+?) и (.+?):'
    pattern_solo = r'(.+?):'
    match = re.search(pattern_and, text)
    if match:
        word1 = match.group(1).strip()
        word2 = match.group(2).strip()
        return f'{word1}, {word2}'
    
    matches = re.findall(pattern_solo, text)
    result = ', '.join(match.strip() for match in matches)
    if result:
        return result
    else:
        return text


def date_edited(d):
    date_obj = datetime.strptime(d, '%Y-%m-%d')
    return date_obj.strftime('%d.%m.%Y')


def path_to_json():
    try:
        file_ = glob.glob(os.path.join('*.json'))
        return file_[0]
    except Exception as e:
        print(f'Ошибка при поиске файла json {e}')


def find_file():
    try:
        file_ = glob.glob(os.path.join('*.json'))
        if file_:
            return True
        else:
            return False
    except Exception as e:
        print(f'Ошибка при поиске файла json {e}')


if __name__ == '__main__':
    try:
        bloodhound = False
        while not bloodhound:
            bloodhound = find_file()
            if not bloodhound:
                input(f'Для обработки данных поместите в директорию c парсером JSON файл бюллетеня НКЦКИ и нажмите Enter ')

        file_path = path_to_json()
        print(f'Найден json файл {file_path}\nПриступаю к выполнению кода')
        with open(file_path, 'r', encoding='utf-8') as f:
            date = json.load(f)

        dates = date['data']

        rows = []
        counter = 1
        for entry in dates:
            row = {
                '№': counter,
                'Источник': 'НКЦКИ',
                'Дата публикации': date_edited(entry.get('date_published')),
                'CVE': entry['vuln_id'].get('MITRE'),
                'CVSS': cvss_edited(entry['cvss'].get('cvss_score')),
                'Продукты': product(entry['vulnerable_software'].get('software_text')),
                'Ссылки': entry.get('urls')[0]
            }
            rows.append(row)
            counter += 1

        df = pd.DataFrame(rows)
        name_f = (f'{datetime.today().strftime('%d.%m.%Y')} НКЦКИ JSON.xlsx')
        df.to_excel(name_f, index=False)
        input(f'Файл {name_f} создан\nНажмите Enter для выхода ')

    except Exception as e:
        input(f'Ошибка при работе кода {e}')
