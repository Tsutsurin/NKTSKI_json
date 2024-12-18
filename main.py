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
    result = re.match(r'(.*?):', text)
    return result.group(1)


def date_edited(d):
    date_obj = datetime.strptime(d, '%Y-%m-%d')
    return date_obj.strftime('%d.%m.%Y')

def path_to_json():
    try:
        file_ = glob.glob(os.path.join('*.json'))
        return file_[0]
    except Exception as e:
        print(f'Ошибка {e}')
        exit


if __name__ == '__main__':
    with open(path_to_json(), 'r', encoding='utf-8') as f:
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
    input(f'Файл {name_f} создан!')
