"""Taiwan wording in the Traditional Chinese text we ship (owner: 點擊 2026-11-15, 前綴 2026-11-16).

用戶端 (client) is the Taiwan term and stays; 用戶 on its own (user) is mainland usage.
A line that quotes a replaced term on purpose says 中國用語 and is skipped.
"""
import glob
import io
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TERMS = {
    '點擊': '點選／按', '前綴': '前置字串（文字）／前置碼（位址）', '用戶(?!端)': '使用者', '日誌': '記錄',
    '默認': '預設', '激活': '啟用', '視頻': '影片', '軟件': '軟體', '進程': '程序', '數據庫': '資料庫',
    '服務器': '伺服器', '網絡': '網路', '文件夾': '資料夾', '鼠標': '滑鼠', '屏幕': '螢幕',
}
PATTERN = re.compile('|'.join(TERMS))


def shipped_files():
    files = glob.glob(os.path.join(ROOT, 'packs', '*', 'manifest.json'))
    files.append(os.path.join(ROOT, 'lib', 'i18n_engine.js'))
    for base in (ROOT, os.path.join(ROOT, 'github')):
        files += glob.glob(os.path.join(base, '*-zh-TW.md'))
        files += glob.glob(os.path.join(base, 'docs', '*zh-TW*.html'))
    return sorted(f for f in set(files) if os.path.exists(f))


class TestTaiwanWording(unittest.TestCase):
    def test_no_mainland_terms(self):
        found = []
        for path in shipped_files():
            with io.open(path, encoding='utf-8') as fh:
                for n, line in enumerate(fh, 1):
                    if '中國用語' in line:
                        continue
                    for m in PATTERN.finditer(line):
                        found.append('%s:%d %s' % (os.path.relpath(path, ROOT), n, m.group(0)))
        self.assertEqual(found, [], 'use the Taiwan term instead')


if __name__ == '__main__':
    unittest.main()
