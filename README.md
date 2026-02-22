# CTF Writeup

這個專案用來整理 CTF 題目、原始附件、解題腳本與 writeup 文章。

## 專案結構

```text
2025/
  BITSCTF/
    web/
      elysias-bakery/
      rusty-proxy/
  WHYCTF/
    pwn/
      old-memes-never-die/
    rev/
      3-ball-mark/
templates/
scripts/
```

每一題建議固定使用這些子資料夾：

- `README.md`: 該題 writeup 文章
- `src/`: 題目原始檔、附件、執行檔
- `solve/`: exploit / solver / helper scripts
- `assets/`: 文章內用到的圖片

## Writeup 索引

| Year | Event | Category | Challenge | Writeup | Source |
|---|---|---|---|---|---|
| 2025 | BITSCTF | web | elysias-bakery | [README](2025/BITSCTF/web/elysias-bakery/README.md) | [src](2025/BITSCTF/web/elysias-bakery/src/) |
| 2025 | BITSCTF | web | rusty-proxy | [README](2025/BITSCTF/web/rusty-proxy/README.md) | [src](2025/BITSCTF/web/rusty-proxy/) |
| 2025 | WHYCTF | pwn | old-memes-never-die | [README](2025/WHYCTF/pwn/old-memes-never-die/README.md) | [src](2025/WHYCTF/pwn/old-memes-never-die/src/) |
| 2025 | WHYCTF | rev | 3-ball-mark | [README](2025/WHYCTF/rev/3-ball-mark/README.md) | [src](2025/WHYCTF/rev/3-ball-mark/src/) |

## 維護方式

- 新增題目時可先複製 `templates/challenge-README.md`
- 可以使用 `scripts/generate-index.py` 重新產生上方表格內容
