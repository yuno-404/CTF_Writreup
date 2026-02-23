# CTF Writeup

這個 repo 用來整理 CTF 題目附件、解題腳本與 writeup。
筆記與HACKMD同步: https://hackmd.io/@jfMsCWB5S_WoY26uOVJM4g  
被 binary 痛擊後，轉去 web 慢慢學習中

## 建議結構

```text
<year>/<event>/<category>/<challenge>/
  README.md
  src/
  solve/
  assets/
```

## Writeup 索引

| Year | Event | Category | Challenge | Writeup | Source |
|---|---|---|---|---|---|
| 2025 | BRUNNERCTF | pwn | the-ingredient-shop | [Link](2025/BRUNNERCTF/pwn_the-ingredient-shop/README.md) | [src](2025/BRUNNERCTF/pwn_the-ingredient-shop) |
| 2025 | BRUNNERCTF | pwn | the-ingredient-shop-s-revenge | [Link](2025/BRUNNERCTF/pwn_the-ingredient-shop-s-revenge/README.md) | [src](2025/BRUNNERCTF/pwn_the-ingredient-shop-s-revenge) |
| 2025 | IDEKCTF | articles | idekctf2025-constructor | [Link](2025/IDEKCTF/articles/idekctf2025-constructor/README.md) | [src](2025/IDEKCTF/articles/idekctf2025-constructor) |
| 2025 | JAILCTF | pyjail | assem | [Link](2025/JAILCTF/assem/README.md) | [src](2025/JAILCTF/assem) |
| 2025 | JAILCTF | pyjail | blindness | [Link](2025/JAILCTF/blindness/README.md) | [src](2025/JAILCTF/blindness) |
| 2025 | JAILCTF | pyjail | calc | [Link](2025/JAILCTF/calc/README.md) | [src](2025/JAILCTF/calc) |
| 2025 | WHYCTF | pwn | old-memes-never-die | [Link](2025/WHYCTF/pwn/old-memes-never-die/README.md) | [src](2025/WHYCTF/pwn/old-memes-never-die/src) |
| 2025 | WHYCTF | rev | 3-ball-mark | [Link](2025/WHYCTF/rev/3-ball-mark/README.md) | [src](2025/WHYCTF/rev/3-ball-mark/src) |
| 2026 | AIS3EOF | articles | ais3-eof-2026-ebpf-challenge-writeup | [Link](2026/AIS3EOF/articles/ais3-eof-2026-ebpf-challenge-writeup/README.md) | [src](2026/AIS3EOF/articles/ais3-eof-2026-ebpf-challenge-writeup) |
| 2026 | AIS3EOF | articles | ais3-eof-2026-writeup-firmware-signal-analysis | [Link](2026/AIS3EOF/articles/ais3-eof-2026-writeup-firmware-signal-analysis/README.md) | [src](2026/AIS3EOF/articles/ais3-eof-2026-writeup-firmware-signal-analysis) |
| 2026 | AIS3EOF | articles | ais3-eof-2026-writeup-seccomp-as-a-sandbox-saas | [Link](2026/AIS3EOF/articles/ais3-eof-2026-writeup-seccomp-as-a-sandbox-saas/README.md) | [src](2026/AIS3EOF/articles/ais3-eof-2026-writeup-seccomp-as-a-sandbox-saas) |
| 2026 | AIS3EOF | articles | ais3-eof-2026-writeup-structured-small | [Link](2026/AIS3EOF/articles/ais3-eof-2026-writeup-structured-small/README.md) | [src](2026/AIS3EOF/articles/ais3-eof-2026-writeup-structured-small) |
| 2026 | BITSCTF | web | elysias-bakery | [Link](2026/BITSCTF/web/elysias-bakery/README.md) | [src](2026/BITSCTF/web/elysias-bakery/src) |
| 2026 | BITSCTF | web | rusty-proxy | [Link](2026/BITSCTF/web/rusty-proxy/README.md) | [src](2026/BITSCTF/web/rusty-proxy) |

## 維護方式

- 新增題目時，建議先複製 `templates/challenge-README.md`
- 重新產生索引表：`python scripts/generate-index.py`
