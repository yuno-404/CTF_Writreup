---
title: pyjail_calc
tags: [pythonjail, CTF]

---

```
#!/usr/local/bin/python3
from sys import addaudithook
from os import _exit
from re import match


def safe_eval(exit, code):
    def hook(*a):
        exit(0)
    def disabled_exit(*a):
        pass

    def dummy():
        pass

    dummy.__code__ = compile(code, "<code>", "eval")
    print("Activating audit hook...")
    addaudithook(hook)
    val = dummy()
    # audit hooks do not allow me to do important stuff afterwards, so i am disabling this one after eval completion
    # surely this won't have unintended effects down the line, ... right?
    print("Disabling audit hook...")
    exit = disabled_exit
    return val


if __name__ == "__main__":
    expr = input("Math expression: ")

    if len(expr) <= 200 and match(r"[0-9+\-*/]+", expr):
        # extra constraints just to make sure people don't use signal this time ...
        if len(expr) <= 75 and ' ' not in expr and '_' not in expr:
            print(safe_
            (_exit, expr))
        else:
            print('Unacceptable')
    else:
        print("Do you know what is a calculator?")

```

* if len(...)：長度限制。payload必須精簡。
* ' ' not in expr 和 '_' not in expr：字元限制。禁止底線 _ ，它封鎖了所有 __magic__ 方法的直接使用，比如 __import__、__class__ 等經典逃逸手法。
* match(r"[0-9+\-*/]+")：正則表達式過濾。
* addaudithook(hook)：稽核鉤子。這是一個現代 Python (3.8+) 的高級安全特性。hook 的內容是 exit(0)，極度嚴苛，意味著任何被監聽的「敏感操作」都會直接讓程式中斷。

----
初學導向

## match
```
match(r"[0-9+\-*/]+", expr)
```
* match() 函數有一個非常關鍵的特性：它只從字串的開頭開始匹配。如果開頭符合規則，就算後面有其他不符規則的字元，match() 也會回傳成功
```
0,type(...)
```
當 match() 看到這個字串時：
它看到了 0。
0 符合 [0-9+\-*/]+ 這個規則。
match() 立刻回報「成功！」，不再往後看。

## type()
用途一：檢查類型
```
x = 123
print(type(x))  # <class 'int'>
```
用途二：動態創建類別
```
type('ClassName', (ParentClasses,), {'attribute_name': value, ...})
```
* ClassName: 一個字串，表示新類別的名稱。
* ParentClasses: 一個元組，包含了所有父類別（如果沒有就用空元組 ()）。
* {...}: 一個字典，定義了這個新類別的所有屬性和方法。
```
class Dog:
    def bark(self):
        return "Woof!"

# type() 的方法 (用表達式)
DogFactory = type('Dog', (), {'bark': lambda self: "Woof!"})
```
## __ repr__
雙底線開頭和結尾的方法（例如 __init__、__add__、__len__）都有特殊含義。它們不是設計來讓你直接呼叫的（雖然也可以），而是由 Python 解譯器在特定情況下自動呼叫的。
```
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    # 我們來定義它的 "官方表示法"
    def __repr__(self):
        return f"Point(x={self.x}, y={self.y})"

# 創建一個物件
p = Point(10, 20)

# 當你在互動式環境中直接輸入變數名，或使用 repr() 函數時，__repr__ 會被自動呼叫
# In [1]: p
# Out[1]: Point(x=10, y=20)
```
print() 函數有一套清晰的工作流程：
* 它首先會嘗試尋找並呼叫物件的 __str__ 方法。__str__ 的設計初衷是提供一個給使用者看的、友好的字串。
* 如果這個物件沒有定義 __str__ 方法，print() 就會退而求其次，去尋找並呼叫 __repr__ 方法作為替代品。
```
class MyWeapon:
    def __str__(self):
        # 使用者看到的友好名稱
        return "一把強大的劍"

    def __repr__(self):
        # 開發者看到的內部表示
        return "<Weapon id=007 type='Sword'>"

weapon = MyWeapon()

# 直接 print 物件，會呼叫 __str__
print(weapon)
# 輸出: 一把強大的劍

# 將物件放入列表後，print 整個列表，會對裡面的物件呼叫 __repr__
inventory = [weapon, "一個盾牌"]
print(inventory)
# 輸出: ['<Weapon id=007 type='Sword'>', '一個盾牌']
```



## eval 字串可以變成程式碼
 class 關鍵字，但 class 是一個陳述式 (Statement)，而 eval() 只接受表達式 (Expression)
eval() 的本質：eval 是一個「表達式 (Expression)」求值器。表達式的核心是「計算並回傳一個值」。創建物件 (type(...)()) 就是一個表達式，它的計算結果就是那個新創的物件。
* 5 + 3 是一個表達式
* my_function()是一個表達式


```
# 攻擊者輸入了下面這個字串
malicious_input = "__import__('os').system('ls -l')"
# 伺服器端的程式碼如果這樣寫，就會出大事
result = eval(malicious_input)
```
* 當 eval() 執行這個字串時：
* __ import__('os')：動態地匯入 Python 的 os 模組，這個模組可以讓你跟作業系統互動。
* .system('ls -l')：呼叫 os 模組中的 system 函式，執行 shell 命令 ls -l 來列出伺服器當前目錄下的所有檔案

## addaudithook()
事件監聽系統。它並不理解程式碼的「意圖」，它只對「事件」做出反應
當 eval() 被呼叫，會觸發 exec 事件，hook 會響應。但 eval() 內部程式碼的執行，只有在觸發了其他特定事件（如 open、import）時，hook 才會再次響應。
```
sys.addaudithook(hook)
```
敏感事件 (Auditable Events)：Python 內部定義了一長串的敏感事件列表。這包括了：
* exec：當 compile(), exec(), eval() 被呼叫時觸發。
* open：當 open() 函數被呼叫時觸發。
* import：當 import 模組時觸發。
* os.system：當執行系統命令時觸發。


鉤子函數 (Hook Function)：這是一個由你來定義的函數。它決定了「當敏感事件發生時，要做什麼事」。它可以是簡單地把事件印出來做紀錄，也可以是採取激烈的手段，例如直接終止程式。
```
def hook(*a):
    exit(0) # 或 os._exit(0)
```
不管發生了什麼敏感事件 (*a 會接收事件的相關資訊，但這裡直接忽略)，都立刻呼叫 exit(0) 來終止程式
目前只要呼叫了eval就會發生中斷

## lambda
lambda 是一個表達式
* def add(x, y): ... 是一個陳述式 (Statement)。它的動作是「定義一個名為 add 的函數」。你不能把它放在 x = ... 的右邊，y = def add... 是非法的語法。
* lambda x, y: x + y 是一個表達式 (Expression)。它的「值」就是那個新創建的、匿名的函數物件。你可以直接把它賦值給變數 add_lambda = lambda

---
解題步驟:


## 逃逸字元限制 _
字元限制繞過
題目禁止使用底線 _，這使我們無法直接定義 __repr__ 等魔法方法。但是，Python 的字串解析器會處理十六進位轉義序列。\x5f 正是底線 _ 的十六進位表示。

如何利用: 我們用字串 '\x5f\x5frepr\x5f\x5f' 來作為 type() 函數屬性字典中的鍵。在執行時，Python 會將其解碼為 '__repr__'，從而成功繞過限制，指定了我們要覆寫的方法。

當 print() 函數需要顯示一個物件時，它會自動呼叫該物件的 __repr__() 或 __str__() 方法。特別是當物件被包含在一個容器（如本題中的元組）中時，print 為了顯示容器的清晰結構，會對容器內的每個物件呼叫其 __repr__() 方法

0,type('',(),{'\x5f\x5frepr\x5f\x5f': lambda*a:next(open('flag.txt'))})
![image](https://hackmd.io/_uploads/ryhKbkrpex.png)
