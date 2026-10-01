--[[ -made by Kaan abiniz :)
╔══════════════════════════════════════════════════════════════════╗
║         ROBLOX DEEP SECURITY SCANNER v0.1                       ║
║  Heuristik statik analiz — Roblox güvenlik dokümantasyonuna göre ║
║  create.roblox.com/docs/scripting/security/security-tactics      ║
╚══════════════════════════════════════════════════════════════════╝

KURULUM:
  File → Plugins Folder → bu dosyayı oraya koy → Studio restart 
  Plugins sekmesinde "🔍 Deep Scan" butonuna tıkla

ÖNEMLİ: Bu araç statik ve heuristiktir. Yanlış pozitif / yanlış negatif olabilir;
        gerçek güvenliğin yerine geçmez. Kritik remote'ları elle de incele.
]]

-- ─────────────────────────────────────────────────────────────────
-- TEMEL
-- ─────────────────────────────────────────────────────────────────
local function SVC(name)
    return game:GetService(name)
end

local toolbar = plugin:CreateToolbar("Deep Security Scanner")
local scanBtn = toolbar:CreateButton(
    "DeepScan",
    "Script ve remote'ları Roblox güvenlik önerilerine göre heuristik olarak analiz et",
    "rbxassetid://4458901886",
    "🔍 Deep Scan"
)

local ROOT_NAMES = {
    "Workspace", "ServerScriptService", "ServerStorage", "ReplicatedStorage",
    "ReplicatedFirst", "StarterPlayer", "StarterGui", "StarterPack", "Lighting",
}

local DOWN = { CRITICAL = "HIGH", HIGH = "MEDIUM", MEDIUM = "LOW", LOW = "LOW" }

-- ─────────────────────────────────────────────────────────────────
-- RAPOR SİSTEMİ
-- ─────────────────────────────────────────────────────────────────
local REPORT, SCAN_STATS, NOTES
local FINDINGS, IGNORED, LAST_KEYS = {}, {}, {}

local function resetAll()
    FINDINGS = {}
    REPORT = { CRITICAL = {}, HIGH = {}, MEDIUM = {}, LOW = {}, OK = {} }
    SCAN_STATS = {
        remotes = 0, serverScripts = 0, clientScripts = 0, sharedScripts = 0,
        unreadable = 0, totalIssues = 0,
    }
    NOTES = {}
end
resetAll()

-- Baseline anahtarı: başlık + (satır numarasız) yol → kod kayınca da aynı bulgu tanınır
local function makeKey(title, path)
    return title .. "@" .. (path:gsub("%s*%(satır[^%)]*%)", ""))
end

-- meta = { obj = açılacak script, line = satır, sel = Explorer'da seçilecek nesne }
local function issue(level, title, path, detail, fix, meta)
    if not REPORT[level] then level = "LOW" end
    local f = {
        level = level, title = title, path = path, detail = detail, fix = fix or "—",
        key = makeKey(title, path), seq = #FINDINGS + 1,
    }
    if meta then
        f.obj, f.line, f.sel = meta.obj, meta.line, meta.sel
        f.cat, f.remote = meta.cat, meta.remote
    end
    f.hay = (title .. " " .. path .. " " .. detail):lower()
    f.isNew = next(LAST_KEYS) ~= nil and not LAST_KEYS[f.key] and level ~= "OK"
    table.insert(REPORT[level], f)
    table.insert(FINDINGS, f)
    if level ~= "OK" then
        SCAN_STATS.totalIssues += 1
    end
end

-- Baseline (yok sayılanlar) ve son tarama anahtarları: plugin ayarlarında saklanır
local function loadSettings()
    local ok, v = pcall(function() return plugin:GetSetting("DeepScanIgnored") end)
    IGNORED = (ok and type(v) == "table") and v or {}
    local ok2, v2 = pcall(function() return plugin:GetSetting("DeepScanLastKeys") end)
    LAST_KEYS = (ok2 and type(v2) == "table") and v2 or {}
end

local function saveIgnored()
    pcall(function() plugin:SetSetting("DeepScanIgnored", IGNORED) end)
end

local function saveLastKeys()
    local t = {}
    for _, f in ipairs(FINDINGS) do
        if f.level ~= "OK" then t[f.key] = true end
    end
    LAST_KEYS = t
    pcall(function() plugin:SetSetting("DeepScanLastKeys", t) end)
end
loadSettings()

-- ─────────────────────────────────────────────────────────────────
-- YARDIMCI FONKSİYONLAR
-- ─────────────────────────────────────────────────────────────────
local opCount = 0
local function throttle()
    opCount += 1
    if opCount % 40 == 0 then
        task.wait()
    end
end

local function getPath(obj)
    local parts, cur = {}, obj
    while cur and cur ~= game do
        table.insert(parts, 1, cur.Name)
        cur = cur.Parent
    end
    return table.concat(parts, ".")
end

local function readSource(obj)
    local ok, src = pcall(function() return obj.Source end)
    if ok and type(src) == "string" then
        return src, true
    end
    return "", false
end

local function splitLines(src)
    local lines = {}
    for line in (src .. "\n"):gmatch("([^\n]*)\n") do
        lines[#lines + 1] = line
    end
    return lines
end

local function lineAt(text, pos)
    local _, n = text:sub(1, pos):gsub("\n", "")
    return n + 1
end

local function escapePat(s)
    return (s:gsub("[%^%$%(%)%%%.%[%]%*%+%-%?]", "%%%0"))
end

-- İsmi kelime sınırlarıyla eşleştiren pattern (isim özel karakterle başlıyorsa sınır koymaz)
local function bounded(name)
    local pre  = name:match("^[%w_]") and "%f[%w_]" or ""
    local post = name:match("[%w_]$") and "%f[^%w_]" or ""
    return pre .. escapePat(name) .. post
end

local function anyPlain(text, list)
    for _, w in ipairs(list) do
        if text:find(w, 1, true) then return w end
    end
    return nil
end

-- ─────────────────────────────────────────────────────────────────
-- KAYNAK TEMİZLEME: yorumları at, string içeriklerinin "kör" kopyasını üret
--   kept  : yorumsuz, string'ler duruyor (isim/pattern eşleştirme için)
--   blank : yorumsuz, string içi boşluk (yapısal analiz için: end/do sayımı)
--   İki çıktı da AYNI uzunlukta ve aynı satır yapısında (offset'ler eşleşir).
-- ─────────────────────────────────────────────────────────────────
local function stripSource(src)
    local kept, blank = {}, {}
    local i, n = 1, #src

    local function push(k, b)
        kept[#kept + 1] = k
        blank[#blank + 1] = b
    end
    local function spaces(s) return (s:gsub("[^\n]", " ")) end
    local function newlinesOnly(s) return (s:gsub("[^\n]", "")) end

    while i <= n do
        local c = src:sub(i, i)

        if c == "-" and src:sub(i + 1, i + 1) == "-" then
            -- yorum
            local eq = src:match("^%-%-%[(=*)%[", i)
            if eq then
                local close = "]" .. eq .. "]"
                local _, e = src:find(close, i + 4 + #eq, true)
                local stop = e or n
                local nl = newlinesOnly(src:sub(i, stop))
                push(nl, nl)
                i = stop + 1
            else
                local e = src:find("\n", i, true)
                i = e or (n + 1)   -- satır sonunu bırak, sonraki turda eklenir
            end

        elseif c == '"' or c == "'" or c == "`" then
            local j = i + 1
            while j <= n do
                local cj = src:sub(j, j)
                if cj == "\\" then
                    j += 2
                elseif cj == c then
                    break
                elseif cj == "\n" and c ~= "`" then
                    break
                else
                    j += 1
                end
            end
            local stop = math.min(j, n)
            local s = src:sub(i, stop)
            local b
            if stop > i then
                b = c .. spaces(s:sub(2, -2)) .. s:sub(-1)
            else
                b = c
            end
            push(s, b)
            i = stop + 1

        elseif c == "[" and src:match("^%[=*%[", i) then
            local eq = src:match("^%[(=*)%[", i)
            local close = "]" .. eq .. "]"
            local _, e = src:find(close, i + 2 + #eq, true)
            local stop = e or n
            local s = src:sub(i, stop)
            push(s, spaces(s))
            i = stop + 1

        else
            local nxt = src:find("[%-\"'`%[]", i + 1) or (n + 1)
            local s = src:sub(i, nxt - 1)
            push(s, s)
            i = nxt
        end
    end

    return table.concat(kept), table.concat(blank)
end

-- ─────────────────────────────────────────────────────────────────
-- BLOK SONU BULUCU (function / while / repeat gövdeleri için)
-- blank kaynağında startPos'tan başlar, ilgili bloğun son karakter index'ini döner
-- ─────────────────────────────────────────────────────────────────
local function findBlockEnd(blank, startPos, maxLen)
    local sub = blank:sub(startPos, startPos + (maxLen or 60000))
    local depth, started = 0, false

    for pos, word in sub:gmatch("()([%a_][%w_]*)") do
        local delta = 0
        if word == "function" or word == "do" or word == "repeat" then
            delta = 1
        elseif word == "if" then
            -- Luau if-expression (x = if a then b else c) 'end' ile kapanmaz
            local win = sub:sub(math.max(1, pos - 40), pos - 1)
            local prevChar = win:match("(%S)%s*$")
            local prevWord = win:match("([%a_][%w_]*)%s*$")
            local isExpr = false
            if prevChar and prevChar:find("[=%(,{%+%-%*/%^<>~%[%.#:]") then isExpr = true end
            if prevWord == "return" or prevWord == "and" or prevWord == "or" or prevWord == "not" then
                isExpr = true
            end
            if prevWord == "else" and win:match("else[ \t]*$") then isExpr = true end
            if not isExpr then delta = 1 end
        elseif word == "end" or word == "until" then
            delta = -1
        end

        if delta ~= 0 then
            depth += delta
            if delta > 0 then started = true end
            if started and depth <= 0 then
                return startPos + pos + #word - 2
            end
        end
    end
    return nil
end

-- ─────────────────────────────────────────────────────────────────
-- SCRIPT İNDEKSİ
-- ─────────────────────────────────────────────────────────────────
local INFOS, REMOTES, INFO_BY_OBJ = {}, {}, {}

local function getRoots()
    local list = {}
    for _, n in ipairs(ROOT_NAMES) do
        local ok, svc = pcall(SVC, n)
        if ok and svc then list[#list + 1] = svc end
    end
    return list
end

local function inService(obj, name)
    local ok, svc = pcall(SVC, name)
    return ok and svc ~= nil and obj:IsDescendantOf(svc)
end

local function isClientAccessible(obj)
    for _, n in ipairs({ "ReplicatedStorage", "Workspace", "StarterGui", "StarterPlayer",
                         "StarterPack", "ReplicatedFirst", "Lighting" }) do
        if inService(obj, n) then return true end
    end
    return false
end

local function runContextOf(obj)
    local ok, rc = pcall(function() return obj.RunContext end)
    if ok and rc ~= nil then
        return tostring(rc):match("([^%.]+)$") or "Legacy"
    end
    return "Legacy"
end

-- "server" | "client" | "shared"
local function classify(obj)
    if obj:IsA("LocalScript") then return "client" end
    if obj:IsA("Script") then
        if runContextOf(obj) == "Client" then return "client" end
        return "server"
    end
    -- ModuleScript
    if inService(obj, "ServerScriptService") or inService(obj, "ServerStorage") then return "server" end
    if inService(obj, "StarterPlayer") or inService(obj, "StarterGui")
       or inService(obj, "StarterPack") or inService(obj, "ReplicatedFirst") then
        return "client"
    end
    return "shared"
end

local function buildIndex()
    INFOS, REMOTES, INFO_BY_OBJ = {}, {}, {}
    for _, root in ipairs(getRoots()) do
        for _, obj in ipairs(root:GetDescendants()) do
            throttle()
            if obj:IsA("LuaSourceContainer") then
                local src, ok = readSource(obj)
                if not ok then SCAN_STATS.unreadable += 1 end
                local kept, blank = stripSource(src)
                local kind = classify(obj)
                local entry = {
                    obj = obj, name = obj.Name, path = getPath(obj), kind = kind,
                    src = kept, blank = blank, lines = splitLines(kept), blankLines = splitLines(blank), ok = ok,
                }
                INFOS[#INFOS + 1] = entry
                INFO_BY_OBJ[obj] = entry
                if kind == "server" then SCAN_STATS.serverScripts += 1
                elseif kind == "client" then SCAN_STATS.clientScripts += 1
                else SCAN_STATS.sharedScripts += 1 end
            elseif obj:IsA("RemoteEvent") or obj:IsA("RemoteFunction") then
                REMOTES[#REMOTES + 1] = obj
            end
        end
    end
    SCAN_STATS.remotes = #REMOTES
end

-- ─────────────────────────────────────────────────────────────────
-- SATIR TABANLI KURAL MOTORU
-- rule = { level (string|function(info)), title, detail, fix, test(line, info, i), gate(info)? }
-- Aynı script + aynı kural için TEK rapor, satır numaraları listelenir bacım.
-- ─────────────────────────────────────────────────────────────────
local function has(pat)
    return function(line) return line:find(pat) ~= nil end
end

local function runLineRules(info, rules, shiftLevel)
    local active = {}
    for _, rule in ipairs(rules) do
        if not rule.gate or rule.gate(info) then active[#active + 1] = rule end
    end
    if #active == 0 then return 0 end

    local hits = {}
    for i, line in ipairs(info.lines) do
        if line ~= "" then
            local bl = info.blankLines[i]
            for _, rule in ipairs(active) do
                -- rule.strings = true → string içeriği gereken kural (yorumsuz kaynak);
                -- aksi halde string içeriği boşaltılmış kopya (string içindeki metin yanlış pozitif vermez)
                if rule.test(rule.strings and line or bl, info, i) then
                    local h = hits[rule]
                    if not h then h = {}; hits[rule] = h end
                    h[#h + 1] = i
                end
            end
        end
    end

    local emitted = 0
    for _, rule in ipairs(active) do
        local h = hits[rule]
        if h then
            local level = type(rule.level) == "function" and rule.level(info) or rule.level
            local title = rule.title
            if shiftLevel then
                level = DOWN[level]
                title = title .. " (paylaşılan modül)"
            end
            local shown = {}
            for k = 1, math.min(#h, 8) do shown[k] = tostring(h[k]) end
            local linesStr = table.concat(shown, ", ") .. (#h > 8 and (" +" .. (#h - 8) .. " satır") or "")
            local preview = info.lines[h[1]]:gsub("^%s+", ""):sub(1, 80)
            issue(level,
                "[" .. info.name .. "] " .. title,
                info.path .. " (satır " .. linesStr .. ")",
                rule.detail .. '\n         Kod: "' .. preview .. '"',
                rule.fix, { obj = info.obj, line = h[1] })
            emitted += 1
        end
    end
    return emitted
end

-- ─────────────────────────────────────────────────────────────────
-- KURAL SETLERİ
-- ─────────────────────────────────────────────────────────────────
local function hasHttpRequests(s)
    return s:find("HttpService", 1, true)
       and (s:find("GetAsync", 1, true) or s:find("RequestAsync", 1, true) or s:find("PostAsync", 1, true))
end

-- Her script türünde taranır (backdoor / exploit imzaları)
local COMMON_RULES = {
    {
        level = function(info) return hasHttpRequests(info.src) and "CRITICAL" or "HIGH" end,
        title = "loadstring kullanımı",
        test  = has("%f[%w_]loadstring%s*%("),
        detail = "loadstring dinamik kod çalıştırır. Backdoor'larda sık görülür; özellikle HttpService ile uzaktan kod çekiliyorsa (bu dosyada öyle görünüyorsa seviye KRİTİK'e çıkar) uzaktan kod çalıştırma demektir. Meşru kullanımı da vardır, o yüzden kaynağı incele.",
        fix = "Kendi kodun değilse sil. Gerçekten gerekiyorsa girdinin güvenilir olduğundan emin ol.",
    },
    {
        level = "HIGH",
        title = "Sayısal asset ID ile require",
        test  = has("require%s*%(%s*%d%d+%s*%)"),
        detail = "require(assetId) uzak bir asset'i yükler. Asset sana ait değilse veya sonradan güncellenmişse backdoor içerebilir. Kendi yüklediğin/bildiğin bir modülse sorun yok.",
        fix = "Asset'i kendi hesabına/grubuna ait olduğundan emin ol veya modülü projeye kopyala: require(script.Parent.ModuleName)",
    },
    {
        level = "HIGH",
        title = "getfenv() kullanımı",
        test  = has("%f[%w_]getfenv%s*%("),
        detail = "getfenv, environment manipülasyonu için exploit araçlarında yaygın, ama bazı meşru kütüphanelerde de görülür. Kaynağını incele.",
        fix = "Kendi kodun değilse sil.",
    },
    {
        level = "HIGH",
        title = "setfenv() kullanımı",
        test  = has("%f[%w_]setfenv%s*%("),
        detail = "setfenv script environment'ını değiştirir. Meşru sandbox kütüphanelerinde de olabilir; kaynağını incele.",
        fix = "Kendi kodun değilse sil.",
    },
}

-- LocalScript ve paylaşılan modüllerde taranır
local CLIENT_RULES = {
    {
        level = "CRITICAL",
        title = "DataStoreService client tarafında",
        strings = true,
        test  = has("DataStoreService"),
        detail = "DataStoreService yalnızca server'da çalışır; client'ta kullanmak hata verir. Paylaşılan modülse, bu modülü client require ederse patlar.",
        fix = "DataStore işlemlerini server Script/ModuleScript'e taşı; client RemoteEvent ile istek göndersin.",
    },
    {
        level = "HIGH",
        title = "Discord webhook URL'si client'ta görünür",
        strings = true,
        test  = has("discord[app]*%.com/api/webhooks"),
        detail = "Client'a replicate olan kodda webhook URL'si bulunuyor. Exploiter Source'u okuyup URL'yi kötüye kullanabilir.",
        fix = "Webhook çağrısını server'a taşı ve URL'yi client'a replicate olmayan bir yerde (ServerStorage/ServerScriptService) tut.",
    },
    {
        level = "MEDIUM",
        title = "leaderstats değeri client'ta yazılıyor",
        strings = true,
        test  = has("leaderstats[^\n]-%.Value%s*[%+%-%*/]?=[^=]"),
        detail = "Client'ta leaderstats.Value değiştirmek server'a yansımaz; yalnız o client'ta görünen sahte bir değer olur. Ya işlevsiz bir koddur ya da mantığı client'a yıktığının işaretidir. (Okumak sorun değildir.)",
        fix = "Stat yazımını server'da yap; client RemoteEvent ile sadece niyetini bildirsin ve server doğrulasın.",
    },
    {
        level = "MEDIUM",
        title = "Humanoid.Health client'ta atanıyor",
        test  = has("%.Health%s*[%+%-%*/]?=[^=]"),
        detail = "Health client'tan server'a replicate olmaz; değişiklik yalnız yerel görünür. Sağlık mantığı client'a yaslanmışsa güvenilmezdir.",
        fix = "Hasar/iyileşme mantığını server'da yönet (Humanoid:TakeDamage vb.).",
    },
    {
        level = "MEDIUM",
        title = "WalkSpeed client'ta değiştiriliyor",
        test  = has("%.WalkSpeed%s*[%+%-%*/]?=[^=]"),
        detail = "Karakterin sahibi client olduğu için WalkSpeed değişikliği fiziksel harekete yansır ve server bunu doğrulamaz. Sprint gibi meşru bir özellik olabilir, ama exploiter aynı yolla speed-hack yapabilir.",
        fix = "Hızı server'da ata ve server tarafında hareket hızını periyodik doğrula (anti-cheat).",
    },
    {
        level = "MEDIUM",
        title = "JumpPower/JumpHeight client'ta değiştiriliyor",
        test  = function(line)
            return line:find("%.JumpPower%s*[%+%-%*/]?=[^=]") ~= nil
                or line:find("%.JumpHeight%s*[%+%-%*/]?=[^=]") ~= nil
        end,
        detail = "WalkSpeed ile aynı mantık: client'ta atanan değer fiziğe yansır, server doğrulamaz.",
        fix = "Değeri server'da yönet ve doğrula.",
    },
    {
        level = "MEDIUM",
        title = "HttpService ile HTTP isteği client'ta",
        gate  = function(info)
            return info.src:find("HttpService", 1, true) ~= nil
               and info.src:find("DataStoreService", 1, true) == nil
        end,
        test  = function(line)
            return line:find(":%s*RequestAsync%s*%(") ~= nil
                or line:find(":%s*PostAsync%s*%(") ~= nil
                or line:find(":%s*GetAsync%s*%(") ~= nil
        end,
        detail = "HttpService istekleri (GetAsync/PostAsync/RequestAsync) client'ta çalışmaz. (JSONEncode/GenerateGUID gibi diğer fonksiyonlar client'ta sorunsuzdur.)",
        fix = "HTTP isteğini server Script'e taşı.",
    },
    {
        level = "LOW",
        title = "FireServer() parametresiz",
        test  = has(":%s*FireServer%s*%(%s*%)"),
        detail = "Parametresiz çağrı kendi başına sorun değildir; ama handler yalnız `player` ile bir şey tetikliyorsa server'ın durumu (pozisyon, sahiplik, cooldown) kendisinin doğruladığından emin ol.",
        fix = "Handler tarafında state doğrulaması yapıldığını kontrol et.",
    },
    {
        level = "LOW",
        title = "RemoteFunction:InvokeServer kullanımı",
        test  = has(":%s*InvokeServer%s*%("),
        detail = "Server handler hata verirse veya hiç return etmezse çağıran client thread'i beklemede kalır (timeout yok). Sonuç doğruluk için değil, UI için kullanılmalı; asla güven kaynağı değildir.",
        fix = "pcall ile sar; mümkünse RemoteEvent + yanıt event'i kullan.",
    },
    {
        level = "LOW",
        title = "Part.Anchored client'ta değiştiriliyor",
        test  = has("%.Anchored%s*=[^=]"),
        detail = "Client'ta yapılan Anchored değişikliği server'a yansımaz; oyuncular arasında görsel tutarsızlık yaratır.",
        fix = "Değişikliği server'da yap.",
    },
    {
        level = "LOW",
        title = "TeleportService client tarafında",
        strings = true,
        test  = has("TeleportService"),
        detail = "Client kendi karakterini teleport edebilir, ama teleport verisi/kararı client'a bırakılırsa istismar edilebilir.",
        fix = "Teleport kararını ve verisini server'da ver, client sadece UI göstersin.",
    },
}

-- Server tarafında çalışan script'lerde taranır
local SERVER_RULES = {
    {
        level = "CRITICAL",
        title = "LocalPlayer server'da kullanılıyor",
        test  = has("%f[%w_]LocalPlayer%f[^%w_]"),
        detail = "Players.LocalPlayer server'da nil'dir. Üzerine erişmek 'attempt to index nil' hatası verir ve ilgili thread durur.",
        fix = "LocalPlayer'ı LocalScript'e taşı. Server'da Players:GetPlayers() veya OnServerEvent'in player argümanını kullan.",
    },
    {
        level = "HIGH",
        title = "RemoteFunction:InvokeClient kullanılıyor",
        test  = has(":%s*InvokeClient%s*%("),
        detail = "Client yanıt vermezse (exploiter bilerek dönmeyebilir) veya oyuncu çıkarsa çağıran server thread'i takılabilir. Roblox bu kullanımı önermez.",
        fix = "RemoteEvent (FireClient) ve gerekirse ikinci bir RemoteEvent ile yanıt al; ya da pcall + zaman aşımı mantığı kur.",
    },
    {
        level = "HIGH",
        title = "FindFirstChild sonucu nil kontrolsüz kullanılıyor",
        test  = function(line)
            for tail in line:gmatch(":%s*FindFirstChild%w*%s*%b()%s*(.?.?)") do
                local c = tail:sub(1, 1)
                if (c == "." and tail:sub(2, 2) ~= ".") or c == ":" or c == "[" then
                    return true
                end
            end
            return false
        end,
        detail = "FindFirstChild nesne yoksa nil döner; hemen ardından . veya : ile erişmek 'attempt to index nil' hatası verir ve script durur.",
        fix = "Önce sonucu değişkene al ve kontrol et:\n  local obj = parent:FindFirstChild(\"Name\")\n  if not obj then return end",
    },
    {
        level = "HIGH",
        title = "DataStore çağrısı pcall olmadan",
        gate  = function(info)
            local s = info.src
            return s:find("DataStoreService", 1, true) ~= nil or s:find("GetDataStore", 1, true) ~= nil
                or s:find("OrderedDataStore", 1, true) ~= nil
        end,
        test  = function(line, info, i)
            if not (line:find(":%s*GetAsync%s*%(") or line:find(":%s*SetAsync%s*%(")
                or line:find(":%s*UpdateAsync%s*%(") or line:find(":%s*IncrementAsync%s*%(")
                or line:find(":%s*RemoveAsync%s*%(") or line:find(":%s*GetSortedAsync%s*%(")) then
                return false
            end
            for j = math.max(1, i - 8), i do
                local l = info.lines[j]:lower()
                if l:find("pcall", 1, true) or l:find("retry", 1, true)
                   or l:find("safecall", 1, true) or l:find("promise", 1, true) then
                    return false
                end
            end
            return true
        end,
        detail = "DataStore çağrıları throttle/timeout ile hata fırlatabilir. pcall yoksa hata thread'i durdurur ve veri kaybı olabilir. (Heuristik: çağrıdan önceki 8 satırda pcall/retry sarmalayıcısı aranır.)",
        fix = "Çağrıyı pcall içine al:\n  local ok, err = pcall(function() store:SetAsync(key, val) end)\n  if not ok then warn(err) end",
    },
    {
        level = "MEDIUM",
        title = "Server'da LocalScript dinamik oluşturuluyor",
        strings = true,
        test  = has("Instance%.new%s*%(%s*[\"']LocalScript[\"']"),
        detail = "Runtime'da LocalScript üretmek yönetimi zorlaştırır ve genelde gereksizdir.",
        fix = "LocalScript'leri önceden hazırla (StarterPlayerScripts vb.), runtime'da üretme.",
    },
    {
        level = "LOW",
        title = "WaitForChild timeout'suz (server)",
        test  = function(line)
            for args in line:gmatch(":%s*WaitForChild%s*(%b())") do
                local inner = args:sub(2, -2):gsub("%b()", "")
                if not inner:find(",", 1, true) then return true end
            end
            return false
        end,
        detail = "Server'da WaitForChild'a timeout verilmemiş; nesne hiç gelmezse script sonsuza kadar bekler (uyarı: 'Infinite yield possible').",
        fix = 'Timeout ekle ve nil kontrolü yap: :WaitForChild("Name", 5)',
    },
    {
        level = "LOW",
        title = "Deprecated wait() kullanımı",
        test  = function(line)
            return line:find("^wait%s*%(") ~= nil or line:find("[^%w_%.:]wait%s*%(") ~= nil
        end,
        detail = "wait() deprecated. task.wait() daha tutarlı ve performanslı çalışır.",
        fix = "wait() → task.wait()",
    },
    {
        level = "LOW",
        title = "Deprecated spawn()/delay() kullanımı",
        test  = function(line)
            return line:find("^spawn%s*%(") ~= nil or line:find("[^%w_%.:]spawn%s*%(") ~= nil
                or line:find("^delay%s*%(") ~= nil or line:find("[^%w_%.:]delay%s*%(") ~= nil
        end,
        detail = "spawn()/delay() deprecated ve throttle'lı çalışır.",
        fix = "spawn → task.spawn, delay → task.delay",
    },
}

-- ─────────────────────────────────────────────────────────────────
-- DÖNGÜ ANALİZİ (yield'siz sonsuz döngü)
-- ─────────────────────────────────────────────────────────────────
local function hasYield(chunk)
    return chunk:find("%f[%w_][Ww]ait%s*%(") ~= nil
        or chunk:find("coroutine%.yield") ~= nil
        or chunk:find("%f[%w_]break%f[^%w_]") ~= nil
        or chunk:find("%f[%w_]return%f[^%w_]") ~= nil
end

local function scanLoops(info)
    local blank = info.blank
    local function flag(pos, what)
        issue("HIGH",
            "[" .. info.name .. "] " .. what .. " içinde yield yok",
            info.path .. " (satır " .. lineAt(blank, pos) .. ")",
            "Döngü gövdesinde wait/task.wait/Wait()/break/return bulunamadı. Bu döngü yield etmeden çalışırsa thread'i bloklar ve script (bazen tüm server) donar.",
            "Döngü gövdesine task.wait(n) ekle.", { obj = info.obj, line = lineAt(blank, pos) })
    end

    local pos = 1
    while true do
        local s = blank:find("%f[%w_]while%s+true%s+do%f[^%w_]", pos)
        if not s then break end
        local e = findBlockEnd(blank, s)
        local chunk = blank:sub(s, e or (s + 4000))
        if not hasYield(chunk) then flag(s, "while true do") end
        pos = s + 1
    end

    pos = 1
    while true do
        local s = blank:find("%f[%w_]repeat%f[^%w_]", pos)
        if not s then break end
        local e = findBlockEnd(blank, s)
        if e and blank:sub(e + 1, e + 20):match("^%s*false%f[^%w_]") then
            local chunk = blank:sub(s, e)
            if not hasYield(chunk) then flag(s, "repeat ... until false") end
        end
        pos = s + 1
    end
end

-- ─────────────────────────────────────────────────────────────────
-- REMOTE ↔ HANDLER EŞLEŞTİRME
-- ─────────────────────────────────────────────────────────────────
local CLIENT_MEMBERS = { "OnClientEvent", "OnClientInvoke", "FireClient", "FireAllClients", "InvokeClient" }

-- src içinde `name` remote'una ait `member` erişimi var mı? (doğrudan veya alias ile)
-- Dönen değer: member ismi başlangıç pozisyonu (kept içinde) veya nil
local function findMemberUse(src, name, members)
    local nb = bounded(name)
    for _, m in ipairs(members) do
        -- Doğrudan: X.Name.OnServerEvent, WaitForChild("Name").OnServerEvent, X["Name"].OnServerEvent
        local direct = nb .. "[\"'%]%),%d%s%.]-[%.:]%s*()" .. m .. "%f[^%w_]"
        local _, _, pos = src:find(direct)
        if pos then return pos, m end

        -- Alias: local r = ...Name   →   r.OnServerEvent
        for alias in src:gmatch("([%a_][%w_]*)%s*=[^\n]-" .. nb) do
            if alias ~= name then
                local viaAlias = "%f[%w_]" .. alias .. "%s*[%.:]%s*()" .. m .. "%f[^%w_]"
                local _, _, p2 = src:find(viaAlias)
                if p2 then return p2, m end
            end
        end
    end
    return nil
end

-- Handler fonksiyonunun başlangıcını bul (isimli fonksiyona referans için)
local function lookupFunctionDef(info, ident)
    local base = ident:match("([%w_]+)$")
    if not base then return nil end
    local blank = info.blank
    local s = blank:find("%f[%w_]function%s+[%w_%.:]-%f[%w_]" .. base .. "%s*%(")
    if s then return s end
    local _, _, p = blank:find("%f[%w_]" .. base .. "%s*=%s*()function%f[^%w_]")
    return p
end

-- OnServerEvent:Connect(function(...) ... end)  /  OnServerInvoke = function(...) ... end
-- /  :Connect(namedFunc)  →  handler gövdesi + parametre isimleri
local function extractHandler(info, memberPos)
    local blank, kept = info.blank, info.src
    local rest = blank:sub(memberPos, memberPos + 300)
    local fs

    local off = rest:match("^OnServer%a+%s*:%s*%a+%s*%(%s*()function%f[^%w_]")
             or rest:match("^OnServer%a+%s*=%s*()function%f[^%w_]")
    if off then
        fs = memberPos + off - 1
    else
        local ident = rest:match("^OnServer%a+%s*:%s*%a+%s*%(%s*([%w_%.:]+)%s*[%),]")
                   or rest:match("^OnServer%a+%s*=%s*([%w_%.:]+)")
        if ident then fs = lookupFunctionDef(info, ident) end
    end
    if not fs then return nil end

    local e = findBlockEnd(blank, fs)
    if not e then return nil end

    local body = kept:sub(fs, e)
    local paramStr = body:match("^function[%s%w_%.:]-%(([^%)]*)%)")
    local params = {}
    for part in (paramStr or ""):gmatch("[^,]+") do
        local pn = part:match("^%s*([%a_][%w_]*)")
        if pn then
            params[#params + 1] = pn
        elseif part:find("%.%.%.") then
            params[#params + 1] = "..."
        end
    end
    return body, params
end

-- ─────────────────────────────────────────────────────────────────
-- HANDLER ANALİZİ
-- ─────────────────────────────────────────────────────────────────
local ECONOMY_WORDS = { "currency", "cash", "coins", "coin", "gold", "bucks", "money", "leaderstats", "points", "gems", "gem" }
local PRIV_NAME_WORDS = { "admin", "kick", "ban", "command", "execute", "give", "setmoney", "addmoney", "addcash",
                          "setlevel", "godmode", "noclip", "teleportto", "setspeed", "sethealth" }
local PRIV_GUARD_WORDS = { "admin", "rank", "group", "whitelist", "permission", "owner", "creatorid", "role" }
local PRICE_PARAM_WORDS = { "price", "cost", "amount", "quantity", "qty", "money", "cash", "coins" }
local TARGET_PARAM_WORDS = { "target", "userid", "victim", "other", "playerid", "playername" }
local SERVER_TABLE_PATS = { "items?%[", "shop%[", "store%[", "prices%[", "config%[", "catalog%[",
                            "%]%.price", "%]%.cost", "getprice", "serverprice" }

local function pRef(p)
    return "%f[%w_]" .. p .. "%f[^%w_]"
end

-- parametre için tip/nil/varlık doğrulaması var mı?
local function isGuarded(body, p)
    local r = pRef(p)
    local tests = {
        "typeof%s*%(%s*" .. r,
        "%f[%w_]type%s*%(%s*" .. r,
        "tonumber%s*%(%s*" .. r,
        r .. "%s*[~=]=%s*nil",
        "nil%s*[~=]=%s*" .. r,
        "not%s+" .. r,
        "if%s+" .. r .. "%s+then",
        r .. "%s*:%s*IsA%s*%(",
        "assert%s*%([^\n]-" .. r,
        "%[%s*" .. r .. "%s*%]%s*[~=]=%s*nil",
        "not%s+[%w_%.:]+%[%s*" .. r .. "%s*%]",
        "table%.find%s*%([^\n]-" .. r,
    }
    for _, pat in ipairs(tests) do
        if body:find(pat) then return true end
    end
    -- if not Validate(player, p) then ...
    for inner in body:gmatch("not%s+[%w_%.:]+%s*(%b())") do
        if inner:find(r) then return true end
    end
    return false
end

local function numericUse(body, p)
    local r = pRef(p)
    return body:find(r .. "%s*[%+%-%*/%%<>]") ~= nil
        or body:find("[%+%-%*/<>]=?%s*" .. r) ~= nil
        or body:find("math%.%a+%s*%([^\n%)]-" .. r) ~= nil
        or body:find("tonumber%s*%(%s*" .. r) ~= nil
end

local function isSanitized(body, p)
    local r = pRef(p)
    return body:find("math%.clamp%s*%(%s*" .. r) ~= nil
        or body:find("math%.m[ai][xn]%s*%([^\n%)]-" .. r) ~= nil
        or body:find(r .. "%s*[<>]=?%s*[%w_%.%-]") ~= nil
        or body:find("[%w_%.%)%]]%s*[<>]=?%s*" .. r) ~= nil
end

local function analyzeHandler(remoteName, body, params, helperText, delegated, astDone)
    helperText = helperText or ""
    delegated = delegated or {}
    local F = {}
    local CAT = {
        ["Parametre tip/nil doğrulaması eksik"] = "type", ["Rate limit / cooldown görünmüyor"] = "rate",
        ["Sayısal değer sınır kontrolü yok"] = "range", ["NaN / inf kontrolü eksik"] = "nan",
        ["Client'tan gelen fiyat/miktar ekonomide kullanılıyor"] = "economy", ["Client'tan gelen hedef oyuncu/ID"] = "target",
        ["Ayrıcalıklı görünen remote'ta yetki kontrolü yok"] = "priv", ["Mekansal eylemde mesafe kontrolü yok"] = "spatial",
        ["Satın alma: fiziksel mesafe gerekiyorsa kontrol yok"] = "spatial",
    }
    local function add(level, title, msg, fix)
        F[#F + 1] = { level = level, title = title, msg = msg, fix = fix, cat = CAT[title] }
    end

    local lower = body:lower()
    -- Kelime tabanlı kontroller handler + çağırdığı yardımcı fonksiyonları birlikte görür
    local lowerAll = (body .. "\n" .. helperText):lower()
    local helperGuard = helperText:find("typeof%s*%(") or helperText:find("%f[%w_]type%s*%(")
                     or helperText:find("tonumber%s*%(") or helperText:find(":%s*IsA%s*%(")
    local helperSan = helperText:find("math%.clamp") or helperText:find("[<>]=?")
    local nameLower = remoteName:lower()
    local paramsKnown = params ~= nil
    local args = {}
    if paramsKnown then
        for i = 2, #params do args[#args + 1] = params[i] end   -- 1. parametre = player
    end

    local touchesEconomy = anyPlain(lowerAll, ECONOMY_WORDS) ~= nil
    local privileged = anyPlain(nameLower, PRIV_NAME_WORDS) ~= nil
    local hasDatastore = lowerAll:find("setasync", 1, true) or lowerAll:find("updateasync", 1, true)
                      or lowerAll:find("incrementasync", 1, true)

    -- 1) Parametre doğrulaması (AST motoru varsa o yapar) ───────────
    if not astDone then
    local unguarded = {}
    if paramsKnown then
        for _, p in ipairs(args) do
            if p ~= "..." and not isGuarded(body, p) and not (delegated[p] and helperGuard) then unguarded[#unguarded + 1] = p end
        end
    else
        local anyGuard = body:find("%f[%w_]typeof%s*%(") or body:find("%f[%w_]type%s*%(")
                      or body:find(":%s*IsA%s*%(") or body:find("[~=]=%s*nil") or body:find("not%s+[%w_]")
        if not anyGuard then unguarded = { "(parametreler belirlenemedi)" } end
    end
    if #unguarded > 0 then
        add((touchesEconomy or privileged) and "CRITICAL" or "HIGH",
            "Parametre tip/nil doğrulaması eksik",
            "Doğrulaması görünmeyen parametre(ler): " .. table.concat(unguarded, ", ") ..
            ". Roblox dokümanı her argümanın tipinin server'da kontrol edilmesini önerir; exploiter beklenmeyen tip (table, nil, string…) gönderebilir.",
            [[Handler başında doğrula:
  if typeof(amount) ~= "number" then return end
  if typeof(itemId) ~= "string" then return end]])
    end

    end

    -- 2) Rate limit ────────────────────────────────────────────────
    local hasRate = anyPlain(lowerAll, { "cooldown", "debounce", "ratelimit", "rate_limit", "throttle",
                                         "lastfire", "lastused", "lastcall", "os.clock", "os.time" })
                 or lowerAll:find("tick%s*%(")
    if not hasRate then
        add((touchesEconomy or privileged or hasDatastore) and "HIGH" or "MEDIUM",
            "Rate limit / cooldown görünmüyor",
            "Exploiter bu remote'u saniyede binlerce kez ateşleyebilir. (Not: cooldown handler dışında/başka bir modülde yapılıyorsa bu uyarı yanlış pozitif olabilir.)",
            [[Cooldown tablosu ekle:
  local last = {}
  local COOLDOWN = 0.5
  -- handler içinde:
  local now = os.clock()
  if (last[player.UserId] or 0) + COOLDOWN > now then return end
  last[player.UserId] = now]])
    end

    -- 3-5) Sayısal/fiyat/hedef kontrolleri (AST motoru varsa o yapar) ─
    if not astDone then
    if paramsKnown then
        local unsanitized, nanRisk = {}, {}
        local hugeGuard = lowerAll:find("math.huge", 1, true) or lowerAll:find("isfinite", 1, true)
                       or lowerAll:find("isnan", 1, true)
                       or helperText:find("([%a_][%w_%.]*)%s*~=%s*%1%f[^%w_]") ~= nil   -- yardımcıdaki x ~= x
        for _, p in ipairs(args) do
            if p ~= "..." and numericUse(body, p) then
                if not isSanitized(body, p) and not (delegated[p] and helperSan) then unsanitized[#unsanitized + 1] = p end
                if not hugeGuard and not body:find(pRef(p) .. "%s*~=%s*" .. pRef(p)) then
                    nanRisk[#nanRisk + 1] = p
                end
            end
        end
        if #unsanitized > 0 then
            add("HIGH", "Sayısal değer sınır kontrolü yok",
                "Sayısal kullanılan parametre(ler): " .. table.concat(unsanitized, ", ") ..
                ". Alt/üst sınır kontrolü görünmüyor; negatif, çok büyük veya math.huge değerleri sorun çıkarabilir.",
                [[Sınırla:
  amount = math.clamp(amount, 0, MAX_AMOUNT)]])
        end
        if #nanRisk > 0 then
            add("MEDIUM", "NaN / inf kontrolü eksik",
                "Parametre(ler): " .. table.concat(nanRisk, ", ") ..
                ". Not: math.clamp NaN'i temizlemez (NaN karşılaştırmaları hep false döner); NaN ayrıca kontrol edilmeli. NaN stat'ları/DataStore'u bozabilir.",
                [[Ekle:
  if value ~= value then return end               -- NaN
  if math.abs(value) == math.huge then return end -- inf]])
        end
    end

    -- 4) Client'tan gelen fiyat/miktar ekonomide kullanılıyor mu? ───
    local clientMoneyParams = {}
    for _, p in ipairs(args) do
        local pl = p:lower()
        for _, w in ipairs(PRICE_PARAM_WORDS) do
            if pl:find(w, 1, true) then clientMoneyParams[#clientMoneyParams + 1] = p; break end
        end
    end
    local priceSuspect = #clientMoneyParams > 0
        or (not paramsKnown and anyPlain(lower, { "price", "cost", "amount", "quantity" }) ~= nil)
    local hasServerTable = false
    for _, pat in ipairs(SERVER_TABLE_PATS) do
        if lowerAll:find(pat) then hasServerTable = true; break end
    end
    if touchesEconomy and priceSuspect and not hasServerTable then
        add("CRITICAL", "Client'tan gelen fiyat/miktar ekonomide kullanılıyor",
            "Ekonomiyle ilgili işlem var ve fiyat/miktar client'tan geliyor" ..
            (#clientMoneyParams > 0 and (" (" .. table.concat(clientMoneyParams, ", ") .. ")") or "") ..
            " ama server'ın kendi fiyat/config tablosuna bakıldığı görünmüyor.",
            [[Client'a güvenme:
  local realPrice = ServerItemConfig[itemId].price   -- server tablosu
  if coins >= realPrice then coins -= realPrice end]])
    end

    -- 5) Client'tan gelen hedef oyuncu/ID ───────────────────────────
    local targetParams = {}
    for _, p in ipairs(args) do
        local pl = p:lower()
        for _, w in ipairs(TARGET_PARAM_WORDS) do
            if pl:find(w, 1, true) then targetParams[#targetParams + 1] = p; break end
        end
    end
    if #targetParams > 0 and (touchesEconomy or privileged or hasDatastore) then
        add("HIGH", "Client'tan gelen hedef oyuncu/ID",
            "Parametre(ler): " .. table.concat(targetParams, ", ") ..
            ". Çağıran oyuncunun bu hedef üzerinde işlem yapmaya yetkili olduğu server'da doğrulanmalı; aksi halde exploiter başka oyuncunun verisini değiştirebilir.",
            [[Sadece çağıranın kendi verisine dokun:
  local data = PlayerData[player.UserId]   -- client'tan gelen ID'yi kullanma]])
    end

    end

    -- 6) Ayrıcalıklı remote'larda yetki kontrolü ────────────────────
    if privileged then
        local guarded = anyPlain(lowerAll, PRIV_GUARD_WORDS) ~= nil or lowerAll:find("userid%s*[~=]=") ~= nil
        if not guarded then
            add("CRITICAL", "Ayrıcalıklı görünen remote'ta yetki kontrolü yok",
                "Remote adı ayrıcalıklı bir işlemi (admin/kick/ban/give…) çağrıştırıyor ama handler'da rol/rank/whitelist/UserId kontrolü görünmüyor. Herhangi bir oyuncu bunu çağırabilir.",
                [[Yetkiyi server'da doğrula:
  if not ADMIN_IDS[player.UserId] then return end
  -- veya: player:GetRankInGroup(groupId) >= REQUIRED_RANK]])
        end
    end

    -- 7) Mekansal eylem → mesafe kontrolü ───────────────────────────
    local hasDist = anyPlain(lowerAll, { "magnitude", "distance", "raycast", "getpartboundsinradius", "region3" }) ~= nil
    if not hasDist then
        -- tetikleyici kelime: handler gövdesi VEYA remote adı (ör. "Pickup")
        if anyPlain(lower .. " " .. nameLower, { "interact", "collect", "pickup", "touch" }) then
            add("MEDIUM", "Mekansal eylemde mesafe kontrolü yok",
                "Handler bir etkileşim/toplama/dokunma eylemi içeriyor ama oyuncunun nesneye yakınlığı doğrulanmıyor; exploiter uzaktan tetikleyebilir.",
                [[Mesafe doğrula:
  local root = player.Character and player.Character:FindFirstChild("HumanoidRootPart")
  if not root or (root.Position - target.Position).Magnitude > MAX_DISTANCE then return end]])
        elseif anyPlain(lower, { "buy", "shop", "purchase" }) then
            add("LOW", "Satın alma: fiziksel mesafe gerekiyorsa kontrol yok",
                "Satın alma bir NPC/tezgâha bağlıysa oyuncunun yakınlığı doğrulanmalı. Menü tabanlı bir mağazaysa bu uyarıyı yok sayabilirsin.",
                "Fiziksel mağazaysa Magnitude ile mesafe kontrolü ekle.")
        end
    end

    return F
end

-- ─────────────────────────────────────────────────────────────────
-- AST MOTORU (v4.2): Luau ayrıştırıcı + taint (veri akışı) analizi
-- ─────────────────────────────────────────────────────────────────
local Ast = (function()
-- Luau ayrıştırıcı: kaynak → AST. Saf Luau; Studio plugin'inde ve Luau CLI'da çalışır.
-- Tipler (annotation) atlanır, AST'ye girmez. Hata: parse() → nil, {msg=, line=}
local Ast = {}

local KEYWORDS = {}
for w in ("and break do else elseif end false for function if in local nil not or repeat return then true until while"):gmatch("%a+") do
    KEYWORDS[w] = true
end
local OPS2 = {
    ["=="] = true, ["~="] = true, ["<="] = true, [">="] = true, [".."] = true, ["::"] = true, ["->"] = true,
    ["+="] = true, ["-="] = true, ["*="] = true, ["/="] = true, ["%="] = true, ["^="] = true, ["//"] = true,
}
local OP1 = "^[%+%-%*/%%%^#&<>=%(%){}%[%];:,%.|%?~@]"
local COMPOUND = { ["+="] = true, ["-="] = true, ["*="] = true, ["/="] = true, ["%="] = true, ["^="] = true, ["//="] = true, ["..="] = true }

local function fail(msg, line)
    error({ msg = msg, line = line }, 0)
end

-- ───────────────────────── LEXER ─────────────────────────
local function lex(src, line0)
    local T, V, L = {}, {}, {}
    local n, i, line, k = #src, 1, line0 or 1, 0
    local find, sub, match = string.find, string.sub, string.match

    local function push(t, v, ln)
        k += 1
        T[k] = t; V[k] = v; L[k] = ln or line
    end

    while true do
        local _, e = find(src, "^[ \t\r]*", i)
        i = e + 1
        if i > n then break end
        local c = sub(src, i, i)

        if c == "\n" then
            line += 1; i += 1

        elseif c == "-" and sub(src, i + 1, i + 1) == "-" then
            local eq = match(src, "^%-%-%[(=*)%[", i)
            if eq then
                local _, ce = find(src, "]" .. eq .. "]", i + 4 + #eq, true)
                local stop = ce or n
                for _ in sub(src, i, stop):gmatch("\n") do line += 1 end
                i = stop + 1
            else
                i = find(src, "\n", i, true) or (n + 1)
            end

        elseif find(c, "^[%a_]") then
            local _, e2 = find(src, "^[%w_]+", i)
            local w = sub(src, i, e2)
            push(KEYWORDS[w] and "kw" or "name", w)
            i = e2 + 1

        elseif find(c, "^%d") or (c == "." and find(src, "^%.%d", i)) then
            local _, e2 = find(src, "^0[xX][%x_]+", i)
            if not e2 then _, e2 = find(src, "^0[bB][01_]+", i) end
            if not e2 then
                _, e2 = find(src, "^[%d_]*%.?[%d_]*", i)
                local _, e3 = find(src, "^[eE][%+%-]?%d+", e2 + 1)
                if e3 then e2 = e3 end
            end
            push("num", sub(src, i, e2))
            i = e2 + 1

        elseif c == '"' or c == "'" then
            local j, buf, startLine = i + 1, {}, line
            local cls = "[\\\n" .. c .. "]"
            while true do
                local p = find(src, cls, j)
                if not p then fail("unfinished string", startLine) end
                buf[#buf + 1] = sub(src, j, p - 1)
                local ch = sub(src, p, p)
                if ch == c then
                    j = p + 1
                    break
                elseif ch == "\n" then
                    fail("unfinished string", startLine)
                else
                    local nx = sub(src, p + 1, p + 1)
                    if nx == "z" then
                        local _, ze = find(src, "^z%s*", p + 1)
                        for _ in sub(src, p + 1, ze):gmatch("\n") do line += 1 end
                        j = ze + 1
                    else
                        if nx == "\n" then line += 1 end
                        buf[#buf + 1] = (nx == "n" and "\n") or (nx == "t" and "\t") or nx
                        j = p + 2
                    end
                end
            end
            push("str", table.concat(buf), startLine)
            i = j

        elseif c == "`" then
            local j, depth, startLine = i + 1, 0, line
            while true do
                local ch = sub(src, j, j)
                if ch == "" then fail("unfinished interpolated string", startLine) end
                if ch == "\\" then
                    if sub(src, j + 1, j + 1) == "\n" then line += 1 end
                    j += 2
                elseif ch == "\n" then
                    line += 1; j += 1
                elseif depth > 0 and (ch == '"' or ch == "'") then
                    local q = find(src, ch, j + 1, true)
                    if not q then fail("unfinished string in interpolation", startLine) end
                    j = q + 1
                elseif ch == "{" then
                    depth += 1; j += 1
                elseif ch == "}" then
                    if depth > 0 then depth -= 1 end
                    j += 1
                elseif ch == "`" and depth == 0 then
                    break
                else
                    j += 1
                end
            end
            push("istr", sub(src, i + 1, j - 1), startLine)
            i = j + 1

        elseif c == "[" and find(src, "^%[=*%[", i) then
            local eq = match(src, "^%[(=*)%[", i)
            local _, ce = find(src, "]" .. eq .. "]", i + 2 + #eq, true)
            if not ce then fail("unfinished long string", line) end
            local body = sub(src, i + 2 + #eq, ce - #eq - 2)
            local startLine = line
            for _ in sub(src, i, ce):gmatch("\n") do line += 1 end
            if sub(body, 1, 1) == "\n" then body = sub(body, 2) end
            push("str", body, startLine)
            i = ce + 1

        else
            local three = sub(src, i, i + 2)
            if three == "..." or three == "//=" or three == "..=" then
                push("op", three); i += 3
            else
                local two = sub(src, i, i + 1)
                if OPS2[two] then
                    push("op", two); i += 2
                elseif find(c, OP1) then
                    push("op", c); i += 1
                else
                    fail("unexpected character '" .. c .. "'", line)
                end
            end
        end
    end
    push("eof", "<eof>")
    return T, V, L
end

-- ───────────────────────── PARSER ─────────────────────────
local BINPRI = {
    ["or"] = { 1, 1 }, ["and"] = { 2, 2 },
    ["<"] = { 3, 3 }, [">"] = { 3, 3 }, ["<="] = { 3, 3 }, [">="] = { 3, 3 }, ["~="] = { 3, 3 }, ["=="] = { 3, 3 },
    [".."] = { 9, 8 }, ["+"] = { 6, 6 }, ["-"] = { 6, 6 },
    ["*"] = { 7, 7 }, ["/"] = { 7, 7 }, ["//"] = { 7, 7 }, ["%"] = { 7, 7 }, ["^"] = { 10, 9 },
}
local UNARY_PRI = 8

local function newParser(src, line0)
    local T, V, L = lex(src, line0)
    local p = 1
    local parseBlock, parseExpr, parseType, parseStatement, parseFuncBody

    local function isOp(v) return T[p] == "op" and V[p] == v end
    local function isKw(v) return T[p] == "kw" and V[p] == v end
    local function acceptOp(v) if isOp(v) then p += 1; return true end return false end
    local function expectOp(v)
        if not acceptOp(v) then fail("'" .. v .. "' bekleniyordu, '" .. tostring(V[p]) .. "' bulundu", L[p]) end
    end
    local function expectKw(v)
        if isKw(v) then p += 1 else fail("'" .. v .. "' bekleniyordu, '" .. tostring(V[p]) .. "' bulundu", L[p]) end
    end
    local function expectName()
        if T[p] ~= "name" then fail("isim bekleniyordu, '" .. tostring(V[p]) .. "' bulundu", L[p]) end
        p += 1
        return V[p - 1]
    end
    local function expectNameOrKw()
        if T[p] ~= "name" and T[p] ~= "kw" then fail("isim bekleniyordu", L[p]) end
        p += 1
        return V[p - 1]
    end

    -- ── tip atlama ──
    local function skipBalanced(open, close)
        local depth = 0
        while true do
            local t, v = T[p], V[p]
            if t == "eof" then fail("dengesiz " .. open, L[p]) end
            if t == "op" then
                if v == open then depth += 1 elseif v == close then depth -= 1 end
            end
            p += 1
            if depth == 0 then return end
        end
    end

    local parseSimpleType
    parseSimpleType = function()
        local t, v = T[p], V[p]
        if t == "op" and v == "(" then
            skipBalanced("(", ")")
            if isOp("->") then p += 1; parseType() end
        elseif t == "op" and v == "{" then
            skipBalanced("{", "}")
        elseif t == "op" and v == "<" then
            skipBalanced("<", ">")
            if isOp("(") then
                skipBalanced("(", ")")
                if isOp("->") then p += 1; parseType() end
            end
        elseif t == "kw" and (v == "nil" or v == "true" or v == "false") then
            p += 1
        elseif t == "str" then
            p += 1
        elseif t == "op" and v == "..." then
            p += 1; parseType()
        elseif t == "name" then
            p += 1
            if v == "typeof" and isOp("(") then
                skipBalanced("(", ")")
            else
                while isOp(".") do p += 1; expectNameOrKw() end
                if isOp("<") then skipBalanced("<", ">") end
            end
        else
            fail("tip bekleniyordu", L[p])
        end
        while isOp("?") do p += 1 end
    end
    parseType = function()
        if isOp("|") or isOp("&") then p += 1 end
        parseSimpleType()
        while isOp("|") or isOp("&") do
            p += 1
            parseSimpleType()
        end
    end

    -- ── ifade ──
    local function parseExprList()
        local list = { parseExpr() }
        while acceptOp(",") do list[#list + 1] = parseExpr() end
        return list
    end

    local function parseTable()
        local line = L[p]
        expectOp("{")
        local items = {}
        while not isOp("}") do
            if T[p] == "name" and T[p + 1] == "op" and V[p + 1] == "=" then
                local nm = V[p]
                p += 2
                items[#items + 1] = { name = nm, key = { k = "Str", value = nm, line = L[p] }, value = parseExpr() }
            elseif isOp("[") then
                p += 1
                local key = parseExpr()
                expectOp("]")
                expectOp("=")
                items[#items + 1] = { key = key, name = key.k == "Str" and key.value or nil, value = parseExpr() }
            else
                items[#items + 1] = { value = parseExpr() }
            end
            if not (acceptOp(",") or acceptOp(";")) then break end
        end
        expectOp("}")
        return { k = "Table", items = items, line = line }
    end

    local function parseArgs()
        if isOp("(") then
            p += 1
            local args = {}
            if not isOp(")") then args = parseExprList() end
            expectOp(")")
            return args
        elseif T[p] == "str" then
            p += 1
            return { { k = "Str", value = V[p - 1], line = L[p - 1] } }
        elseif isOp("{") then
            return { parseTable() }
        end
        fail("argüman bekleniyordu", L[p])
    end

    local function parseSuffixed()
        local t, v, line = T[p], V[p], L[p]
        local e
        if t == "name" then
            p += 1
            e = { k = "Name", name = v, line = line }
        elseif t == "op" and v == "(" then
            p += 1
            local inner = parseExpr()
            expectOp(")")
            e = { k = "Paren", e = inner, line = line }
        else
            fail("beklenmeyen simge '" .. tostring(v) .. "'", line)
        end
        while true do
            local t2, v2 = T[p], V[p]
            if t2 == "op" and v2 == "." then
                p += 1
                local ln = L[p]
                local nm = expectNameOrKw()
                e = { k = "Index", obj = e, name = nm, key = { k = "Str", value = nm, line = ln }, line = ln }
            elseif t2 == "op" and v2 == "[" then
                local ln = L[p]
                p += 1
                local key = parseExpr()
                expectOp("]")
                e = { k = "Index", obj = e, key = key, name = key.k == "Str" and key.value or nil, line = ln }
            elseif t2 == "op" and v2 == ":" then
                p += 1
                local ln = L[p]
                local nm = expectNameOrKw()
                e = { k = "Method", obj = e, name = nm, args = parseArgs(), line = ln }
            elseif (t2 == "op" and (v2 == "(" or v2 == "{")) or t2 == "str" then
                local ln = L[p]
                e = { k = "Call", fn = e, args = parseArgs(), line = ln }
            else
                break
            end
        end
        return e
    end

    local parseInterp
    parseInterp = function(raw, line)
        local parts = {}
        local i, n = 1, #raw
        while i <= n do
            local ch = raw:sub(i, i)
            if ch == "\\" then
                i += 2
            elseif ch == "{" then
                local depth, j = 1, i + 1
                while j <= n and depth > 0 do
                    local c2 = raw:sub(j, j)
                    if c2 == "{" then depth += 1
                    elseif c2 == "}" then depth -= 1
                    elseif c2 == '"' or c2 == "'" then
                        local q = raw:find(c2, j + 1, true)
                        j = q or n
                    end
                    j += 1
                end
                local exprSrc = raw:sub(i + 1, j - 2)
                local ok, sub = pcall(function()
                    local P2 = newParser(exprSrc, line)
                    return P2.expr()
                end)
                if ok and sub then parts[#parts + 1] = sub end
                i = j
            else
                i += 1
            end
        end
        return { k = "IStr", parts = parts, line = line }
    end

    local function parseIfExpr()
        local line = L[p]
        p += 1 -- if / elseif
        local c = parseExpr()
        expectKw("then")
        local a = parseExpr()
        local b
        if isKw("elseif") then
            b = parseIfExpr()
        else
            expectKw("else")
            b = parseExpr()
        end
        return { k = "IfExpr", cond = c, a = a, b = b, line = line }
    end

    local function parseSimple()
        local t, v, line = T[p], V[p], L[p]
        local e
        if t == "num" then
            p += 1
            e = { k = "Num", value = tonumber((v:gsub("_", ""))) or 0, line = line }
        elseif t == "str" then
            p += 1
            e = { k = "Str", value = v, line = line }
        elseif t == "istr" then
            p += 1
            e = parseInterp(v, line)
        elseif t == "kw" and v == "nil" then
            p += 1; e = { k = "Nil", line = line }
        elseif t == "kw" and (v == "true" or v == "false") then
            p += 1; e = { k = "Bool", value = (v == "true"), line = line }
        elseif t == "op" and v == "..." then
            p += 1; e = { k = "Vararg", line = line }
        elseif t == "op" and v == "{" then
            e = parseTable()
        elseif t == "kw" and v == "function" then
            p += 1
            e = parseFuncBody(line, false)
        elseif t == "kw" and v == "if" then
            e = parseIfExpr()
        else
            e = parseSuffixed()
        end
        while isOp("::") do
            p += 1
            parseType()
        end
        return e
    end

    local function binOpAt()
        local t, v = T[p], V[p]
        if (t == "op" or (t == "kw" and (v == "and" or v == "or"))) and BINPRI[v] then return v end
        return nil
    end

    parseExpr = function(limit)
        limit = limit or 0
        local left
        local t, v, line = T[p], V[p], L[p]
        if (t == "kw" and v == "not") or (t == "op" and (v == "-" or v == "#")) then
            p += 1
            left = { k = "Un", op = v, e = parseExpr(UNARY_PRI), line = line }
        else
            left = parseSimple()
        end
        while true do
            local op = binOpAt()
            if not op or BINPRI[op][1] <= limit then break end
            local ln = L[p]
            p += 1
            local right = parseExpr(BINPRI[op][2])
            left = { k = "Bin", op = op, l = left, r = right, line = ln }
        end
        return left
    end

    -- ── fonksiyon gövdesi ──
    parseFuncBody = function(line, isMethod)
        local params, isVararg = {}, false
        if isOp("<") then skipBalanced("<", ">") end
        expectOp("(")
        if isMethod then params[1] = "self" end
        if not isOp(")") then
            repeat
                if isOp("...") then
                    p += 1
                    isVararg = true
                    if isOp(":") then p += 1; parseType() end
                else
                    params[#params + 1] = expectName()
                    if isOp(":") then p += 1; parseType() end
                end
            until not acceptOp(",")
        end
        expectOp(")")
        if isOp(":") then p += 1; parseType() end
        local body = parseBlock()
        local endLine = L[p]
        expectKw("end")
        return { k = "Func", params = params, isVararg = isVararg, body = body, line = line, endLine = endLine }
    end

    -- ── deyimler ──
    local function blockEnd()
        local t, v = T[p], V[p]
        return t == "eof" or (t == "kw" and (v == "end" or v == "else" or v == "elseif" or v == "until"))
    end

    local function skipAttributes()
        while isOp("@") do
            p += 1
            if isOp("[") then skipBalanced("[", "]") else expectNameOrKw() end
        end
    end

    local function continueIsStmt()
        local t, v = T[p + 1], V[p + 1]
        if t == "eof" then return true end
        if t == "op" then
            return not (v == "=" or v == "(" or v == "." or v == ":" or v == "[" or v == "," or v == "{"
                or COMPOUND[v] or v == "+" or v == "-" or v == "*" or v == "/" or v == ".." or v == "==" or v == "~=")
        end
        if t == "str" then return false end
        return true
    end

    parseStatement = function()
        local t, v, line = T[p], V[p], L[p]

        if t == "op" and v == "@" then
            skipAttributes()
            return parseStatement()
        end

        if t == "kw" then
            if v == "if" then
                p += 1
                local clauses = {}
                local cond = parseExpr()
                expectKw("then")
                clauses[1] = { cond = cond, block = parseBlock() }
                local elseBlock
                while true do
                    if isKw("elseif") then
                        p += 1
                        local c = parseExpr()
                        expectKw("then")
                        clauses[#clauses + 1] = { cond = c, block = parseBlock() }
                    elseif isKw("else") then
                        p += 1
                        elseBlock = parseBlock()
                        expectKw("end")
                        break
                    else
                        expectKw("end")
                        break
                    end
                end
                return { k = "If", clauses = clauses, elseBlock = elseBlock, line = line }

            elseif v == "while" then
                p += 1
                local cond = parseExpr()
                expectKw("do")
                local body = parseBlock()
                expectKw("end")
                return { k = "While", cond = cond, block = body, line = line }

            elseif v == "repeat" then
                p += 1
                local body = parseBlock()
                expectKw("until")
                return { k = "Repeat", block = body, cond = parseExpr(), line = line }

            elseif v == "do" then
                p += 1
                local body = parseBlock()
                expectKw("end")
                return { k = "Do", block = body, line = line }

            elseif v == "for" then
                p += 1
                local n1 = expectName()
                if isOp(":") then p += 1; parseType() end
                if isOp("=") then
                    p += 1
                    local start = parseExpr()
                    expectOp(",")
                    local stop = parseExpr()
                    local step
                    if acceptOp(",") then step = parseExpr() end
                    expectKw("do")
                    local body = parseBlock()
                    expectKw("end")
                    return { k = "NumFor", var = n1, start = start, stop = stop, step = step, block = body, line = line }
                end
                local names = { n1 }
                while acceptOp(",") do
                    names[#names + 1] = expectName()
                    if isOp(":") then p += 1; parseType() end
                end
                expectKw("in")
                local exprs = parseExprList()
                expectKw("do")
                local body = parseBlock()
                expectKw("end")
                return { k = "GenFor", names = names, exprs = exprs, block = body, line = line }

            elseif v == "function" then
                p += 1
                local ln = L[p]
                local target = { k = "Name", name = expectName(), line = ln }
                local isMethod = false
                while isOp(".") do
                    p += 1
                    local ln2 = L[p]
                    local key = expectNameOrKw()
                    target = { k = "Index", obj = target, name = key, key = { k = "Str", value = key, line = ln2 }, line = ln2 }
                end
                if isOp(":") then
                    p += 1
                    local ln2 = L[p]
                    local key = expectNameOrKw()
                    target = { k = "Index", obj = target, name = key, key = { k = "Str", value = key, line = ln2 }, line = ln2 }
                    isMethod = true
                end
                local fn = parseFuncBody(line, isMethod)
                return { k = "FunctionStmt", target = target, isMethod = isMethod, fn = fn, line = line }

            elseif v == "local" then
                p += 1
                if isKw("function") then
                    p += 1
                    local name = expectName()
                    return { k = "LocalFunction", name = name, fn = parseFuncBody(line, false), line = line }
                end
                local names = {}
                repeat
                    names[#names + 1] = expectName()
                    if isOp(":") then p += 1; parseType() end
                until not acceptOp(",")
                local values = {}
                if acceptOp("=") then values = parseExprList() end
                return { k = "Local", names = names, values = values, line = line }

            elseif v == "return" then
                p += 1
                local values = {}
                if not blockEnd() and not isOp(";") then values = parseExprList() end
                return { k = "Return", values = values, line = line }

            elseif v == "break" then
                p += 1
                return { k = "Break", line = line }
            end

        elseif t == "name" then
            if v == "continue" and continueIsStmt() then
                p += 1
                return { k = "Continue", line = line }
            end
            local isExport = (v == "export" and T[p + 1] == "name" and V[p + 1] == "type")
            if isExport or (v == "type" and T[p + 1] == "name" and T[p + 2] == "op" and (V[p + 2] == "=" or V[p + 2] == "<")) then
                if isExport then p += 1 end
                p += 2 -- type Name
                if isOp("<") then skipBalanced("<", ">") end
                expectOp("=")
                parseType()
                return nil
            end
        end

        -- ifade deyimi: atama veya çağrı
        local e = parseSuffixed()
        if isOp("=") or isOp(",") then
            local targets = { e }
            while acceptOp(",") do targets[#targets + 1] = parseSuffixed() end
            expectOp("=")
            return { k = "Assign", targets = targets, values = parseExprList(), line = line }
        elseif T[p] == "op" and COMPOUND[V[p]] then
            local op = V[p]
            p += 1
            return { k = "Assign", targets = { e }, values = { parseExpr() }, op = op, line = line }
        elseif e.k == "Call" or e.k == "Method" then
            return { k = "CallStmt", call = e, line = line }
        end
        fail("sözdizimi hatası", line)
    end

    parseBlock = function()
        local stmts, startLine = {}, L[p]
        while not blockEnd() do
            local st = parseStatement()
            if st then stmts[#stmts + 1] = st end
            acceptOp(";")
        end
        return { k = "Block", stmts = stmts, line = startLine }
    end

    return {
        chunk = function()
            local b = parseBlock()
            if T[p] ~= "eof" then fail("beklenmeyen '" .. tostring(V[p]) .. "'", L[p]) end
            return b
        end,
        expr = function() return parseExpr() end,
    }
end

function Ast.parse(src)
    local ok, res = pcall(function()
        return newParser(src, 1).chunk()
    end)
    if ok then return res, nil end
    if type(res) == "table" then return nil, res end
    return nil, { msg = tostring(res), line = 0 }
end

-- ───────────────────────── GENEL GEZİNTİ ─────────────────────────
local function children(n, out)
    local k = n.k
    if k == "Block" then
        for _, s in ipairs(n.stmts) do out[#out + 1] = s end
    elseif k == "Local" then
        for _, v in ipairs(n.values) do out[#out + 1] = v end
    elseif k == "Assign" then
        for _, v in ipairs(n.targets) do out[#out + 1] = v end
        for _, v in ipairs(n.values) do out[#out + 1] = v end
    elseif k == "CallStmt" then
        out[#out + 1] = n.call
    elseif k == "LocalFunction" then
        out[#out + 1] = n.fn
    elseif k == "FunctionStmt" then
        out[#out + 1] = n.target; out[#out + 1] = n.fn
    elseif k == "If" then
        for _, c in ipairs(n.clauses) do out[#out + 1] = c.cond; out[#out + 1] = c.block end
        if n.elseBlock then out[#out + 1] = n.elseBlock end
    elseif k == "While" then
        out[#out + 1] = n.cond; out[#out + 1] = n.block
    elseif k == "Repeat" then
        out[#out + 1] = n.block; out[#out + 1] = n.cond
    elseif k == "NumFor" then
        out[#out + 1] = n.start; out[#out + 1] = n.stop
        if n.step then out[#out + 1] = n.step end
        out[#out + 1] = n.block
    elseif k == "GenFor" then
        for _, v in ipairs(n.exprs) do out[#out + 1] = v end
        out[#out + 1] = n.block
    elseif k == "Do" then
        out[#out + 1] = n.block
    elseif k == "Return" then
        for _, v in ipairs(n.values) do out[#out + 1] = v end
    elseif k == "Index" then
        out[#out + 1] = n.obj
        if n.key and n.key.k ~= "Str" then out[#out + 1] = n.key end
    elseif k == "Call" then
        out[#out + 1] = n.fn
        for _, a in ipairs(n.args) do out[#out + 1] = a end
    elseif k == "Method" then
        out[#out + 1] = n.obj
        for _, a in ipairs(n.args) do out[#out + 1] = a end
    elseif k == "Bin" then
        out[#out + 1] = n.l; out[#out + 1] = n.r
    elseif k == "Un" or k == "Paren" then
        out[#out + 1] = n.e
    elseif k == "Table" then
        for _, it in ipairs(n.items) do
            if it.key and it.key.k ~= "Str" then out[#out + 1] = it.key end
            out[#out + 1] = it.value
        end
    elseif k == "IfExpr" then
        out[#out + 1] = n.cond; out[#out + 1] = n.a; out[#out + 1] = n.b
    elseif k == "IStr" then
        for _, x in ipairs(n.parts) do out[#out + 1] = x end
    elseif k == "Func" then
        out[#out + 1] = n.body
    end
end

-- cb(node) false dönerse alt düğümlere inilmez
function Ast.walk(node, cb)
    if cb(node) == false then return end
    local out = {}
    children(node, out)
    for _, c in ipairs(out) do Ast.walk(c, cb) end
end

return Ast

end)()

local Taint = (function()
-- Taint analizi: client'tan gelen remote parametreleri hangi kritik noktalara,
-- hangi doğrulamalardan geçerek ulaşıyor?  (Ast = parser.lua çıktısı üzerinde çalışır)
--
-- Model:
--   taint  T = { [kaynakParametre] = { [doğrulamaTürü] = true } }   (nil = temiz/sunucu verisi)
--   Doğrulama türleri: type, nil, min, max, nan, member, scope
--   "v:" önekli türler DEĞER dönüşümünden gelir (clamp, tonumber…); yardımcı fonksiyon
--   özetinde çağıran değişkene GEÇMEZ (çünkü değer kopyası değişir, çağıranınki değişmez).
local Taint = {}

local function set(list)
    local s = {}
    for _, v in ipairs(list) do s[v] = true end
    return s
end

local NUM_PROPS = set({ "health", "maxhealth", "walkspeed", "jumppower", "jumpheight", "transparency" })
local VEC_PROPS = set({ "position", "cframe", "size", "velocity", "assemblylinearvelocity", "orientation", "rotation" })
local VEC_METHODS = set({ "PivotTo", "MoveTo", "SetPrimaryPartCFrame", "Translate", "ApplyImpulse" })
local NUM_METHODS = set({ "TakeDamage" })
local DESTRUCTIVE = set({ "Destroy", "Kick", "ClearAllChildren", "BreakJoints", "Remove", "LoadCharacter" })
local DS_METHODS = set({ "GetAsync", "SetAsync", "UpdateAsync", "RemoveAsync", "IncrementAsync" })
local HTTP_METHODS = set({ "GetAsync", "PostAsync", "RequestAsync" })
local TELEPORT_METHODS = set({ "Teleport", "TeleportAsync", "TeleportToPlaceInstance", "TeleportPartyAsync" })
local STRING_METHODS = set({ "lower", "upper", "sub", "gsub", "format", "rep", "reverse" })
local ECON_WORDS = { "coin", "cash", "gold", "money", "gem", "point", "xp", "balance", "currency", "buck", "credit", "diamond", "score" }
local DATA_WORDS = { "data", "inventory", "stats", "profile", "save", "cache", "owned", "settings", "session" }
local AUTH_WORDS = { "admin", "whitelist", "owner", "allowed", "moderator", "isstaff", "permission", "rank", "isvip" }
local PASS_FN = set({ "math.floor", "math.ceil", "math.abs", "math.round", "math.sqrt", "math.sign", "string.lower",
    "string.upper", "string.sub", "string.format", "string.gsub", "string.reverse" })
local CLEAN_FN = set({ "typeof", "type", "rawequal", "select", "next", "ipairs", "pairs", "os.clock", "os.time", "tick",
    "time", "string.len", "utf8.len", "print", "warn", "error", "assert", "pcall", "xpcall", "unpack", "table.unpack" })
local CMP = set({ "<", ">", "<=", ">=", "==", "~=" })

local function containsAny(s, words)
    for _, w in ipairs(words) do
        if s:find(w, 1, true) then return true end
    end
    return false
end

local LABEL = {
    type = "tip/nil doğrulaması", min = "alt sınır (negatif değerler)", max = "üst sınır", nan = "NaN kontrolü",
    member = "izinli-liste üyeliği", scope = "kapsam kontrolü (IsDescendantOf/Backpack…)",
}

-- ───────────────────────── küme yardımcıları ─────────────────────────
local function addKind(T, kind)
    if not T then return nil end
    local r = {}
    for p, v in pairs(T) do
        if v[kind] then
            r[p] = v
        else
            local nv = {}
            for k in pairs(v) do nv[k] = true end
            nv[kind] = true
            r[p] = nv
        end
    end
    return r
end

local function addKinds(T, kinds)
    for _, k in ipairs(kinds) do T = addKind(T, k) end
    return T
end

local function stripKinds(T)
    if not T then return nil end
    local r = {}
    for p in pairs(T) do r[p] = {} end
    return r
end

-- aynı kaynak iki yoldan geliyorsa doğrulama = kesişim (en zayıf halka)
local function combine(a, b)
    if not a then return b end
    if not b then return a end
    local r = {}
    for p, v in pairs(a) do
        local w = b[p]
        if w then
            local iv = {}
            for k in pairs(v) do if w[k] then iv[k] = true end end
            r[p] = iv
        else
            r[p] = v
        end
    end
    for p, w in pairs(b) do
        if not a[p] then r[p] = w end
    end
    return r
end

local function shallow(t)
    local r = {}
    for k, v in pairs(t) do r[k] = v end
    return r
end

-- iki ortamı birleştir (if dalları): kaynaklar birleşir, doğrulama kesişir
local function mergeEnv(a, b)
    local r = {}
    for k, v in pairs(a) do
        if k == "@authz" then
            r[k] = (b[k] and v) or nil
        elseif b[k] ~= nil then
            r[k] = combine(v, b[k])
        else
            r[k] = v
        end
    end
    for k, v in pairs(b) do
        if a[k] == nil and k ~= "@authz" then r[k] = v end
    end
    return r
end

-- ───────────────────────── AST yardımcıları ─────────────────────────
local function pathOf(e)
    local k = e.k
    if k == "Name" then return e.name end
    if k == "Paren" then return pathOf(e.e) end
    if k == "Index" and e.name then
        local base = pathOf(e.obj)
        if base then return base .. "." .. e.name end
    end
    return nil
end

local function rootName(e)
    while e do
        if e.k == "Name" then return e.name end
        if e.k == "Index" or e.k == "Method" then e = e.obj
        elseif e.k == "Call" then e = e.fn
        elseif e.k == "Paren" then e = e.e
        else return nil end
    end
    return nil
end

local function calleeName(fnExpr)
    return pathOf(fnExpr)
end

local function isNil(e) return e.k == "Nil" end

-- ifadedeki tüm "yol" ifadeleri (Name / a.b.c)
local function collectPaths(e, out)
    out = out or {}
    local k = e.k
    if k == "Name" or (k == "Index" and pathOf(e)) then
        out[#out + 1] = e
        return out
    end
    if k == "Paren" or k == "Un" then return collectPaths(e.e, out) end
    if k == "Bin" then collectPaths(e.l, out); collectPaths(e.r, out)
    elseif k == "Index" then collectPaths(e.obj, out)
    elseif k == "Call" then for _, a in ipairs(e.args) do collectPaths(a, out) end
    elseif k == "Method" then collectPaths(e.obj, out); for _, a in ipairs(e.args) do collectPaths(a, out) end
    elseif k == "IfExpr" then collectPaths(e.a, out); collectPaths(e.b, out)
    end
    return out
end

-- ───────────────────────── ifade taint'i ─────────────────────────
local info

local function isPlayerScoped(objExpr, ctx)
    local r = rootName(objExpr)
    return r ~= nil and r == ctx.playerVar
end

local function callInfo(e, env, ctx)
    local cached = ctx.ret[e]
    if cached ~= nil then return cached or nil end

    local isM = e.k == "Method"
    local name = isM and e.name or calleeName(e.fn)
    local args = e.args

    if not isM and name then
        local a1 = args[1] and info(args[1], env, ctx)
        if name == "tonumber" or name == "tostring" then return addKind(a1, "v:type") end
        if name == "math.clamp" then return addKinds(a1, { "v:min", "v:max", "v:type" }) end
        if name == "math.max" or name == "math.min" then
            local t, hasClean = nil, false
            for _, a in ipairs(args) do
                local ai = info(a, env, ctx)
                if ai then t = combine(t, ai) else hasClean = true end
            end
            if t and hasClean then t = addKind(t, name == "math.max" and "v:min" or "v:max") end
            return t
        end
        if PASS_FN[name] then return a1 end
        if CLEAN_FN[name] then return nil end
    end

    local t
    if isM then
        local recv = info(e.obj, env, ctx)
        if recv and STRING_METHODS[e.name] then
            t = recv
        elseif recv then
            t = stripKinds(recv)
        end
    end
    for _, a in ipairs(args) do
        local ai = info(a, env, ctx)
        if ai then t = combine(t, stripKinds(ai)) end
    end
    if t and isM and (e.name == "FindFirstChild" or e.name == "WaitForChild" or e.name == "FindFirstChildWhichIsA")
       and isPlayerScoped(e.obj, ctx) then
        t = addKind(t, "scope")
    end
    return t
end

info = function(e, env, ctx)
    local k = e.k
    if k == "Name" then return env[e.name]
    elseif k == "Vararg" then return env["..."]
    elseif k == "Paren" then return info(e.e, env, ctx)
    elseif k == "Index" then
        local p = pathOf(e)
        if p and env[p] then return env[p] end
        local ot = info(e.obj, env, ctx)
        if ot then return stripKinds(ot) end
        return nil
    elseif k == "Un" then
        if e.op == "not" or e.op == "#" then return nil end
        return info(e.e, env, ctx)
    elseif k == "Bin" then
        local op = e.op
        if CMP[op] then return nil end
        if op == "and" then return info(e.r, env, ctx) end
        if op == "or" then
            local l, r = info(e.l, env, ctx), info(e.r, env, ctx)
            if l and not r then return addKind(l, "v:nil") end
            return combine(l, r)
        end
        return combine(info(e.l, env, ctx), info(e.r, env, ctx))
    elseif k == "IfExpr" then
        return combine(info(e.a, env, ctx), info(e.b, env, ctx))
    elseif k == "Table" then
        local t
        for _, it in ipairs(e.items) do
            local vi = info(it.value, env, ctx)
            if vi then t = combine(t, vi) end
        end
        return stripKinds(t)
    elseif k == "IStr" then
        local t
        for _, part in ipairs(e.parts) do
            local pi = info(part, env, ctx)
            if pi then t = combine(t, pi) end
        end
        return addKind(stripKinds(t), "v:type")
    elseif k == "Call" or k == "Method" then
        return callInfo(e, env, ctx)
    end
    return nil
end

-- ───────────────────────── koşul → doğrulama çıkarımı ─────────────────────────
local function has(v, kind)
    return v[kind] or v["v:" .. kind]
end

-- cond `want` değerini aldığında hangi ifadeler hangi türde doğrulanmış olur?
local function tainted(e, env, ctx)
    for _, pe in ipairs(collectPaths(e)) do
        if info(pe, env, ctx) then return true end
    end
    return false
end

local function truths(c, want, ctx, out, env)
    local k = c.k
    if k == "Paren" then return truths(c.e, want, ctx, out, env) end
    if k == "Un" and c.op == "not" then return truths(c.e, not want, ctx, out, env) end

    if k == "Bin" then
        local op = c.op
        if op == "and" then
            if want then truths(c.l, true, ctx, out, env); truths(c.r, true, ctx, out, env) end
            return
        elseif op == "or" then
            if not want then truths(c.l, false, ctx, out, env); truths(c.r, false, ctx, out, env) end
            return
        elseif op == "==" or op == "~=" then
            local eqHolds = ((op == "==") == want)
            local l, r = c.l, c.r
            -- typeof(x) == "number"
            local function typeofArg(a, b)
                if a.k == "Call" and b.k == "Str" then
                    local nm = calleeName(a.fn)
                    if (nm == "typeof" or nm == "type") and a.args[1] then return a.args[1] end
                end
            end
            local ta = typeofArg(l, r) or typeofArg(r, l)
            if ta then
                if eqHolds then out[#out + 1] = { e = ta, kind = "type" } end
                return
            end
            -- x == nil / x ~= nil
            local nx = (isNil(r) and l) or (isNil(l) and r) or nil
            if nx then
                if not eqHolds then
                    out[#out + 1] = { e = nx, kind = "nil" }
                    if nx.k == "Index" and nx.key and nx.key.k ~= "Str" then
                        out[#out + 1] = { e = nx.key, kind = "member" }
                    end
                end
                return
            end
            -- x ~= x (NaN)
            local pl, pr = pathOf(l), pathOf(r)
            if pl and pl == pr then
                if eqHolds then
                    out[#out + 1] = { e = l, kind = "nan" }
                    out[#out + 1] = { e = l, kind = "type" }
                end
                return
            end
            if eqHolds then
                -- x % 1 == 0  → tamsayı/NaN'siz sayı
                local function modArg(a, b)
                    if a.k == "Bin" and a.op == "%" and b.k == "Num" then return a.l end
                end
                local ma = modArg(l, r) or modArg(r, l)
                if ma then
                    out[#out + 1] = { e = ma, kind = "nan" }
                    out[#out + 1] = { e = ma, kind = "type" }
                    return
                end
                -- x == "sabit" → x sabit bir izinli değer
                local lt = tainted(l, env, ctx)
                local rt = tainted(r, env, ctx)
                if lt and not rt then out[#out + 1] = { e = l, kind = "member" }
                elseif rt and not lt then out[#out + 1] = { e = r, kind = "member" } end
            end
            return
        elseif op == "<" or op == ">" or op == "<=" or op == ">=" then
            local l, r = c.l, c.r
            local lt, rt = tainted(l, env, ctx), tainted(r, env, ctx)
            local E, o
            if lt and not rt then
                E, o = l, op
            elseif rt and not lt then
                E = r
                o = ({ ["<"] = ">", [">"] = "<", ["<="] = ">=", [">="] = "<=" })[op]
            else
                return
            end
            -- |x| <= c  → iki yönlü sınır
            local inner, abs = E, false
            if E.k == "Call" and calleeName(E.fn) == "math.abs" and E.args[1] then inner, abs = E.args[1], true end
            local kinds
            if o == ">" or o == ">=" then
                kinds = want and { "min", "nan" } or { "max" }
            else
                kinds = want and { "max", "nan" } or { "min" }
            end
            if abs and (o == "<" or o == "<=") and want then kinds = { "min", "max", "nan" } end
            if abs and not want and (o == ">" or o == ">=") then kinds = { "min", "max" } end
            for _, pe in ipairs(collectPaths(inner)) do
                for _, kd in ipairs(kinds) do out[#out + 1] = { e = pe, kind = kd } end
            end
            return
        end
        return
    end

    if k == "Call" then
        local nm = calleeName(c.fn)
        if want then
            if nm == "table.find" and c.args[2] then
                out[#out + 1] = { e = c.args[2], kind = "member" }
                return
            end
            local post = ctx.post[c]
            if post then
                for _, pe in ipairs(post) do out[#out + 1] = pe end
            end
        end
        return
    end

    if k == "Method" then
        if want then
            if c.name == "IsA" then out[#out + 1] = { e = c.obj, kind = "type" } end
            if c.name == "IsDescendantOf" or c.name == "IsAncestorOf" then
                out[#out + 1] = { e = c.obj, kind = "scope" }
                out[#out + 1] = { e = c.obj, kind = "type" }
            end
            local post = ctx.post[c]
            if post then
                for _, pe in ipairs(post) do out[#out + 1] = pe end
            end
        end
        return
    end

    if k == "Name" or k == "Index" then
        if want then
            out[#out + 1] = { e = c, kind = "nil" }
            if k == "Index" and c.key and c.key.k ~= "Str" then
                out[#out + 1] = { e = c.key, kind = "member" }
            end
        end
    end
end

-- koşul bir yetki (admin/rank) kapısı mı?
local function isAuthCond(c, ctx)
    local hit = false
    local function scan(n)
        if hit or type(n) ~= "table" then return end
        if n.k == "Index" and n.key and n.key.k ~= "Str" then
            local base = (pathOf(n.obj) or ""):lower()
            local keyPath = (pathOf(n.key) or ""):lower()
            if containsAny(base, AUTH_WORDS) and keyPath:find(ctx.playerVar or "player", 1, true) then hit = true end
        end
        if n.k == "Call" or n.k == "Method" then
            local nm = ((n.k == "Method") and n.name or calleeName(n.fn) or ""):lower()
            if containsAny(nm, AUTH_WORDS) then hit = true end
        end
        local kids = {}
        -- hafif gezinti
        if n.k == "Bin" then kids = { n.l, n.r }
        elseif n.k == "Un" or n.k == "Paren" then kids = { n.e }
        elseif n.k == "Call" then kids = n.args
        elseif n.k == "Method" then kids = n.args
        elseif n.k == "Index" then kids = { n.obj }
        end
        for _, ch in ipairs(kids) do scan(ch) end
    end
    scan(c)
    return hit
end

local function applyTruths(list, env, ctx)
    for _, tr in ipairs(list) do
        for _, pe in ipairs(collectPaths(tr.e)) do
            local p = pathOf(pe)
            if p then
                local base = env[p] or info(pe, env, ctx)
                if base then env[p] = addKind(base, tr.kind) end
            end
        end
    end
end

-- ───────────────────────── sink ve gereksinimler ─────────────────────────
local function reqMissing(profile, v)
    local miss = {}
    if profile == "num" or profile == "vec" then
        if has(v, "member") then return miss end
        if not (has(v, "type") or has(v, "min") or has(v, "max") or has(v, "nan")) then miss[#miss + 1] = "type" end
        if profile == "num" and not has(v, "min") then miss[#miss + 1] = "min" end
        if not has(v, "max") then miss[#miss + 1] = "max" end
    elseif profile == "key" then
        if not has(v, "member") then miss[#miss + 1] = "member" end
        if not (has(v, "type") or has(v, "member")) then miss[#miss + 1] = "type" end
    elseif profile == "inst" then
        if not (has(v, "scope") or has(v, "member")) then miss[#miss + 1] = "scope" end
        if not (has(v, "type") or has(v, "scope") or has(v, "member")) then miss[#miss + 1] = "type" end
    else -- "exec"
        if not has(v, "member") then miss[#miss + 1] = "member" end
        if not (has(v, "type") or has(v, "member")) then miss[#miss + 1] = "type" end
    end
    return miss
end

local function missText(miss)
    local parts = {}
    for _, m in ipairs(miss) do parts[#parts + 1] = LABEL[m] or m end
    return table.concat(parts, ", ")
end

local function emit(ctx, f)
    f.file = ctx.file
    local key = f.cat .. "|" .. tostring(f.line) .. "|" .. f.title .. "|" .. tostring(ctx.file and ctx.file.path)
    if ctx.seen[key] then return end
    ctx.seen[key] = true
    ctx.findings[#ctx.findings + 1] = f
end

-- T'deki her kaynak için gereksinimi kontrol et; sink bulgusu + toplu (tip/aralık/NaN) kayıtları
local function sink(ctx, env, T, profile, cat, what, line, exec)
    if not T then return end
    if env["@authz"] and (cat == "target" or cat == "prop") then return end

    local bad, anyBad = {}, false
    local worst = "HIGH"
    for p, v in pairs(T) do
        local miss = reqMissing(profile, v)
        local acc = ctx.acc[p]
        if not acc then acc = { sinks = {} }; ctx.acc[p] = acc end
        if #miss > 0 then
            anyBad = true
            bad[#bad + 1] = "'" .. p .. "' (" .. missText(miss) .. ")"
            local hasType, hasMin, hasMax = false, false, false
            for _, m in ipairs(miss) do
                if m == "type" then hasType = true elseif m == "min" then hasMin = true elseif m == "max" then hasMax = true end
            end
            if hasType then acc.type = acc.type or { line = line, what = what } end
            if hasMin or hasMax then acc.range = acc.range or { line = line, what = what } end
            if cat == "economy" and hasType and (hasMin or hasMax) then worst = "CRITICAL" end
            if cat == "economy" and hasType and profile == "num" and #miss >= 3 then worst = "CRITICAL" end
        elseif profile == "num" or profile == "vec" then
            if not (has(v, "nan") or has(v, "member")) then
                acc.nan = acc.nan or { line = line, what = what }
            end
        end
    end
    if not anyBad then return end
    table.sort(bad)
    if cat == "exec" and exec == "critical" then worst = "CRITICAL" end
    if cat == "prop" then worst = "HIGH" end

    local fixes = {
        economy = "Miktarı/fiyatı client'tan alma; sunucudaki tablodan oku. Miktar gerekiyorsa:\n  if typeof(qty) ~= \"number\" or qty ~= qty then return end\n  qty = math.clamp(math.floor(qty), 1, MAX_QTY)",
        prop = "Değeri sunucuda sınırla:\n  if typeof(v) ~= \"number\" or v ~= v then return end\n  v = math.clamp(v, MIN, MAX)",
        dos = "Döngü/boyut sınırı koy:\n  n = math.clamp(n, 0, MAX_N)",
        target = "Hedefi sunucuda doğrula: izinli-liste (ALLOWED[x]), IsDescendantOf veya kendi oyuncunun verisi (player.UserId) ile sınırla.",
        exec = "Client girdisini kod/URL/asset olarak kullanma; sabit izinli listeden seç.",
    }
    emit(ctx, {
        cat = cat, level = worst, line = line,
        title = what,
        msg = "Client'tan gelen " .. table.concat(bad, ", ") .. " değeri doğrulanmadan bu noktaya ulaşıyor (satır " .. tostring(line) .. ").",
        fix = fixes[cat],
    })
end

-- ───────────────────────── gezinti ─────────────────────────
local walkBlock, visit, walkFunctionInline

local function isEconPath(path)
    local lp = (path or ""):lower()
    return lp:find("leaderstats", 1, true) ~= nil or containsAny(lp:match("[^%.]*$") or "", ECON_WORDS)
        or (lp:match("[^%.]*$") == "value" and containsAny(lp, ECON_WORDS))
end

local function classifyTarget(t)
    if t.k ~= "Index" or not t.name then return nil end
    local name = t.name
    local ln = name:lower()
    local path = pathOf(t) or ""
    if NUM_PROPS[ln] then return "num", "prop", "Client değeri '" .. name .. "' özelliğine yazılıyor" end
    if VEC_PROPS[ln] then return "vec", "prop", "Client değeri '" .. name .. "' özelliğine yazılıyor" end
    if name == "Parent" then return "inst", "target", "Client'tan gelen nesne Parent olarak atanıyor" end
    if name == "Value" or containsAny(ln, ECON_WORDS) or path:lower():find("leaderstats", 1, true) then
        if isEconPath(path) then
            return "num", "economy", "Client'tan gelen değer ekonomi yazımına ulaşıyor (" .. name .. ")"
        end
        return "num", "prop", "Client değeri '" .. path .. "' durumuna yazılıyor"
    end
    return nil
end

local function checkCall(e, env, ctx)
    local isM = e.k == "Method"
    local name = isM and e.name or calleeName(e.fn)
    local args = e.args
    local line = e.line

    -- yardımcı fonksiyon: bağlamsal (inline) analiz
    if ctx.resolve and ctx.depth < 2 and ctx.calls < 40 then
        local target = isM and e.obj or e.fn
        local r
        if not (name and (CLEAN_FN[name] or PASS_FN[name])) then
            r = ctx.resolve(isM and { k = "Index", obj = e.obj, name = e.name, key = { k = "Str", value = e.name } } or e.fn, ctx.file)
        end
        if r and r.fn and not ctx.stack[r.fn] then
            local argExprs = {}
            if isM and r.fn.params[1] == "self" then argExprs[1] = e.obj end
            for _, a in ipairs(args) do argExprs[#argExprs + 1] = a end
            local anyT = false
            local argT = {}
            for i, a in ipairs(argExprs) do
                argT[i] = info(a, env, ctx)
                if argT[i] then anyT = true end
            end
            if anyT then
                walkFunctionInline(r, argExprs, argT, e, ctx)
                return
            end
        end
    end

    if not isM and name then
        if name == "loadstring" or name == "require" then
            for _, a in ipairs(args) do
                local t = info(a, env, ctx)
                if t then
                    sink(ctx, env, t, "exec", "exec", name == "loadstring"
                        and "Client verisi loadstring ile çalıştırılıyor" or "Client verisi require() hedefi olarak kullanılıyor",
                        line, "critical")
                end
            end
        elseif name == "Instance.new" and args[1] then
            sink(ctx, env, info(args[1], env, ctx), "exec", "exec", "Client, Instance.new ile oluşturulacak sınıfı seçiyor", line)
        elseif name == "string.rep" and args[2] then
            sink(ctx, env, info(args[2], env, ctx), "vec", "dos", "Client değeri string.rep tekrar sayısı olarak kullanılıyor", line)
        elseif name == "table.create" and args[1] then
            sink(ctx, env, info(args[1], env, ctx), "vec", "dos", "Client değeri table.create boyutu olarak kullanılıyor", line)
        end
        return
    end

    if isM then
        local recvT = info(e.obj, env, ctx)
        local recvPath = (pathOf(e.obj) or ""):lower()
        local m = e.name

        if HTTP_METHODS[m] and recvPath:find("http", 1, true) then
            for _, a in ipairs(args) do
                sink(ctx, env, info(a, env, ctx), "exec", "exec", "Client verisi HTTP isteğinde kullanılıyor (SSRF)", line)
            end
        elseif DS_METHODS[m] then
            if args[1] then
                sink(ctx, env, info(args[1], env, ctx), "key", "target", "Client, DataStore anahtarını belirliyor", line)
            end
            if args[2] and m ~= "UpdateAsync" then
                local vt = info(args[2], env, ctx)
                if vt then
                    sink(ctx, env, vt, m == "IncrementAsync" and "num" or "exec", m == "IncrementAsync" and "economy" or "target",
                        "Client verisi doğrudan DataStore'a yazılıyor", line)
                end
            end
        elseif TELEPORT_METHODS[m] then
            for _, a in ipairs(args) do
                sink(ctx, env, info(a, env, ctx), "exec", "exec", "Client verisi TeleportService çağrısında kullanılıyor", line)
            end
        elseif NUM_METHODS[m] and args[1] then
            sink(ctx, env, info(args[1], env, ctx), "num", "prop", "Client değeri " .. m .. "() argümanı olarak kullanılıyor", line)
        elseif VEC_METHODS[m] then
            for _, a in ipairs(args) do
                sink(ctx, env, info(a, env, ctx), "vec", "prop", "Client değeri " .. m .. "() ile konum/hareket olarak uygulanıyor", line)
            end
        elseif m == "SetAttribute" then
            if args[1] then
                sink(ctx, env, info(args[1], env, ctx), "key", "target", "Client, SetAttribute isim anahtarını belirliyor", line)
            end
        elseif m == "FireAllClients" then
            for _, a in ipairs(args) do
                local t = info(a, env, ctx)
                if t then
                    emit(ctx, { cat = "relay", level = "LOW", line = line, title = "Client verisi tüm oyunculara yayınlanıyor",
                        msg = "FireAllClients ile filtresiz client girdisi yayılıyor (spam/aldatma).", fix = "Girdiyi doğrula/filtrele ve hız sınırla." })
                end
            end
        end
        -- client'ın seçtiği nesne üzerinde yıkıcı/taşıyıcı/hasar işlemi
        if recvT and (DESTRUCTIVE[m] or NUM_METHODS[m] or VEC_METHODS[m]) then
            sink(ctx, env, recvT, "inst", "target", "Client'tan gelen nesne üzerinde " .. m .. "() çağrılıyor", line)
        end
    end
end

local function assignSinks(t, valT, env, ctx, line, compound)
    -- t: hedef ifade; valT: atanan değerin taint'i
    if t.k ~= "Index" then return end
    -- hedef zincirindeki her dinamik anahtar: T[k].x = v  /  T[k] = v
    local o = t
    while o and o.k == "Index" do
        if o.key and o.key.k ~= "Str" then
            local kt = info(o.key, env, ctx)
            local objP = (pathOf(o.obj) or ""):lower()
            if kt and not info(o.obj, env, ctx) then
                local isData = containsAny(objP, DATA_WORDS)
                sink(ctx, env, kt, "key", "target",
                    isData and "Client, oyuncu/veri tablosunun anahtarını belirliyor" or "Client, tablo anahtarını belirliyor", line)
            end
        end
        o = o.obj
    end
    if valT then
        local profile, cat, what = classifyTarget(t)
        if profile then sink(ctx, env, valT, profile, cat, what, line) end
    end
end

visit = function(e, env, ctx)
    local k = e.k
    if k == "Call" then
        visit(e.fn, env, ctx)
        for _, a in ipairs(e.args) do visit(a, env, ctx) end
        checkCall(e, env, ctx)
    elseif k == "Method" then
        visit(e.obj, env, ctx)
        for _, a in ipairs(e.args) do visit(a, env, ctx) end
        checkCall(e, env, ctx)
    elseif k == "Bin" then
        visit(e.l, env, ctx); visit(e.r, env, ctx)
    elseif k == "Un" or k == "Paren" then
        visit(e.e, env, ctx)
    elseif k == "Index" then
        visit(e.obj, env, ctx)
        if e.key and e.key.k ~= "Str" then visit(e.key, env, ctx) end
    elseif k == "Table" then
        for _, it in ipairs(e.items) do
            if it.key and it.key.k ~= "Str" then visit(it.key, env, ctx) end
            visit(it.value, env, ctx)
        end
    elseif k == "IfExpr" then
        visit(e.cond, env, ctx); visit(e.a, env, ctx); visit(e.b, env, ctx)
    elseif k == "IStr" then
        for _, x in ipairs(e.parts) do visit(x, env, ctx) end
    elseif k == "Func" then
        -- kapanış (closure): yakalanan ortamla birlikte gez
        local inner = shallow(env)
        for _, pn in ipairs(e.params) do inner[pn] = nil end
        walkBlock(e.body, inner, ctx)
    end
end

local function stmtExits(st)
    local k = st.k
    if k == "Return" or k == "Break" or k == "Continue" then return true end
    if k == "CallStmt" then
        local c = st.call
        if c.k == "Call" and calleeName(c.fn) == "error" then return true end
        return false
    end
    if k == "If" and st.elseBlock then
        for _, c in ipairs(st.clauses) do
            local ex = false
            for _, s in ipairs(c.block.stmts) do if stmtExits(s) then ex = true break end end
            if not ex then return false end
        end
        for _, s in ipairs(st.elseBlock.stmts) do if stmtExits(s) then return true end end
        return false
    end
    if k == "Do" then
        for _, s in ipairs(st.block.stmts) do if stmtExits(s) then return true end end
    end
    return false
end

local function blockExits(b)
    for _, s in ipairs(b.stmts) do
        if stmtExits(s) then return true end
    end
    return false
end

local function setLocal(env, name, T)
    -- yeni değer: eski yol kayıtlarını (name.x) temizle
    local prefix = name .. "."
    for key in pairs(env) do
        if type(key) == "string" and key:sub(1, #prefix) == prefix then env[key] = nil end
    end
    env[name] = T
end

local function walkStmt(st, env, ctx)
    local k = st.k

    if k == "Local" then
        for _, v in ipairs(st.values) do visit(v, env, ctx) end
        local vals = {}
        for i, v in ipairs(st.values) do vals[i] = info(v, env, ctx) end
        for i, nm in ipairs(st.names) do
            local T = vals[i]
            if T == nil and i > #st.values and #st.values > 0 then
                local last = st.values[#st.values]
                if last.k == "Call" or last.k == "Method" or last.k == "Vararg" then T = vals[#st.values] end
            end
            setLocal(env, nm, T)
        end

    elseif k == "Assign" then
        for _, v in ipairs(st.values) do visit(v, env, ctx) end
        for _, t in ipairs(st.targets) do
            if t.k == "Index" then visit(t.obj, env, ctx) end
        end
        for i, t in ipairs(st.targets) do
            local vexpr = st.values[i] or st.values[#st.values]
            local T = vexpr and info(vexpr, env, ctx)
            if st.op then
                -- bileşik atama: hedefin mevcut değeriyle birleşir (doğrulama kaybolur)
                local cur = info(t, env, ctx)
                if T and cur then T = combine(stripKinds(T), stripKinds(cur)) end
                if not T then T = cur and stripKinds(cur) or nil end
                if vexpr then
                    local rhsT = info(vexpr, env, ctx)
                    assignSinks(t, rhsT, env, ctx, st.line, true)
                end
            else
                assignSinks(t, T, env, ctx, st.line, false)
            end
            local p = pathOf(t)
            if t.k == "Name" then
                setLocal(env, t.name, T)
            elseif p then
                if T then env[p] = T else env[p] = nil end
            end
        end

    elseif k == "CallStmt" then
        visit(st.call, env, ctx)
        local c = st.call
        if c.k == "Call" and calleeName(c.fn) == "assert" and c.args[1] then
            local list = {}
            truths(c.args[1], true, ctx, list, env)
            applyTruths(list, env, ctx)
        end

    elseif k == "If" then
        local branches = {}
        local running = shallow(env)
        local allNoExit = true
        for _, cl in ipairs(st.clauses) do
            visit(cl.cond, running, ctx)
            local tList, fList = {}, {}
            truths(cl.cond, true, ctx, tList, running)
            truths(cl.cond, false, ctx, fList, running)
            local thenEnv = shallow(running)
            applyTruths(tList, thenEnv, ctx)
            walkBlock(cl.block, thenEnv, ctx)
            if not blockExits(cl.block) then branches[#branches + 1] = thenEnv end
            if blockExits(cl.block) and isAuthCond(cl.cond, ctx) then
                running["@authz"] = true
            end
            applyTruths(fList, running, ctx)
        end
        local elseEnv = shallow(running)
        if st.elseBlock then
            walkBlock(st.elseBlock, elseEnv, ctx)
            if not blockExits(st.elseBlock) then branches[#branches + 1] = elseEnv end
        else
            branches[#branches + 1] = elseEnv
        end
        local merged = branches[1]
        for i = 2, #branches do merged = mergeEnv(merged, branches[i]) end
        if not merged then merged = running end
        for key in pairs(env) do env[key] = nil end
        for key, v in pairs(merged) do env[key] = v end

    elseif k == "While" then
        visit(st.cond, env, ctx)
        local inner = shallow(env)
        local tl = {}
        truths(st.cond, true, ctx, tl, env)
        applyTruths(tl, inner, ctx)
        walkBlock(st.block, inner, ctx)

    elseif k == "Repeat" then
        local inner = shallow(env)
        walkBlock(st.block, inner, ctx)
        visit(st.cond, inner, ctx)

    elseif k == "NumFor" then
        visit(st.start, env, ctx); visit(st.stop, env, ctx)
        if st.step then visit(st.step, env, ctx) end
        sink(ctx, env, info(st.stop, env, ctx), "vec", "dos", "Client değeri döngü üst sınırı olarak kullanılıyor", st.line)
        sink(ctx, env, info(st.start, env, ctx), "vec", "dos", "Client değeri döngü başlangıcı olarak kullanılıyor", st.line)
        local inner = shallow(env)
        inner[st.var] = nil
        walkBlock(st.block, inner, ctx)

    elseif k == "GenFor" then
        for _, x in ipairs(st.exprs) do visit(x, env, ctx) end
        local T
        for _, x in ipairs(st.exprs) do
            local xi = info(x, env, ctx)
            if xi then T = combine(T, xi) end
            if x.k == "Call" and x.args[1] then
                local ai = info(x.args[1], env, ctx)
                if ai then T = combine(T, ai) end
            end
        end
        local inner = shallow(env)
        for _, nm in ipairs(st.names) do inner[nm] = stripKinds(T) end
        walkBlock(st.block, inner, ctx)

    elseif k == "Do" then
        local inner = shallow(env)
        walkBlock(st.block, inner, ctx)

    elseif k == "Return" then
        for _, v in ipairs(st.values) do visit(v, env, ctx) end
        if ctx.retCollector then
            local falsy = (#st.values == 0) or (st.values[1].k == "Bool" and st.values[1].value == false) or st.values[1].k == "Nil"
            if not falsy then
                local rt
                for _, v in ipairs(st.values) do
                    local vi = info(v, env, ctx)
                    if vi then rt = combine(rt, vi) end
                end
                ctx.retCollector[#ctx.retCollector + 1] = { env = shallow(env), t = rt }
            end
        end

    elseif k == "LocalFunction" then
        env[st.name] = nil
    elseif k == "FunctionStmt" then
        -- yerel tanım; gövde çağrıldığında analiz edilir
    end
end

walkBlock = function(block, env, ctx)
    for _, st in ipairs(block.stmts) do
        walkStmt(st, env, ctx)
        if stmtExits(st) then break end
    end
end

-- Çözümlenmiş yardımcı fonksiyonu, çağıranın taint'leriyle inline gez.
-- argExprs[i] i. parametreye gelen argüman ifadesi; argT[i] onun taint'i.
walkFunctionInline = function(r, argExprs, argT, callNode, ctx)
    local fn = r.fn
    ctx.calls += 1
    ctx.stack[fn] = true
    ctx.depth += 1
    local savedFile, savedRet = ctx.file, ctx.retCollector
    ctx.file = r.file
    ctx.retCollector = {}

    local env = {}
    local paramTaint = {}
    for i, pn in ipairs(fn.params) do
        env[pn] = argT[i]
        paramTaint[i] = argT[i]
    end
    walkBlock(fn.body, env, ctx)

    local rets = ctx.retCollector
    ctx.file, ctx.retCollector = savedFile, savedRet
    ctx.depth -= 1
    ctx.stack[fn] = nil

    -- dönüş değeri taint'i
    local rt
    for _, rc in ipairs(rets) do
        if rc.t then rt = combine(rt, rc.t) end
    end
    ctx.ret[callNode] = rt or false

    -- guard etkisi: yalnız "doğru dönen" yollarda, DEĞER dönüşümü olmayan (v: olmayan) doğrulamalar
    if #rets > 0 then
        local post = {}
        for i, pn in ipairs(fn.params) do
            local ae = argExprs[i]
            if ae and argT[i] then
                local common
                for _, rc in ipairs(rets) do
                    local T = rc.env[pn]
                    local kinds = {}
                    if T then
                        -- bu parametrenin herhangi bir kaynağındaki doğrulamalar (kesişim)
                        local first = true
                        for _, v in pairs(T) do
                            if first then
                                for kd in pairs(v) do if kd:sub(1, 2) ~= "v:" then kinds[kd] = true end end
                                first = false
                            else
                                for kd in pairs(kinds) do if not v[kd] then kinds[kd] = nil end end
                            end
                        end
                    end
                    if common == nil then
                        common = kinds
                    else
                        for kd in pairs(common) do if not kinds[kd] then common[kd] = nil end end
                    end
                end
                for kd in pairs(common or {}) do post[#post + 1] = { e = ae, kind = kd } end
            end
        end
        ctx.post[callNode] = post
    end
end

-- ───────────────────────── dışa açık API ─────────────────────────
-- fnNode: handler Func düğümü. opts: { file=info, resolve=function(calleeExpr, curInfo) }
function Taint.analyze(fnNode, opts)
    local ctx = {
        findings = {}, seen = {}, acc = {}, ret = {}, post = {}, stack = {}, depth = 0, calls = 0,
        file = opts.file, resolve = opts.resolve,
        playerVar = fnNode.params[1],
    }
    local env = {}
    for i = 2, #fnNode.params do
        local pn = fnNode.params[i]
        env[pn] = { [pn] = {} }
    end
    if fnNode.isVararg then env["..."] = { ["..."] = {} } end

    walkBlock(fnNode.body, env, ctx)

    -- toplu bulgular (parametre başına)
    local params = {}
    for p in pairs(ctx.acc) do params[#params + 1] = p end
    table.sort(params)
    for _, p in ipairs(params) do
        local a = ctx.acc[p]
        if a.type then
            emit(ctx, {
                cat = "type", level = "HIGH", line = a.type.line, title = "Parametre tip/nil doğrulaması eksik: " .. p,
                msg = "'" .. p .. "' parametresi tip/nil doğrulaması olmadan kritik bir noktaya ulaşıyor (satır " .. tostring(a.type.line) ..
                    "): " .. a.type.what .. ". Exploiter beklenmeyen tip (table, nil, string…) gönderebilir.",
                fix = "Handler başında doğrula:\n  if typeof(" .. p .. ") ~= \"number\" then return end",
            })
        end
        if a.range then
            emit(ctx, {
                cat = "range", level = "HIGH", line = a.range.line, title = "Sayısal değer sınır kontrolü eksik: " .. p,
                msg = "'" .. p .. "' için alt/üst sınır kontrolü tamam değil (satır " .. tostring(a.range.line) ..
                    "): " .. a.range.what .. ". Negatif, çok büyük veya math.huge değerleri sorun çıkarabilir.",
                fix = "Sınırla:\n  " .. p .. " = math.clamp(" .. p .. ", 0, MAX)   -- veya: if " .. p .. " < 0 or " .. p .. " > MAX then return end",
            })
        end
        if a.nan then
            emit(ctx, {
                cat = "nan", level = "MEDIUM", line = a.nan.line, title = "NaN kontrolü eksik: " .. p,
                msg = "'" .. p .. "' aralık kontrolünden geçse de NaN karşılaştırmaları hep false döner; NaN bu kontrolleri atlatabilir (satır " ..
                    tostring(a.nan.line) .. ").",
                fix = "Ekle:\n  if " .. p .. " ~= " .. p .. " then return end",
            })
        end
    end
    return ctx.findings
end

-- ───────────────────────── handler / fonksiyon indeksi ─────────────────────────
-- ast içindeki isimli fonksiyonlar: name → Func düğümü
function Taint.functionIndex(ast, Ast)
    local idx = {}
    local aliases = {}
    Ast.walk(ast, function(n)
        local k = n.k
        if k == "LocalFunction" then
            idx[n.name] = n.fn
        elseif k == "FunctionStmt" then
            local t = n.target
            idx[t.name] = n.fn
        elseif k == "Assign" then
            for i, t in ipairs(n.targets) do
                local v = n.values[i]
                if v and v.k == "Func" and (t.k == "Name" or (t.k == "Index" and t.name)) then idx[t.name] = v end
            end
        elseif k == "Local" then
            for i, nm in ipairs(n.names) do
                local v = n.values[i]
                if v and v.k == "Func" then idx[nm] = v end
            end
        elseif k == "Table" then
            for _, it in ipairs(n.items) do
                if it.name and it.value.k == "Func" then
                    idx[it.name] = it.value
                elseif it.name and it.value.k == "Name" then
                    aliases[#aliases + 1] = { it.name, it.value.name }
                end
            end
        end
    end)
    for _, a in ipairs(aliases) do
        if not idx[a[1]] and idx[a[2]] then idx[a[1]] = idx[a[2]] end
    end
    return idx
end

-- Remote handler bağlamaları: X.OnServerEvent:Connect(fn) / X.OnServerInvoke = fn
-- dönen liste: { line=, member=, fn=Func|nil, ref=isim|nil }
function Taint.findBindings(ast, Ast)
    local out = {}
    Ast.walk(ast, function(n)
        if n.k == "Method" and (n.name == "Connect" or n.name == "Once" or n.name == "ConnectParallel")
           and n.obj.k == "Index" and (n.obj.name == "OnServerEvent") then
            local a = n.args[1]
            local b = { line = n.obj.line, member = "OnServerEvent" }
            if a and a.k == "Func" then b.fn = a
            elseif a and (a.k == "Name" or a.k == "Index") then b.ref = a.name end
            out[#out + 1] = b
        elseif n.k == "Assign" and #n.targets == 1 and n.targets[1].k == "Index" and n.targets[1].name == "OnServerInvoke" then
            local a = n.values[1]
            local b = { line = n.targets[1].line, member = "OnServerInvoke" }
            if a and a.k == "Func" then b.fn = a
            elseif a and (a.k == "Name" or a.k == "Index") then b.ref = a.name end
            out[#out + 1] = b
        end
    end)
    return out
end

return Taint

end)()

-- ─────────────────────────────────────────────────────────────────
-- YARDIMCI / MODÜL TAKİBİ
-- Handler'ın çağırdığı yerel fonksiyonlar ve require edilen modül fonksiyonları
-- (en fazla 2 seviye, 6 fonksiyon) çözülüp gövdeleri analiz metnine eklenir.
-- ─────────────────────────────────────────────────────────────────

-- `script.Parent.Mod`, `game:GetService("ServerStorage").Modules.X`, `RS:WaitForChild("X")` gibi
-- ifadeleri Instance'a çözer. Çözemezse nil.
local function resolveExpr(info, expr, depth)
    depth = depth or 0
    if depth > 4 then return nil end
    expr = expr:gsub("%s+", "")
    expr = expr:gsub(":(%a+)%(([\"'])([^\"']+)%2[^%)]*%)", function(m, _, n)
        if m == "WaitForChild" or m == "FindFirstChild" or m == "GetService" then return "." .. n end
    end)
    expr = expr:gsub("%[([\"'])([^\"']+)%1%]", ".%2")

    local cur, first = nil, true
    for seg in expr:gmatch("[^%.]+") do
        if first then
            first = false
            if seg == "script" then
                cur = info.obj
            elseif seg == "game" then
                cur = game
            elseif seg == "workspace" then
                cur = SVC("Workspace")
            else
                local rhs = info.src:match("local%s+" .. escapePat(seg) .. "%s*=%s*([^\n]+)")
                if rhs then cur = resolveExpr(info, rhs, depth + 1) end
                if not cur then
                    local ok, svc = pcall(SVC, seg)
                    if ok then cur = svc end
                end
            end
        else
            if not cur then return nil end
            if seg == "Parent" then
                cur = cur.Parent
            elseif cur == game then
                local ok, svc = pcall(SVC, seg)
                cur = ok and svc or nil
            else
                local ok, child = pcall(function() return cur:FindFirstChild(seg) end)
                cur = ok and child or nil
            end
        end
        if not cur then return nil end
    end
    return cur
end

-- local Mod = require(<ifade>)  →  { Mod = <modülün info'su> }
local function getReqMap(info)
    if info.reqMap then return info.reqMap end
    local map = {}
    info.reqMap = map
    for name, args in info.src:gmatch("local%s+([%a_][%w_]*)%s*=%s*require%s*(%b())") do
        local ok, target = pcall(resolveExpr, info, args:sub(2, -2), 0)
        if ok and target and INFO_BY_OBJ[target] then map[name] = INFO_BY_OBJ[target] end
    end
    return map
end

local SKIP_CALLS = {
    ["function"] = true, ["if"] = true, ["while"] = true, ["for"] = true, ["return"] = true,
    ["and"] = true, ["or"] = true, ["not"] = true, ["until"] = true, ["elseif"] = true, ["in"] = true,
}

-- st = { count, chars, visited, texts, names, delegated, paramSet }
local function collectHelpers(info, text, depth, st)
    if depth > 2 then return end
    local reqMap = getReqMap(info)

    local function take(defInfo, fn, args)
        if st.count >= 6 or st.chars > 20000 then return end
        -- parametre bu çağrıya argüman olarak devredildi mi?
        for p in pairs(st.paramSet) do
            if args:find(pRef(p)) then st.delegated[p] = true end
        end
        local key = defInfo.path .. ":" .. fn
        if st.visited[key] then return end
        local fs = lookupFunctionDef(defInfo, fn)
        if not fs then return end
        local e = findBlockEnd(defInfo.blank, fs)
        if not e then return end
        st.visited[key] = true
        local body = defInfo.src:sub(fs, e)
        st.count += 1
        st.chars += #body
        st.texts[#st.texts + 1] = body
        st.names[#st.names + 1] = (defInfo == info and fn) or (defInfo.name .. "." .. fn)
        collectHelpers(defInfo, body, depth + 1, st)
    end

    -- Modül fonksiyonları: Mod.fn(...) / Mod:fn(...)
    for recv, fn, args in text:gmatch("([%a_][%w_]*)%s*[%.:]%s*([%a_][%w_]*)%s*(%b())") do
        local m = reqMap[recv]
        if m then take(m, fn, args) end
    end
    -- Aynı script'teki yerel fonksiyonlar: fn(...)
    for pos, fn, args in text:gmatch("()([%a_][%w_]*)%s*(%b())") do
        local prev = pos > 1 and text:sub(pos - 1, pos - 1) or ""
        if not prev:find("[%w_%.:]") and not SKIP_CALLS[fn] then take(info, fn, args) end
    end
end

-- ─────────────────────────────────────────────────────────────────
-- AST ENTEGRASYONU
-- ─────────────────────────────────────────────────────────────────
local CONFIG = { useAst = true }
do
    local g = rawget(_G, "__DEEPSCAN_CONFIG")   -- test/ölçüm için dışarıdan geçersiz kılma
    if type(g) == "table" then
        for k, v in pairs(g) do CONFIG[k] = v end
    end
end

local function getAst(info)
    if info.ast == nil then
        local ast, err = Ast.parse(info.src)
        if ast then info.ast = ast else info.ast = false; info.astErr = err end
    end
    return info.ast or nil
end

local function funcIndexOf(info)
    if not info.fidx then
        local ast = getAst(info)
        info.fidx = ast and Taint.functionIndex(ast, Ast) or {}
    end
    return info.fidx
end

-- çağrılan ifadeyi (Name veya Mod.fn) fonksiyon gövdesine çöz
local function resolveCallee(e, curInfo)
    if not getAst(curInfo) then return nil end
    local idx = funcIndexOf(curInfo)
    if e.k == "Name" then
        local f = idx[e.name]
        if f then return { fn = f, file = curInfo } end
    elseif e.k == "Index" and e.obj.k == "Name" and e.name then
        local m = getReqMap(curInfo)[e.obj.name]
        if m and getAst(m) then
            local f = funcIndexOf(m)[e.name]
            if f then return { fn = f, file = m } end
        end
        -- aynı dosyada tanımlı yerel tablo: local M = {} ; function M.fn(...)
        if not m and curInfo.src:find("local%s+" .. escapePat(e.obj.name) .. "%s*=%s*{") then
            local f = idx[e.name]
            if f then return { fn = f, file = curInfo } end
        end
    end
    return nil
end

-- handler'ı AST'de bul ve taint analizi çalıştır. Başarısızsa nil, neden.
local function tryAst(hInfo, hPos)
    if not CONFIG.useAst then return nil end
    local ast = getAst(hInfo)
    if not ast then
        return nil, "AST ayrıştırılamadı" .. (hInfo.astErr and (": " .. tostring(hInfo.astErr.msg) .. " (satır " .. tostring(hInfo.astErr.line) .. ")") or "")
    end
    if not hInfo.bindings then hInfo.bindings = Taint.findBindings(ast, Ast) end
    local hLine = lineAt(hInfo.src, hPos)
    local best
    for _, b in ipairs(hInfo.bindings) do
        if b.line == hLine then best = b; break end
    end
    if not best then
        for _, b in ipairs(hInfo.bindings) do
            if math.abs(b.line - hLine) <= 1 then best = b; break end
        end
    end
    if not best then return nil, "handler AST'de bulunamadı" end
    local fn = best.fn or (best.ref and funcIndexOf(hInfo)[best.ref])
    if not fn then return nil, "handler fonksiyonu çözülemedi" end
    local ok, res = pcall(Taint.analyze, fn, { file = hInfo, resolve = resolveCallee })
    if not ok then return nil, "taint analizi hatası: " .. tostring(res) end
    return res
end

-- ─────────────────────────────────────────────────────────────────
-- TARAMA A — REMOTE'LAR
-- ─────────────────────────────────────────────────────────────────
local function scanRemotes()
    print("  📡 Remote analizi başlıyor... (" .. #REMOTES .. " remote)")

    local handlerCandidates, dynamicBinders = {}, {}
    for _, info in ipairs(INFOS) do
        if (info.kind == "server" or info.kind == "shared") and #info.src > 0 then
            handlerCandidates[#handlerCandidates + 1] = info
            local s = info.src
            if s:find("OnServer%a+") and (s:find("GetChildren", 1, true) or s:find("GetDescendants", 1, true)
                or s:find("%[%s*[%a_][%w_]*%s*%]%s*%.%s*OnServer")) then
                dynamicBinders[#dynamicBinders + 1] = info
            end
        end
    end

    local nameCount = {}
    for _, r in ipairs(REMOTES) do nameCount[r.Name] = (nameCount[r.Name] or 0) + 1 end
    local dupWarned = {}

    for _, remote in ipairs(REMOTES) do
        throttle()
        local name, path = remote.Name, getPath(remote)
        local isFunc = remote:IsA("RemoteFunction")
        local clientOk = isClientAccessible(remote)
        local serverMember = isFunc and "OnServerInvoke" or "OnServerEvent"

        if nameCount[name] > 1 and not dupWarned[name] then
            dupWarned[name] = true
            issue("LOW", "Aynı isimde " .. nameCount[name] .. " remote: " .. name, path,
                "Eşleştirme isim üzerinden yapıldığı için handler eşleşmesi belirsiz olabilir.",
                "Remote'lara benzersiz isim ver.", { obj = remote })
        end

        -- handler ara
        local hInfo, hPos
        for _, info in ipairs(handlerCandidates) do
            if info.src:find(name, 1, true) then
                local pos = findMemberUse(info.src, name, { serverMember })
                if pos then hInfo, hPos = info, pos; break end
            end
        end

        if not hInfo then
            -- Server→Client remote mu?
            local clientDir = false
            for _, info in ipairs(INFOS) do
                if #info.src > 0 and info.src:find(name, 1, true)
                   and findMemberUse(info.src, name, CLIENT_MEMBERS) then
                    clientDir = true; break
                end
            end

            local unreadableNote = SCAN_STATS.unreadable > 0
                and (" (" .. SCAN_STATS.unreadable .. " script'in Source'u okunamadığı için handler orada olabilir.)") or ""

            if clientDir then
                issue("OK", name, path,
                    "Server→Client remote görünüyor (OnClientEvent/FireClient kullanımı bulundu); OnServerEvent gerekmiyor.",
                    nil, { obj = remote })
            elseif #dynamicBinders > 0 then
                local where = {}
                for k = 1, math.min(3, #dynamicBinders) do where[k] = dynamicBinders[k].path end
                issue("MEDIUM", "Handler bulunamadı (dinamik bağlama olası): " .. name, path,
                    "Bu isimle doğrudan bağlanan handler görünmüyor ama şu script(ler)de döngü/index ile OnServer bağlantısı var: " ..
                    table.concat(where, ", ") .. ". Handler orada olabilir; oradaki doğrulamaları elle incele." .. unreadableNote,
                    "Dinamik handler'ların da parametre doğrulaması yaptığından emin ol.",
                    { obj = dynamicBinders[1].obj, sel = remote })
            elseif clientOk then
                issue("LOW", "Handler'sız Remote: " .. name, path,
                    "Client erişebilir ama hiçbir server script'te OnServerEvent/OnServerInvoke bağlantısı bulunamadı. Handler yoksa ateşlemenin etkisi olmaz; kullanılmıyorsa temizlik adayıdır." .. unreadableNote,
                    "Kullanılmıyorsa sil; kullanılıyorsa server'da handler ekle ve parametreleri doğrula.", { obj = remote })
            else
                issue("LOW", "Handler bulunamadı (server-only): " .. name, path,
                    "Client erişemeyen bir remote; handler görünmüyor. Kullanılmıyor olabilir." .. unreadableNote,
                    "Kullanılmıyorsa sil.", { obj = remote })
            end
        else
            local body, params = extractHandler(hInfo, hPos)
            local scopeNote = ""
            local helperText, helperNames, delegated = "", {}, {}
            if not body then
                body, params = hInfo.src, nil
                scopeNote = "\n         Not: Handler gövdesi ayrıştırılamadı; script'in tamamı analiz edildi (kesinlik düşük)."
            else
                local st = { count = 0, chars = 0, visited = {}, texts = {}, names = {}, delegated = {}, paramSet = {} }
                if params then
                    for i = 2, #params do st.paramSet[params[i]] = true end
                end
                local okH, errH = pcall(collectHelpers, hInfo, body, 0, st)
                if not okH then
                    scopeNote = "\n         Not: yardımcı fonksiyon takibi başarısız oldu (" .. tostring(errH) .. ")."
                end
                helperText, helperNames, delegated = table.concat(st.texts, "\n"), st.names, st.delegated
                if #helperNames > 0 then
                    scopeNote = scopeNote .. "\n         Analize dahil edilen yardımcı fonksiyonlar: " .. table.concat(helperNames, ", ")
                end
            end

            local astFindings, astNote = tryAst(hInfo, hPos)
            local findings
            if astFindings then
                findings = analyzeHandler(name, body, params, helperText, delegated, true)
                for _, af in ipairs(astFindings) do findings[#findings + 1] = af end
            else
                findings = analyzeHandler(name, body, params, helperText, delegated)
                if astNote then
                    scopeNote = scopeNote .. "\n         Not: " .. astNote .. " — regex analizine dönüldü."
                end
            end
            local where = "Handler: " .. hInfo.path .. "  |  Remote: " .. path
            local hLine = lineAt(hInfo.src, hPos)

            if #findings == 0 then
                issue("OK", name, path,
                    "Handler bulundu (" .. hInfo.path .. "). Heuristik kontroller geçti — bu güvenlik garantisi değildir; kapsam dışı yardımcılardaki doğrulamalar ve mantık hataları görülemez." .. scopeNote,
                    nil, { obj = hInfo.obj, line = hLine, sel = remote, cat = "ok", remote = name })
            else
                for _, f in ipairs(findings) do
                    local meta = { obj = (f.file and f.file.obj) or hInfo.obj, line = f.line or hLine, sel = remote,
                                   cat = f.cat, remote = name }
                    issue(f.level, "[Remote: " .. name .. "] " .. f.title, where, f.msg .. scopeNote, f.fix, meta)
                end
            end
        end
    end
end

-- ─────────────────────────────────────────────────────────────────
-- TARAMA B — CLIENT / PAYLAŞILAN KOD
-- ─────────────────────────────────────────────────────────────────
local function scanClientCode()
    print("  🖥️  Client/paylaşılan kod analizi başlıyor...")
    for _, info in ipairs(INFOS) do
        if (info.kind == "client" or info.kind == "shared") and #info.src >= 5 then
            throttle()
            local n = runLineRules(info, COMMON_RULES, false)
            n += runLineRules(info, CLIENT_RULES, info.kind == "shared")
            if n == 0 then
                issue("OK", info.name, info.path, "Bilinen tehlikeli pattern bulunamadı.", nil, { obj = info.obj })
            end
        end
    end
end

-- ─────────────────────────────────────────────────────────────────
-- TARAMA C — SERVER KODU
-- ─────────────────────────────────────────────────────────────────
local function scanServerCode()
    print("  🐛 Server kod analizi başlıyor...")
    for _, info in ipairs(INFOS) do
        if info.kind == "server" and #info.src >= 5 then
            throttle()
            runLineRules(info, COMMON_RULES, false)
            runLineRules(info, SERVER_RULES, false)
            scanLoops(info)
        end
    end
end

-- ─────────────────────────────────────────────────────────────────
-- TARAMA D — MİMARİ
-- ─────────────────────────────────────────────────────────────────
local SUSPICIOUS_REMOTE_NAMES = {
    "GiveMoney", "AddCash", "GiveCash", "AddMoney", "SetMoney", "ResetMoney",
    "Admin", "AdminCommand", "RunCommand", "Execute",
    "Kick", "BanPlayer", "Ban", "Unban",
    "GiveItem", "GiveWeapon", "GiveTool", "AddItem",
    "SetHealth", "SetHp", "GodMode", "Invincible",
    "Kill", "Respawn", "RevivePlayer",
    "Teleport", "TeleportTo", "SetPosition", "MoveTo",
    "Fly", "Noclip", "Speed", "SetSpeed",
    "GivePoints", "AddPoints", "SetPoints", "AddXP", "GiveXP",
    "SetLevel", "LevelUp", "GiveLevel",
    "GiveAmmo", "AddAmmo", "InfiniteAmmo",
}

local EXPOSED_SERVER_HINTS = { "ServerStorage", "ServerScriptService", "OnServerEvent", "OnServerInvoke" }
local EXPOSED_SECRET_HINTS = { "webhook", "api_key", "apikey", "secret" }

local function scanArchitecture()
    print("  🏗️  Mimari analiz başlıyor...")

    for _, remote in ipairs(REMOTES) do
        local lowerName = remote.Name:lower()
        for _, bad in ipairs(SUSPICIOUS_REMOTE_NAMES) do
            if lowerName == bad:lower() then
                issue("LOW",
                    "Tahmin edilebilir Remote ismi: '" .. remote.Name .. "'",
                    getPath(remote),
                    "RemoteSpy gibi araçlar remote'ları zaten listeler; isim gizlemek asıl korumayı sağlamaz. Bu isim yalnızca hedefi 'ilginç' gösterir. Asıl koruma handler'daki doğrulamadır (yukarıdaki Remote bulgularına bak).",
                    "İsteğe bağlı: daha nötr bir isim ver. UYARI: client kodun isme WaitForChild(\"" .. remote.Name .. "\") ile bağlıysa oyunu bozmamak için iki tarafı birlikte güncelle. GUID gibi rastgele isimler bakımı zorlaştırır.", { obj = remote })
                break
            end
        end
    end

    for _, info in ipairs(INFOS) do
        throttle()
        local obj = info.obj

        -- LocalScript ServerScriptService'de
        if obj:IsA("LocalScript") and inService(obj, "ServerScriptService")
           and not obj:FindFirstAncestorOfClass("Tool") then
            issue("MEDIUM", "ServerScriptService'de LocalScript: " .. obj.Name, info.path,
                "LocalScript'ler yalnızca Backpack, PlayerGui, PlayerScripts, Character ve ReplicatedFirst gibi client konumlarında çalışır; ServerScriptService'de çalışmaz.",
                "LocalScript'i StarterPlayerScripts/StarterGui'ye taşı ya da Script (RunContext = Client) kullan.", { obj = obj })
        end

        -- Legacy Script ReplicatedStorage'da (Tool şablonu değilse)
        if obj:IsA("Script") and runContextOf(obj) == "Legacy" and inService(obj, "ReplicatedStorage")
           and not obj:FindFirstAncestorOfClass("Tool") then
            issue("LOW", "ReplicatedStorage'da Legacy Script: " .. obj.Name, info.path,
                "RunContext = Legacy olan Script'ler ReplicatedStorage'da çalışmaz. (Klonlanan bir şablonsa sorun yok; RunContext = Server/Client ise burada çalışabilir.)",
                "Server kodu ServerScriptService'de olsun; ya da Script.RunContext'i açıkça Server/Client yap.", { obj = obj })
        end

        -- İstemciye replicate olan ModuleScript'te server-only ipuçları / secret
        if obj:IsA("ModuleScript") and info.kind == "shared"
           and (inService(obj, "ReplicatedStorage")) and #info.src > 0 then
            local lower = info.src:lower()
            local secret = anyPlain(lower, EXPOSED_SECRET_HINTS)
            local serverHint = anyPlain(info.src, EXPOSED_SERVER_HINTS)
            if secret then
                issue("HIGH", "[" .. obj.Name .. "] Olası secret ifadesi paylaşılan modülde: '" .. secret .. "'", info.path,
                    "ReplicatedStorage içeriği client'a replicate olur; exploiter modülün Source'unu okuyabilir. (Bu bir heuristik: 'secret' kelimesi masum bir isim de olabilir.)",
                    "API anahtarı/webhook/secret'ı ServerStorage veya ServerScriptService'te tut.", { obj = obj })
            elseif serverHint then
                issue("MEDIUM", "[" .. obj.Name .. "] Server'a özel ifade paylaşılan modülde: '" .. serverHint .. "'", info.path,
                    "Bu modül ReplicatedStorage'da olduğu için client tarafından okunabilir. Server iş mantığını gizli sanıyorsan gizli değildir.",
                    "Yalnız server'ın kullandığı modülü ServerStorage/ServerScriptService'e taşı.", { obj = obj })
            end
        end
    end
end

-- ─────────────────────────────────────────────────────────────────
-- RAPOR YAZICI
-- ─────────────────────────────────────────────────────────────────
local function indent(s)
    return (s:gsub("\n", "\n       "))
end

local function printReport()
    local R, hidden = {}, 0
    for lvl, list in pairs(REPORT) do
        R[lvl] = {}
        for _, r in ipairs(list) do
            if IGNORED[r.key] then hidden += 1 else R[lvl][#R[lvl] + 1] = r end
        end
    end
    local counts = {
        CRITICAL = #R.CRITICAL, HIGH = #R.HIGH, MEDIUM = #R.MEDIUM,
        LOW = #R.LOW, OK = #R.OK,
    }

    print("\n")
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║          🔍 DEEP SECURITY SCAN RAPORU — v4.2                     ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")
    print(string.format("📊 Remote: %d  |  Server Script: %d  |  Client Script: %d  |  Paylaşılan Modül: %d",
        SCAN_STATS.remotes, SCAN_STATS.serverScripts, SCAN_STATS.clientScripts, SCAN_STATS.sharedScripts))
    print(string.format("   🔴 Kritik: %d  |  🟠 Yüksek: %d  |  🟡 Orta: %d  |  🔵 Düşük: %d  |  ✅ Heuristik geçti: %d",
        counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW, counts.OK))
    print("═══════════════════════════════════════════════════════════════════")

    if SCAN_STATS.unreadable > 0 then
        print(string.format("⚠️  %d script'in Source'u OKUNAMADI (plugin izni/erişim). Bu script'ler taranmadı; 'temiz' sayılmamalı.",
            SCAN_STATS.unreadable))
    end
    if hidden > 0 then
        print(string.format("🚫 %d bulgu 'yok say' listesinde olduğu için gizlendi.", hidden))
    end
    print("ℹ️  Bu bir heuristik statik analizdir: yanlış pozitif/negatif olabilir, gerçek güvenliğin yerine geçmez.")

    local function printSection(label, emoji, items)
        if #items == 0 then return end
        print(string.format("\n%s %s  (%d bulgu)", emoji, label, #items))
        print("───────────────────────────────────────────────────────────────────")
        for i, r in ipairs(items) do
            print(string.format("[%d] %s", i, r.title))
            print(string.format("    📍 %s", r.path))
            print(string.format("    ℹ  %s", indent(r.detail)))
            if r.fix and r.fix ~= "—" then
                print(string.format("    🔧 %s", indent(r.fix)))
            end
            print("")
        end
    end

    printSection("KRİTİK", "🔴", R.CRITICAL)
    printSection("YÜKSEK RİSK", "🟠", R.HIGH)
    printSection("ORTA RİSK", "🟡", R.MEDIUM)
    printSection("DÜŞÜK", "🔵", R.LOW)

    if counts.OK > 0 then
        print(string.format("\n✅ HEURİSTİK KONTROLLERİ GEÇENLER (%d) — 'güvenli' anlamına gelmez", counts.OK))
        print("───────────────────────────────────────────────────────────────────")
        for _, r in ipairs(R.OK) do
            print(string.format("  ✅  %s  —  %s", r.path, r.detail))
        end
    end

    print("\n═══════════════════════════════════════════════════════════════════")
    if counts.CRITICAL > 0 then
        print(string.format("🚨 %d KRİTİK bulgu var. Yayınlamadan önce incele.", counts.CRITICAL))
    elseif counts.HIGH > 0 then
        print(string.format("⚠️  %d yüksek riskli bulgu var. İncelemeni öneririm.", counts.HIGH))
    elseif counts.MEDIUM > 0 then
        print("💛 Orta riskli bulgular var. Gözden geçir.")
    else
        print("🎉 Bu heuristiklerle ciddi bulgu çıkmadı. (Yine de kritik remote'ları elle kontrol et.)")
    end
    print("═══════════════════════════════════════════════════════════════════\n")
end

-- ─────────────────────────────────────────────────────────────────
-- ARAYÜZ (DockWidget)
-- ─────────────────────────────────────────────────────────────────
local SEV = { CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, OK = 5 }
local LEVELS_ALL = { "CRITICAL", "HIGH", "MEDIUM", "LOW", "OK" }
local LEVEL_LABEL = { CRITICAL = "KRİTİK", HIGH = "YÜKSEK", MEDIUM = "ORTA", LOW = "DÜŞÜK", OK = "GEÇTİ" }
local CHIP_LABEL = { CRITICAL = "Kritik", HIGH = "Yüksek", MEDIUM = "Orta", LOW = "Düşük", OK = "Geçti" }
local LEVEL_COLOR = {
    CRITICAL = Color3.fromRGB(215, 65, 65), HIGH = Color3.fromRGB(230, 130, 40),
    MEDIUM = Color3.fromRGB(205, 170, 40), LOW = Color3.fromRGB(70, 140, 215),
    OK = Color3.fromRGB(70, 175, 100),
}
local MAX_CARDS = 150

local UI = {
    filters = { CRITICAL = true, HIGH = true, MEDIUM = true, LOW = true, OK = false },
    showIgnored = false, search = "", expanded = {},
}
local ui, widget = nil, nil
local themedList = {}
local render

local function mk(class, props, parent)
    local o = Instance.new(class)
    for k, v in pairs(props) do o[k] = v end
    if parent then o.Parent = parent end
    return o
end

local function tc(guide, fallback)
    local ok, c = pcall(function()
        return settings().Studio.Theme:GetColor(Enum.StudioStyleGuideColor[guide])
    end)
    return (ok and c) or fallback
end

local function palette()
    return {
        bg = tc("MainBackground", Color3.fromRGB(46, 46, 46)),
        card = tc("InputFieldBackground", Color3.fromRGB(37, 37, 37)),
        text = tc("MainText", Color3.fromRGB(230, 230, 230)),
        sub = tc("SubText", Color3.fromRGB(160, 160, 160)),
        btn = tc("Button", Color3.fromRGB(60, 60, 60)),
        btnText = tc("ButtonText", Color3.fromRGB(230, 230, 230)),
        accent = tc("DialogMainButton", Color3.fromRGB(0, 130, 220)),
    }
end

local function themed(obj, prop, key)
    themedList[#themedList + 1] = { obj, prop, key }
end

local function setStatus(text)
    if ui and ui.status then ui.status.Text = text end
end

local function openFinding(f)
    local target = f.obj
    if target and target.Parent and target:IsA("LuaSourceContainer") then
        task.spawn(function()
            local ok = pcall(function() plugin:OpenScript(target, f.line or 1) end)
            if not ok then
                pcall(function() game:GetService("ScriptEditorService"):OpenScriptDocumentAsync(target) end)
            end
        end)
    end
    local sel = f.sel or f.obj
    if sel and sel.Parent then
        pcall(function() game:GetService("Selection"):Set({ sel }) end)
    end
end

local function visibleFindings()
    local out, q = {}, UI.search:lower()
    for _, f in ipairs(FINDINGS) do
        local ig = IGNORED[f.key]
        if UI.filters[f.level] and (UI.showIgnored or not ig) and (q == "" or f.hay:find(q, 1, true)) then
            out[#out + 1] = f
        end
    end
    table.sort(out, function(a, b)
        if SEV[a.level] ~= SEV[b.level] then return SEV[a.level] < SEV[b.level] end
        local an, bn = a.isNew and 1 or 0, b.isNew and 1 or 0
        if an ~= bn then return an > bn end
        return a.seq < b.seq
    end)
    return out
end

local function makeCard(f, order, P)
    local ignored = IGNORED[f.key]
    local exp = UI.expanded[f.key]
    local card = mk("Frame", {
        Size = UDim2.new(1, 0, 0, 0), AutomaticSize = Enum.AutomaticSize.Y,
        BackgroundColor3 = P.card, BackgroundTransparency = ignored and 0.6 or 0,
        BorderSizePixel = 0, LayoutOrder = order,
    }, ui.list)
    mk("UICorner", { CornerRadius = UDim.new(0, 4) }, card)
    mk("UIPadding", { PaddingLeft = UDim.new(0, 10), PaddingRight = UDim.new(0, 10),
        PaddingTop = UDim.new(0, 6), PaddingBottom = UDim.new(0, 6) }, card)
    mk("UIListLayout", { SortOrder = Enum.SortOrder.LayoutOrder, Padding = UDim.new(0, 3) }, card)

    local function label(text, order2, size, color, font)
        return mk("TextLabel", {
            Size = UDim2.new(1, 0, 0, 0), AutomaticSize = Enum.AutomaticSize.Y, BackgroundTransparency = 1,
            Text = text, TextWrapped = true, TextXAlignment = Enum.TextXAlignment.Left,
            TextYAlignment = Enum.TextYAlignment.Top, TextSize = size, TextColor3 = color,
            Font = font or Enum.Font.SourceSans, LayoutOrder = order2, RichText = false,
        }, card)
    end

    local badge = "● " .. LEVEL_LABEL[f.level] .. (f.isNew and "   ·   YENİ" or "") .. (ignored and "   ·   YOK SAYILDI" or "")
    label(badge, 1, 12, LEVEL_COLOR[f.level], Enum.Font.SourceSansBold)

    local titleBtn = mk("TextButton", {
        Size = UDim2.new(1, 0, 0, 0), AutomaticSize = Enum.AutomaticSize.Y, BackgroundTransparency = 1,
        Text = (exp and "▼ " or "▶ ") .. f.title, TextWrapped = true, TextXAlignment = Enum.TextXAlignment.Left,
        TextColor3 = P.text, Font = Enum.Font.SourceSansBold, TextSize = 15, LayoutOrder = 2,
    }, card)
    titleBtn.MouseButton1Click:Connect(function()
        UI.expanded[f.key] = (not UI.expanded[f.key]) or nil
        render()
    end)

    label(f.path, 3, 12, P.sub)
    if exp then
        label(f.detail, 4, 14, P.text)
        if f.fix and f.fix ~= "—" then
            label("🔧 " .. f.fix, 5, 13, P.text, Enum.Font.Code)
        end
    end

    local row = mk("Frame", { Size = UDim2.new(1, 0, 0, 24), BackgroundTransparency = 1, LayoutOrder = 9 }, card)
    mk("UIListLayout", { FillDirection = Enum.FillDirection.Horizontal, Padding = UDim.new(0, 6),
        SortOrder = Enum.SortOrder.LayoutOrder }, row)
    local function small(text, width, cb)
        local b = mk("TextButton", {
            Text = text, Size = UDim2.new(0, width, 0, 22), BackgroundColor3 = P.btn, TextColor3 = P.btnText,
            Font = Enum.Font.SourceSans, TextSize = 13, BorderSizePixel = 0,
        }, row)
        mk("UICorner", { CornerRadius = UDim.new(0, 4) }, b)
        b.MouseButton1Click:Connect(cb)
    end
    if f.obj or f.sel then small("📂 Aç", 70, function() openFinding(f) end) end
    if ignored then
        small("↩ Geri al", 84, function() IGNORED[f.key] = nil; saveIgnored(); render() end)
    else
        small("🚫 Yok say", 90, function() IGNORED[f.key] = true; saveIgnored(); render() end)
    end
end

render = function()
    if not ui then return end
    local P = palette()

    local counts, nIgnored = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, OK = 0 }, 0
    for _, f in ipairs(FINDINGS) do
        if IGNORED[f.key] then nIgnored += 1 else counts[f.level] += 1 end
    end
    for _, lvl in ipairs(LEVELS_ALL) do
        local chip = ui.chips[lvl]
        chip.Text = CHIP_LABEL[lvl] .. " " .. counts[lvl]
        chip.BackgroundColor3 = UI.filters[lvl] and LEVEL_COLOR[lvl] or P.btn
        chip.TextColor3 = UI.filters[lvl] and Color3.new(1, 1, 1) or P.btnText
    end
    ui.ignoredChip.Text = "Gizli " .. nIgnored
    ui.ignoredChip.BackgroundColor3 = UI.showIgnored and P.accent or P.btn
    ui.ignoredChip.TextColor3 = UI.showIgnored and Color3.new(1, 1, 1) or P.btnText

    local scrollPos = ui.list.CanvasPosition
    for _, c in ipairs(ui.list:GetChildren()) do
        if not c:IsA("UIListLayout") and not c:IsA("UIPadding") then c:Destroy() end
    end

    local vis = visibleFindings()
    for i, f in ipairs(vis) do
        if i > MAX_CARDS then break end
        makeCard(f, i, P)
    end

    local note
    if #vis == 0 then
        note = (#FINDINGS == 0) and "Henüz tarama yok. ▶ Tara'ya bas." or "Bu filtreyle gösterilecek bulgu yok."
    elseif #vis > MAX_CARDS then
        note = string.format("… %d bulgu daha var. Filtreyi daralt veya ara.", #vis - MAX_CARDS)
    end
    if note then
        mk("TextLabel", { Size = UDim2.new(1, 0, 0, 40), BackgroundTransparency = 1, Text = note, TextColor3 = P.sub,
            TextSize = 14, Font = Enum.Font.SourceSans, LayoutOrder = MAX_CARDS + 1 }, ui.list)
    end
    ui.list.CanvasPosition = scrollPos
end

local function applyTheme()
    if not ui then return end
    local P = palette()
    for _, t in ipairs(themedList) do
        pcall(function() t[1][t[2]] = P[t[3]] end)
    end
    render()
end

local scanning = false
local runScan

local function buildUI()
    local P = palette()
    local dinfo = DockWidgetPluginGuiInfo.new(Enum.InitialDockState.Right, false, false, 480, 640, 340, 300)
    widget = plugin:CreateDockWidgetPluginGui("DeepSecurityScannerWidget", dinfo)
    widget.Title = "Deep Security Scanner"
    local u = { chips = {} }

    local root = mk("Frame", { Size = UDim2.fromScale(1, 1), BackgroundColor3 = P.bg, BorderSizePixel = 0 }, widget)
    themed(root, "BackgroundColor3", "bg")

    local function button(text, parent, size, pos, isAccent)
        local b = mk("TextButton", {
            Text = text, Size = size, Position = pos, BorderSizePixel = 0, TextSize = 14,
            Font = Enum.Font.SourceSansSemibold,
            BackgroundColor3 = isAccent and P.accent or P.btn,
            TextColor3 = isAccent and Color3.new(1, 1, 1) or P.btnText,
        }, parent)
        mk("UICorner", { CornerRadius = UDim.new(0, 4) }, b)
        if not isAccent then
            themed(b, "BackgroundColor3", "btn")
            themed(b, "TextColor3", "btnText")
        else
            themed(b, "BackgroundColor3", "accent")
        end
        return b
    end

    -- üst çubuk
    u.scanButton = button("▶ Tara", root, UDim2.new(0, 84, 0, 26), UDim2.new(0, 6, 0, 6), true)
    u.status = mk("TextLabel", {
        Position = UDim2.new(0, 98, 0, 6), Size = UDim2.new(1, -300, 0, 26), BackgroundTransparency = 1,
        Text = "Hazır", TextXAlignment = Enum.TextXAlignment.Left, TextColor3 = P.sub, TextSize = 13,
        Font = Enum.Font.SourceSans, TextTruncate = Enum.TextTruncate.AtEnd,
    }, root)
    themed(u.status, "TextColor3", "sub")
    local resetBtn = button("↺ Sıfırla", root, UDim2.new(0, 74, 0, 26), UDim2.new(1, -80, 0, 6))
    local consoleBtn = button("📋 Konsol", root, UDim2.new(0, 74, 0, 26), UDim2.new(1, -158, 0, 6))

    -- filtre çipleri
    local chipRow = mk("Frame", { Position = UDim2.new(0, 6, 0, 38), Size = UDim2.new(1, -12, 0, 54),
        BackgroundTransparency = 1 }, root)
    mk("UIListLayout", { FillDirection = Enum.FillDirection.Horizontal, Wraps = true, Padding = UDim.new(0, 4),
        SortOrder = Enum.SortOrder.LayoutOrder }, chipRow)
    local function chip(order)
        local b = mk("TextButton", { Size = UDim2.new(0, 76, 0, 24), BorderSizePixel = 0, TextSize = 13,
            Font = Enum.Font.SourceSansSemibold, LayoutOrder = order, Text = "", BackgroundColor3 = P.btn }, chipRow)
        mk("UICorner", { CornerRadius = UDim.new(0, 12) }, b)
        return b
    end
    for i, lvl in ipairs(LEVELS_ALL) do
        local c = chip(i)
        u.chips[lvl] = c
        c.MouseButton1Click:Connect(function() UI.filters[lvl] = not UI.filters[lvl]; render() end)
    end
    u.ignoredChip = chip(10)
    u.ignoredChip.MouseButton1Click:Connect(function() UI.showIgnored = not UI.showIgnored; render() end)

    -- arama
    u.search = mk("TextBox", {
        Position = UDim2.new(0, 6, 0, 94), Size = UDim2.new(1, -12, 0, 26), BackgroundColor3 = P.card,
        TextColor3 = P.text, PlaceholderColor3 = P.sub, PlaceholderText = "Ara (başlık, yol, açıklama)…",
        Text = "", ClearTextOnFocus = false, TextXAlignment = Enum.TextXAlignment.Left, TextSize = 14,
        Font = Enum.Font.SourceSans, BorderSizePixel = 0,
    }, root)
    mk("UICorner", { CornerRadius = UDim.new(0, 4) }, u.search)
    mk("UIPadding", { PaddingLeft = UDim.new(0, 8) }, u.search)
    themed(u.search, "BackgroundColor3", "card")
    themed(u.search, "TextColor3", "text")
    u.search:GetPropertyChangedSignal("Text"):Connect(function()
        UI.search = u.search.Text
        render()
    end)

    -- liste
    u.list = mk("ScrollingFrame", {
        Position = UDim2.new(0, 0, 0, 126), Size = UDim2.new(1, 0, 1, -126), BackgroundTransparency = 1,
        BorderSizePixel = 0, ScrollBarThickness = 8, AutomaticCanvasSize = Enum.AutomaticSize.Y,
        CanvasSize = UDim2.new(0, 0, 0, 0),
    }, root)
    mk("UIListLayout", { SortOrder = Enum.SortOrder.LayoutOrder, Padding = UDim.new(0, 6) }, u.list)
    mk("UIPadding", { PaddingLeft = UDim.new(0, 6), PaddingRight = UDim.new(0, 12), PaddingTop = UDim.new(0, 4),
        PaddingBottom = UDim.new(0, 8) }, u.list)

    u.scanButton.MouseButton1Click:Connect(function() runScan() end)
    consoleBtn.MouseButton1Click:Connect(function()
        if #FINDINGS == 0 then setStatus("Önce tarama yap.") else printReport() end
    end)
    resetBtn.MouseButton1Click:Connect(function()
        IGNORED = {}
        saveIgnored()
        render()
        setStatus("Yok sayma listesi sıfırlandı.")
    end)

    pcall(function() settings().Studio.ThemeChanged:Connect(applyTheme) end)
    ui = u
    render()
end

-- ─────────────────────────────────────────────────────────────────
-- ANA AKIŞ
-- ─────────────────────────────────────────────────────────────────
runScan = function()
    if scanning then
        warn("Deep Scan zaten çalışıyor, bitmesini bekle.")
        return
    end
    scanning = true
    resetAll()
    setStatus("Taranıyor…")

    print("\n🚀 Deep Security Scan v4.2 başlatılıyor...")
    local t0 = os.clock()

    local ok, err = pcall(function()
        buildIndex()
        setStatus(string.format("İndekslendi: %d script, %d remote. Analiz ediliyor…", #INFOS, #REMOTES))
        scanRemotes()
        scanClientCode()
        scanServerCode()
        scanArchitecture()
    end)

    scanning = false

    if not ok then
        warn("❌ Tarama sırasında beklenmedik hata:", err)
        setStatus("Hata: " .. tostring(err))
        return
    end

    local ms = (os.clock() - t0) * 1000
    local hidden, c = 0, { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, OK = 0 }
    local newCount = 0
    for _, f in ipairs(FINDINGS) do
        if IGNORED[f.key] then hidden += 1 else c[f.level] += 1 end
        if f.isNew and not IGNORED[f.key] then newCount += 1 end
    end
    saveLastKeys()

    local summary = string.format("%d kritik · %d yüksek · %d orta · %d düşük  (%d yeni, %d gizli, %.0f ms)",
        c.CRITICAL, c.HIGH, c.MEDIUM, c.LOW, newCount, hidden, ms)
    print("✅ Tarama bitti: " .. summary)
    if ui then
        setStatus(summary)
        render()
    else
        printReport()
    end
end

local uiOk, uiErr = pcall(buildUI)
if not uiOk then
    warn("Arayüz oluşturulamadı, konsol modunda çalışılacak:", uiErr)
    ui = nil
end

scanBtn.Click:Connect(function()
    if ui and widget then
        widget.Enabled = not widget.Enabled
    else
        runScan()
    end
end)

if widget then
    widget:GetPropertyChangedSignal("Enabled"):Connect(function()
        scanBtn:SetActive(widget.Enabled)
    end)
end

print("✅ Deep Security Scanner v0.1 yüklendi.")
print("   Plugins sekmesinde '🔍 Deep Scan' butonu paneli açar/kapatır; panelden ▶ Tara'ya bas.")
