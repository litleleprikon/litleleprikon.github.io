---
layout: post
title:  "Meltdown and Spectre"
short_title: 'Критическая уязвимость процессоров'
date:   2018-01-05 04:40:00
comments: true
tags: [infosec]
---

Чем грозит и как работает недавно обнародованная уязвимость в процессорах.

> **TL;DR:**![](/images/2018/meltdown-spectre/duck.jpg)![](/images/2018/meltdown-spectre/gandalf.jpg)

## Подводка(конвейер, спекулятивное исполнение, кэш)

### Конвейер

Итак, для того, чтоб понять, как работает уязвимости Meltdown и Spectre, надо для начала понять, как работает сам процессор. Современные процессоры используют вычислительный конвейер, чтобы выполнять программы быстрее. Программы состоят из инструкций, которые выполняются процессором последовательно и цикл выполнения каждой инструкции состоит из нескольких шагов, например:

* Прочитать инструкцию из памяти
* Исполнить инструкцию
* Записать результат в память и/или регистры

Современные же процессоры умеют каждый шаг этого цикла исполнять отдельно: после того, как первая инструкция загрузилась и начинает исполняться, следующая за ней инструкция уже так же загружается, не дожидаясь, пока цикл исполнения предыдущей команды завершит свое исполнение.

[![Общий четырёхуровневых конвейер; цветные квадраты символизируют независимые друг от друга инструкции. Источник-Wikipedia](/images/2018/meltdown-spectre/pipeline.png)](https://ru.wikipedia.org/wiki/Вычислительный_конвейер#/media/File:Pipeline,_4_stage.svg)

### Спекулятивное выполнение

Недостатком такого подхода являются случаи, когда последовательные инструкции не могут быть выполнены одновременно. Такие ситуации называются конфликтами и возникают если например в последующих инструкциях используются результаты выполнения текущей инструкции. В момент, когда происходит конфликт, некоторые ядра процессора вынуждены простаивать, пока конфликт не разрешится, что плачевно сказывается на производительности. Иной возможной причиной конфликта может являться условный переход и жта ситуация называется конфликтом по управлению. При условном переходе программа как бы ветвится в зависимости от какого-то условия и выполняется либо одна, либо другая последовательность инструкций. Такие конфликты не позволяют процессору параллельно выполнять последующие инструкции, пока не известен результат проверки условия.

Чтоб процессор не простаивал, придумана такая оптимизация, которая называется спекулятивным исполнением. Процессоры с данной технологией могут предсказывать, какие инструкции будут занимать много процессорного времени и выполнять следующие после них инструкции не дожидаясь результата предыдущей. Когда же предыдущай инструкция все-таки будет выполнена, и окажется, что смысла выполнять последующие не было, процессор просто отзовет результаты последующих.


### Кэш

Для работы процессор берет данные из оперативной памяти. Для ускорения доступа к данным в процессорах используется кэш. Кэш-это небольшая область памяти, находящаяся непосредственно в самом процессоре и доступ к ней в десятки раз быстрее, чем доступ к оперативной памяти. В кэш не получится поместить все данные из оперативной памяти, однако данные, нужные процессору, или данные, которые станут нужны позднее, загружаются в кэш, дабы ускорить доступ к этим данным и соответственно ускорить работу программы.

### Предсказатель переходов

Механизм в процессорах с конвейерной архитектурой, который заранее предсказывает результат выполнения условия в условных операторах и заранее загружает инструкции из оперативной памяти в кэш процессора, позволяя не ждать загрузки инструкций, когда они действительно понадобятся.

## Принципы работы уязвимости

Исследователи нашли три варианта уязвимости:

* Bounds check bypass ([CVE-2017-5753](https://vulners.com/search?query=CVE-2017-5753))
* Branch target injection ([CVE-2017-5715](https://vulners.com/search?query=CVE-2017-5715))
* Rogue data cache load ([CVE-2017-5754](https://vulners.com/search?query=CVE-2017-5754))

### Spectre

```c
if (x < array1_size)
    y = array2[array1[x] * 256];
```

Благодаря спекулятивному исполнению код будет выполняться так: сначала процессор попытается вычислить значение `x < array1_size`. Значения `array1_size` может не оказаться в кэше процессора и для лучшего использования ресурсов, процессор попытается исполнить `y = array2[array1[x] * 256];`, пока `array1_size` достается из относительно медленной оперативной памяти. Если же значение `x` больше, чем длина массива, то мы получаем доступ к данным за пределом массива. Конечно же процессор не даст просто так доступ к этим даным, ведь когда он поймет, что `x < array1_size` ложно, он откатит состояние на момент до `y = array2[array1[x] * 256];`. Однако, если `y = array2[array1[x] * 256];` успеет выполниться, то в кэш процессора попадет ячейка памяти по адресу `array2 + (array1[x] * 256);`. Теперь, если перебирать каждый байт после адреса `array2` и смотреть, как быстро процессор отдает значение, можно предположить, какая ячейка памяти лежит в кэше. А номер данной ячейки будет равен значению ячейки памяти `array1+x` помноженному на 256. Таким образом можно, перебирая, получать данные из памяти, находящейся в недоступной области для атакующего процесса.

Самым неприятным являет то, что таким образом JS может читать данные из памяти браузера, не предназначеные ему, что чревато кражей данных сайтами прямиком из браузера.

```javascript
if (index < simpleByteArray.length) {
  index = simpleByteArray[index | 0];
  index = (((index * TABLE1_STRIDE)|0) & (TABLE1_BYTES-1))|0;
  localJunk ^= probeTable[index|0]|0;
}
```

Рассмотрим другой пример:

```c
struct array {
 unsigned long length;
 unsigned char data[];
};
struct array *arr1 = ...; /* small array */
struct array *arr2 = ...; /* array of size 0x400 */
/* >0x400 (OUT OF BOUNDS!) */
unsigned long untrusted_offset_from_caller = ...;
if (untrusted_offset_from_caller < arr1->length) {
 unsigned char value = arr1->data[untrusted_offset_from_caller];
 unsigned long index2 = ((value&1)*0x100)+0x200;
 if (index2 < arr2->length) {
   unsigned char value2 = arr2->data[index2];
 }
}
```

В данном примере `untrusted_offset_from_caller < arr1->length` будет выполняться относительно долго, если `arr1->length` не находится в кэше и процессор, не дожидаясь вычисления условия, начнет выполнять блок данных дальше и прочтет данные в `arr1->data[untrusted_offset_from_caller]`, которые не должны быть прочитаны из-за проверки адреса. Конечно же после вычисления условия последствия всех инструкций в блоке кода будут отменены, отднако:

```c
 unsigned long index2 = ((value&1)*0x100)+0x200;
 if (index2 < arr2->length) {
   unsigned char value2 = arr2->data[index2];
 }
 ```

 Тут в зависимости от от первого бита байта `value`, который является значением памяти по адресу `arr1->data[untrusted_offset_from_caller]` в кэш будет записан либо `arr2->data[0x200]`, либо `arr2->data[0x300]`. Дальше, измерив время доступа к памяти к адресам `0x200` и `0x300` в `arr2->data`, можно узнать значение первого бита `value`.

Другим вариантом уязвимости Spectre является использование предсказателя переходов: злоумышленник запутывает предсказатель переходов, заставляя его заранее предсказать переход на область памяти, в которой лежит код злоумышленника. Процессор исполнит код, подсунутый злоумышленником и когда поймет, что исполнять его не стоило, откатит изменения. Однако черерз кэш можно восстановить данные, которые были считаны на предыдущем шаге атаки.

Информация взята из исследования [**Spectre Attacks: Exploiting Speculative Execution**](https://spectreattack.com/spectre.pdf)

Продожение следует... [https://litleleprikon.me/2018/01/05/meltdown-and-spectre-2.html](https://litleleprikon.me/2018/01/05/meltdown-and-spectre-2.html)
