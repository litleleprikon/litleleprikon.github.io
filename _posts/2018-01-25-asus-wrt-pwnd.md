---
layout: post
title:  "Уязвимости прошивке AsusWRT"
short_title: "Уязвимости прошивке AsusWRT"
date:   2018-01-25 18:23:00
comments: true
tags: [infosec]
---

В прошивке AsusWRT, используемой в роутерах ASUS, найдены уязвимости, позволяющие произвести атаку remote code execution, если злоумышленник находится в одной локальной сети с роутером. Уязвимости обнаружены исследователем Pedro Ribeiro (pedrib@gmail.com) и опубликованы на [GitHub](https://raw.githubusercontent.com/pedrib/PoC/master/advisories/asuswrt-lan-rce.txt).

## HTTP server authentication bypass

**[CVE-2018-5999](https://vulners.com/cve/CVE-2018-5999)**

Первая уязвимость состоит в том, что несмотря на отрицательную проверку аутентификации, обработка POST запроса продолжается.

```c
handle_request(void)
{
...
    handler->auth(auth_userid, auth_passwd, auth_realm);
    auth_result = auth_check(auth_realm, authorization, url, file, cookies, fromapp);

    if (auth_result != 0) // auth fails
    {
        if(strcasecmp(method, "post") == 0){
            if (handler->input) {
                handler->input(file, conn_fp, cl, boundary); // but POST request is still processed
            }
            send_login_page(fromapp, auth_result, NULL, NULL, 0);
        }
        //if(!fromapp) http_logout(login_ip_tmp, cookies);
        return;
    }
...
}
```

В данном куске кода результат работы функции [`auth_check`](https://github.com/RMerl/asuswrt-merlin/blob/master/release/src/router/httpd/httpd.c#L511-L590) означает, авторизованный ли это запрос(`0`) или нет (любое другое не нулевое значение, означающим, что не так пошло во время проверки аутентификации). Однако в случае ошибки аутентификации вместо отклонения запроса происходит другая проверка на то, что запрос POST и если он POST, то запрос выполнятся.

## Unauthorised configuration change (NVRAM value setting)

**[CVE-2018-6000](https://vulners.com/cve/CVE-2018-6000)**

Используя предыдущую уязвимость, возможно вызвать функцию [`do_vpnupload_post`](https://github.com/RMerl/asuswrt-merlin/blob/master/release/src/router/httpd/web.c#L8742-L8830), которая позволяет устанавливать [NVRAM переменные](https://wikileaks.org/ciav7p1/cms/page_26968084.html). В NVRAM переменных хранятся данные, необходимые для работы прошивки, в том числе и пароль админа. Наипростейший способ использовать данную уязвимость-установить новый пароль для админа и открыть SSH. Однако такую атаку легко обнаружить, по-этому есть другой способ атаки. Необходимо установить переменную NVRAM `ateCommand_flag` в `1`, после чего демон `infosvr`, который открывает UDP порт на `9999`, начинает исполнять команды, переданные в пакете, от пользователя `root`. Структура пакета приведена ниже:

```c
- Header
  typedef struct iboxPKTEx
  {
    BYTE		ServiceID;
    BYTE		PacketType;
    WORD		OpCode;
    DWORD 		Info; // Or Transaction ID
    BYTE		MacAddress[6];
    BYTE		Password[32];   //NULL terminated string, string length:1~31, cannot be NULL string
  } ibox_comm_pkt_hdr_ex;

- Body
  typedef struct iboxPKTCmd
  {
    WORD		len;
    BYTE		cmd[420];		<--- command goes here
  } PKT_SYSCMD;		// total 422 bytes
```

Также доступен [эксплоит для Metasploit](https://raw.githubusercontent.com/pedrib/PoC/master/exploits/metasploit/asuswrt_lan_rce.rb)