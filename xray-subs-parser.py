#!/bin/python3
from argparse import ArgumentParser # Обработка консольных аргументов 
from urllib.parse import urlsplit, parse_qs, unquote # Обработка URL
from urllib.request import urlopen, Request # Запрос по URL
from base64 import b64decode # Декодирование ответа по URL
from json import dumps # Формирование JSON
from platform import uname # Имя системы
from hashlib import sha256 # Хеш-функция 

# Программа
app_name = "Xray-subs-parser"
app_version = "v0.1"
# ID устройства 
## Используется для идентификации на стороне сервера. 
## Если не требуется, то можно заменить пустыми значениями
device_os = f"{uname().system}/{uname().release}/{uname().version}"
node = uname().node
hwid = sha256(device_os.encode("ascii")).hexdigest()

def parse_subscribtion(url: str) -> list[str] | list:
    """
    Делает запрос по указанной ссылке и получает в ответ url-конфиги.
    Если ответ закодирован в base64, то сначала декодирует его.
    Возвращает список из строк с url-конфигами. 
    Если при запросе возникает ошибка - возвращает пустой список
    """
    
    try:
        response = Request(
            url,
            headers = {
                "User-Agent": f"{app_name}/{app_version}",
                "Accept": "*/*",
                "x-hwid": hwid,
                "x-device-os": device_os,
                "x-app-version": f"{app_name}/{app_version}",
                "x-client-name": node,
            }
        )
        response = urlopen(response).read().decode("UTF-8")
    except: 
        print(f"Ошибка запроса подписки") 
        return []
    else:
        try:
            decode_response = b64decode(response).decode("UTF-8")
            config_urls = decode_response.split("\n")
        except:
            print(f"Ответ не закодирован в base64") 
            config_urls = response.split("\n")
    return config_urls

def url2json(url: str, tag: str = "") -> dict:
    """
    Получает из url-ссылки параметры конфига и подставляет их в шаблон.
    Возвращает словарь с готовой конфигурацией.
    Если протокол не поддерживается - возвращает пустой словарь
    """
    
    url_split = urlsplit(url)
    parse_url = parse_qs(url_split.query)
    
    # Базовый шаблон outbound
    
    outbound = {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
      },
      "streamSettings": {
        "network": "raw",
        "security": "none",
      },
      "mux": {
        "enabled": True,
        "concurrency": 8,
        "xudpConcurrency": -1,
        "xudpProxyUDP443": "skip"
      }
    }
    
    # Удобно посмотреть содержимсое url
    # print(f"\n#====#\n{url_split}\n\n{parse_url}\n#====#\n")
    
    # Настройка прокси-протокола 
    match url_split.scheme:
        case "vless":
            # Шаблон настроек прокси-протокола
            settings = {
                "vnext": [
                    {
                        "address": "",
                        "port": 443,
                        "users": [
                            {
                                "id": "",
                                "encryption": "none",
                                "flow": "",
                                "level": 0
                            }
                        ]
                    }     
                ]
            }
            
            # Подстановка основных настроек 
            outbound["protocol"] = url_split.scheme
            settings["vnext"][0]["address"] = url_split.hostname
            if url_split.port != None:
                settings["vnext"][0]["port"] = url_split.port
            settings["vnext"][0]["users"][0]["id"] = url_split.username
            
            # Подставнока необязательных параметров
            for setting in parse_url:
                match setting:
                    case "encryption":
                        settings["vnext"][0]["users"][0]["encryption"] = parse_url["encryption"][0]
                    case "flow":
                        settings["vnext"][0]["users"][0]["flow"] = parse_url["flow"][0]
                    case _:
                        pass
            outbound["settings"].update(settings)

        case "hy2" | "hysteria2":
            settings = {
                "version": 2,
                "address": "",
                "port": 443
            }
            
            # Подстановка основных настроек 
            outbound["protocol"] = url_split.scheme
            settings["address"] = url_split.hostname
            if url_split.port != None:
                settings["port"] = url_split.port
            outbound["settings"].update(settings)    
            # "hysteriaSettings": {
              # "version": 2,
              # "auth": "",
              # "congestion": "brutal",
              # "up": "900mbps",
              # "down": "900mbps",
              # "tcpFastOpen": True,
              # "recvWindowConn": 15728640,
              # "recvWindow": 62914560,
              # "disableMTUDiscovery": False
            # }
        case _:
            print("Неизвестный прокси-протокол") 
    
    # Настройка транспорт-протокола
    ## Возможно потом добавлю параметры именно транспортов
    if parse_url.get("type") != None:
        match parse_url["type"][0]:
            case "tcp":
                outbound["streamSettings"]["network"] = parse_url["type"][0]
            case "xhttp":
                outbound["streamSettings"]["network"] = parse_url["type"][0]
            case "hysteria":
                outbound["streamSettings"]["network"] = parse_url["type"][0]
            case _:
                print("Неизвестный транспорт-протокол") 
    elif parse_url.get("packetEncoding") == ["xudp"]:
        outbound["streamSettings"]["network"] = "xhttp"
    else:
        print("Отсутствует транспорт-протокол") 
    
    # Настройка secutity-протокола
    if parse_url.get("security") != None:
        match parse_url["security"][0]:
            case "tls":
                tlsSettings = {
                    "tlsSettings": {
                        "serverName": "",
                        "allowInsecure": False,
                        "alpn": ["h2", "http/1.1"],
                        "fingerprint": "",
                    }
                }
                
                # Подстановка основных настроек 
                outbound["streamSettings"]["security"] = parse_url["security"][0]
                if parse_url.get("sni") != None and lenght(parse_url.get("sni")) != 0:
                    realitySettings["tlsSettings"]["serverName"] = parse_url["sni"][0]
                else:
                    realitySettings["tlsSettings"]["serverName"] = url_split.hostname
                
                # Подстановка необязательных настроек 
                for setting in parse_url:
                    match setting:
                        case "allowInsecure":
                            tlsSettings["tlsSettings"]["allowInsecure"] = parse_url[setting][0]
                        case "alpn":
                            tlsSettings["tlsSettings"]["alpn"] = parse_url[setting]
                        case "fp":
                            tlsSettings["tlsSettings"]["fingerprint"] = parse_url[setting][0]
                        case _:
                            pass 
                outbound["streamSettings"].update(tlsSettings)
            case "reality":
                realitySettings = {
                    "realitySettings": {
                        "serverName": "",
                        "publicKey": "",
                        "fingerprint": "",
                        "shortId": "",
                        "spiderX": ""
                    }
                }
                
                # Подстановка основных настроек 
                outbound["streamSettings"]["security"] = parse_url["security"][0]
                if parse_url.get("sni") != None and (parse_url.get("sni")) != 0:
                    realitySettings["realitySettings"]["serverName"] = parse_url["sni"][0]
                else:
                    realitySettings["realitySettings"]["serverName"] = url_split.hostname
                
                # Подстановка необязательных настроек 
                for setting in parse_url:
                    match setting:
                        case "pbk":
                            realitySettings["realitySettings"]["publicKey"] = parse_url[setting][0]
                        case "fp":
                            realitySettings["realitySettings"]["fingerprint"] = parse_url[setting][0]
                        case "sid":
                            realitySettings["realitySettings"]["shortId"] = parse_url[setting][0]
                        case "spx":
                            realitySettings["realitySettings"]["spiderX"] = parse_url[setting][0]
                        case _:
                            pass 
                outbound["streamSettings"].update(realitySettings)
            case _:
                print("Неизвестный sucurity-протокол") 
    else:
        print("Отсутствует sucurity-протокол") 
        
    # Подстановка тега
    if tag != "":
        pass
    elif url_split.fragment != "":
        tag = url_split.fragment
    else:
        tag = outbound["protocol"]
    outbound["tag"] = tag
        
    return outbound

def create_json_config(outbounds: dict[list], path: str = "./", file_name: str = "outbounds_proxy.json") -> None:
    """
    Создаёт файл по указанному пути с указанным именем файла.
    """
    outbounds_json = dumps(outbounds, indent=2, ensure_ascii = False)
    with open(f"{path}/{file_name}", "w", encoding="utf-8") as config:
        config.write(outbounds_json)
        
def args_parser() -> list:
    """
    Обрабатывает аргументы передаваемые в консоли
    """
    argparser = ArgumentParser(
        prog=app_name,
        description = "Парсер подписок для Xray. Сбор доступных ссылок конфигов и конвертация их в JSON конфиги."
    )
    argparser.add_argument(
        "url", 
        #dest=url,
        help="Ссылка на подписку или конфигурацию (https, vless)."
    )
    argparser.add_argument(
        "-t", "--tag", 
        #dest=tag,
        default = "proxy",
        help="Тег конфигурации. Будет добавться в имя конфигурации и имя файла (PROTOCOL-TAG-LOCATION-INDEX.json)."
    )
    argparser.add_argument(
        "-f", "--file", 
        #dest=file,
        help="Файл с ссылками подписок и конфигураций. Каждая ссылка должна быть отдельной строке (TAG URL)"
    )
    argparser.add_argument(
        "-c", "--cron", 
        action="store_true",
        help="Добавить задачу обновления подписки каждый час в crontab."
    )
    argparser.add_argument(
        "-V", "--version", 
        action="version",
        version=f"{app_name}/{app_version}",
        help="Версия программы."
    )
    args = argparser.parse_args()
    
    return args
    
def main() -> None:
    """
    Принимает вводные данные и вызывает необходимые функции.
    """
    # Собираем аргументы комманды
    args = args_parser()
    # print (args)
    url = args.url
    tag = args.tag # Тег для конфигурации
    
    url_split = urlsplit(url)
    match url_split.scheme:
        case "https":
            print(f"Обработка подписки от {url_split.netloc}") 
            config_urls = [unquote(config_url) for config_url in parse_subscribtion(url)]
            outbounds = {"outbounds": []}
            for config_url in config_urls:
                print(unquote(config_url))
                outbound = url2json(unquote(config_url), tag) 
                outbounds["outbounds"].append(outbound)
            create_json_config(outbounds, file_name=f"{tag}.json")
        case _:
            print(unquote(url))
            outbound = url2json(unquote(url), tag) 
            outbounds = {"outbounds": [outbound]}
            create_json_config(outbound, file_name=f"{tag}.json")
    

if __name__ == "__main__":
    main()