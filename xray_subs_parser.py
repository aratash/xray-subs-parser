#!/bin/python3
from argparse import ArgumentParser # Обработка консольных аргументов 
from urllib.parse import urlsplit, parse_qs, unquote # Обработка URL
from urllib.request import urlopen, Request # Запрос по URL
from base64 import b64decode # Декодирование ответа по URL
from json import dumps # Формирование JSON
from platform import uname # Имя системы
from hashlib import sha256 # Хеш-функция 
import os # Взаимодействие с файловой системой

# Программа
app_name = "Xray-subs-parser"
app_version = "v1.0.2"
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
    print(f"[I] Парсинг подписки: {url}")
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
        print(f"[E] Ошибка запроса подписки") 
        return []
    else:
        try:
            decode_response = b64decode(response).decode("UTF-8")
            config_urls = decode_response.split("\n")
        except:
            config_urls = response.split("\n")
    return config_urls

def url2json(url: str, tag: str = "", addTag: str = "") -> dict:
    """
    Получает из url-ссылки параметры конфига и подставляет их в шаблон.
    Возвращает словарь с готовой конфигурацией.
    Если протокол не поддерживается - возвращает пустой словарь
    """
    print(f"[I] Обработка url-конфигурации: {url}")
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
                        "address": "127.0.0.1",
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
                "address": "127.0.0.1",
                "port": 443
            }
            hysteriaSettings = {
                "hysteriaSettings": {
                    "version": 2,
                    "auth": "",
                    "udpIdleTimeout": 60
                }
            }
            tlsSettings = {
                "tlsSettings": {
                    "serverName": "",
                    "allowInsecure": False,
                    "alpn": ["h3"],
                    "fingerprint": "",
                }
            }
            finalmask = {
                "finalmask": {
                    "udp": [],
                    "quicParams": {
                        "congestion": "force-brutal",
                        "bbrProfile": "standard",
                        "brutalUp": 0,
                        "brutalDown": 0,
                        "udpHop": {
                          "ports": "",
                          "interval": ""
                        }
                    }
                }
            }
            
            # Подстановка основных настроек 
            outbound["protocol"] = url_split.scheme
            settings["address"] = url_split.hostname
            
            hyPort = url_split.netloc.split(":")[-1]
            if "-" in hyPort:
                settings["port"] = int(hyPort.split("-")[0])
                finalmask["finalmask"]["quicParams"]["udpHop"]["ports"] = hyPort
            
            if parse_url.get("sni") != None and parse_url.get("sni"):
                tlsSettings["tlsSettings"]["serverName"] = parse_url["sni"][0]
            else:
                tlsSettings["tlsSettings"]["serverName"] = url_split.hostname
                
            for param in parse_url.keys():
                match param:
                    case "obfs-password": 
                        udpParams = {
                            "type": "salamander",
                            "settings": {
                                "password": parse_url[param][0]
                            }
                        }
                        finalmask["finalmask"]["udp"].append(udpParams)
                    case "upmbps":
                        finalmask["finalmask"]["quicParams"]["brutalUp"] = parse_url[param][0]
                    case "downmbps":
                        finalmask["finalmask"]["quicParams"]["brutalDown"] = parse_url[param][0]
                    case "hop_interval":
                        finalmask["finalmask"]["quicParams"]["udpHop"]["interval"] = parse_url[param][0]
                    case "insecure" | "allowInsecure":
                        tlsSettings["tlsSettings"]["allowInsecure"] = bool(parse_url[param][0])
                    case "fp":
                        tlsSettings["tlsSettings"]["fingerprint"] = parse_url[param][0]
                    case _:
                        pass
            outbound["settings"].update(settings)
            outbound["streamSettings"].update(hysteriaSettings)
            outbound["streamSettings"].update(tlsSettings) 
            outbound["streamSettings"].update(finalmask) 

        case _:
            print("[W] Неизвестный proxy-protocol") 
    
    # Настройка транспорт-протокола
    ## Возможно потом добавлю параметры именно транспортов
    if parse_url.get("type") != None:
        match parse_url["type"][0]:
            case "tcp" | "raw":
                outbound["streamSettings"]["network"] = parse_url["type"][0]
                
            case "xhttp":
                xhttpSettings: {
                    "xhttpSettings": {
                        "host": "",
                        "path": "/", 
                        "mode": "auto"
                    }
                }
                
                outbound["streamSettings"]["network"] = parse_url["type"][0]
                # Подставнока необязательных параметров
                for setting in parse_url:
                    match setting:
                        case "path":
                            xhttpSettings["xhttpSettings"]["path"] = parse_url["path"][0]
                        case "host":
                            xhttpSettings["xhttpSettings"]["host"] = parse_url["host"][0]
                        case "mode":
                            xhttpSettings["xhttpSettings"]["mode"] = parse_url["mode"][0]
                        case _:
                            pass
                            
                outbound["streamSettings"].update(xhttpSettings)
                
            case "hysteria":
                outbound["streamSettings"]["network"] = parse_url["type"][0]
                
            case "ws":
                wsSettings = { 
                    "wsSettings": {
                        "path": "/",
                        "host": "",
                        "headers": {}
                    }
                }
                
                outbound["streamSettings"]["network"] = parse_url["type"][0]
                # Подставнока необязательных параметров
                for setting in parse_url:
                    match setting:
                        case "path":
                            wsSettings["wsSettings"]["path"] = parse_url["path"][0]
                        case "host":
                            wsSettings["wsSettings"]["host"] = parse_url["host"][0]
                        case "ed":
                            wsSettings["wsSettings"]['ed'] = wsSettings["wsSettings"]["path"] + f"?ed={parse_url['ed'][0]}"
                        case "headers":
                            headers = parse_url["headers"][0].split(",")
                            for header in headers:
                                header = header.split("|")
                                for i in header:
                                    if i == "":
                                        header[header.index(i)] = " " + header[header.index(i)+1]
                                wsSettings["wsSettings"]["headers"].update({header[0]: header[1]})
                        case _:
                            pass
                            
                outbound["streamSettings"].update(wsSettings)
                
            case "grpc":
                grpcSettings = { 
                    "grpcSettings": {
                        "authority": "",
                        "serviceName": "",
                        "multiMode": false
                    }
                }
                
                outbound["streamSettings"]["network"] = parse_url["type"][0]
                # Подставнока необязательных параметров
                for setting in parse_url:
                    match setting:
                        case "path":
                            grpcSettings["grpcSettings"]["authority"] = parse_url["authority"][0]
                        case "host":
                            grpcSettings["grpcSettings"]["multiMode"] = True
                        case _:
                            pass
                            
                outbound["streamSettings"].update(grpcSettings)
                
            case "httpupgrade":
                httpupgradeSettings = { 
                    "httpupgradeSettings": {
                        "host": "",
                        "path": "/",
                        "headers": {}
                    }
                }
                
                outbound["streamSettings"]["network"] = parse_url["type"][0]
                # Подставнока необязательных параметров
                for setting in parse_url:
                    match setting:
                        case "path":
                            httpupgradeSettings["httpupgradeSettings"]["host"] = parse_url["host"][0]
                        case "host":
                            httpupgradeSettings["httpupgradeSettings"]["path"] = parse_url["path"][0]
                        case "ed":
                            httpupgradeSettings["httpupgradeSettings"]['ed'] = httpupgradeSettings["httpupgradeSettings"]["path"] + f"?ed={parse_url['ed'][0]}"
                        case "headers":
                            headers = parse_url["headers"][0].split(",")
                            for header in headers:
                                header = header.split("|")
                                for i in header:
                                    if i == "":
                                        header[header.index(i)] = " " + header[header.index(i)+1]
                                httpupgradeSettings["httpupgradeSettings"]["headers"].update({header[0]: header[1]})
                        case _:
                            pass
                            
                outbound["streamSettings"].update(httpupgradeSettings)
                
            case _:
                print("[W] Неизвестный transport-protocol") 
        
    else:
        print("[W] Отсутствует transport-protocol") 
    
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
                if parse_url.get("sni") != None and parse_url.get("sni"):
                    tlsSettings["tlsSettings"]["serverName"] = parse_url["sni"][0]
                else:
                    tlsSettings["tlsSettings"]["serverName"] = url_split.hostname
                
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
                
                if parse_url.get("sni") != None and parse_url.get("sni"):
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
                print("[W] Неизвестный security-protocol") 
                
    else:
        print("[W] Отсутствует security-protocol") 
        
    # Настройка mux-протокола
    if parse_url.get("packetEncoding") != None:
        match parse_url["packetEncoding"][0]:
            case "xudp":
                mux = { 
                    "enabled": true,
                    "concurrency": 8,
                    "xudpConcurrency": 16
                }
                
                outbound["mux"].update(mux)
                
            case "packetaddr":
                mux = { 
                    "enabled": true,
                    "concurrency": 8
                }
                
                outbound["mux"].update(mux)
                
            case _:
                print("[W] Unknow mux-protocol")
        
    # Подстановка тега
    if url_split.fragment:
        tag = f"{tag}_{unquote(url_split.fragment)}"
    else:
        tag = f"{url_split.hostname}-{outbound['protocol']}-{outbound['streamSettings']['network']}-{outbound['streamSettings']['security']}"
    
    if addTag:
        tag = f"{addTag}_{tag}"
        
    outbound["tag"] = tag
        
    return outbound

def create_json_config(outbounds: dict[list], path: str = "./", file_name: str = "outbounds_proxy.json") -> None:
    """
    Создаёт файл по указанному пути с указанным именем файла.
    """
    outbounds_json = dumps(outbounds, indent=2, ensure_ascii = False)
    with open(f"{path}/{file_name}", "w", encoding="utf-8") as config:
        config.write(outbounds_json)
        
def read_config(file_path: str) -> list[tuple[str, str]]:
    """
    Читает ссылки из файла.
    Ожидаемый формат строки: 'URL' или 'TAG URL'.
    Если первое слово не содержит '://', оно считается тегом, а остаток строки после пробела - ссылкой.
    Если содержит '://', вся строка считается ссылкой.
    Есть поддержка закоментированных строк с помощью #
    Возвращает список кортежей (url, tag).
    """
    links = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line == "" or line.startswith("#"):
                    continue
                    
                parts = line.split(" ", 1)
                
                # Вся строка — это ссылка, тега нет
                if "://" in parts[0]:
                    links.append((line, ""))
                # Первое слово — тег, остальное — ссылка (если есть)
                elif len(parts) == 2:
                    links.append((parts[1], parts[0])) # (URL, TAG)
                else:
                    #- Возможно стоит добавить проверку на корректность данных 
                    links.append((parts[0], ""))       # (URL, пусто)
                    
    except FileNotFoundError:
        print(f"[E] Файл не найден: {file_path}")
        
    return links 
        
def args_parser() -> list:
    """
    Обрабатывает аргументы передаваемые в консоли
    """
    argparser = ArgumentParser(
        prog=app_name,
        description = "Парсер подписок для Xray. Сбор доступных ссылок конфигов и конвертация их в JSON конфиги."
    )
    argparser.add_argument(
        "--url", 
        action="append",
        help="Ссылка на подписку или конфигурацию (https, vless). Можно указать несколько раз."
    )
    argparser.add_argument(
        "-t", "--tag", 
        help="Глобальный тег конфигурации. Будет добавляться к имени конфигурации и станет именем файла (TAG.json). Приоритет тегов: глобальный-тег_тег-файла_URL-fragment. Для тега конфигурации будет использоваться SERVER-PROTOCOL-TRANSPORT-SECURITY если fragment пуст.",
        default=""
    )
    argparser.add_argument(
        "-c", "--config", 
        action="append",
        help="Файл с ссылками подписок и конфигураций. Каждая ссылка должна быть отдельной строке. Можно указать тег для конфигурации (TAG URL). Можно указать несколько раз."
    )
    argparser.add_argument(
        "-d", "--dir",
        default = "./",
        help="Директория сохранения конфигурации."
    )
    argparser.add_argument(
        "-i", "--index",
        action = "store_true",
        help="Добавить порядковый номер в тег конфигураций (TAG-INDEX)."
    )
    argparser.add_argument(
        "-V", "--version", 
        action="version",
        version=f"{app_name}/{app_version}",
        help="Версия программы."
    )
    args = argparser.parse_args()
    
    return args
    
def add_index_tag(outbounds: dict[list]) -> dict[list]:
    index = 1
    for outbound in outbounds["outbounds"]:
        outbound["tag"] += f"-{index}"
        index += 1
        
    return outbounds

def main() -> None:
    """
    Принимает вводные данные и вызывает необходимые функции.
    """
    # Собираем аргументы комманды
    args = args_parser()
    links = []
    
    # Гарантируем существование директории
    os.makedirs(args.dir, exist_ok=True)
    
    outbounds = {"outbounds": []}
    base_filename = args.tag if args.tag else "outbounds_proxy"

    # Обработка файла
    if args.config:
        for config in args.config:
            print(f"[I] Чтение конфига: {config}")
            config_links = read_config(config)
            for url, line_tag in config_links:
                # Приоритет тегов: тег из строки файла -> глобальный тег -t -> парсинг из URL
                tag_to_use = line_tag if line_tag else ""
                links.append((url, tag_to_use))
        
    # Подгонка простых url под общий формат
    if args.url:
        for url in args.url:
            links.append((url, ""))
          
    if not links:
        print("[E] Необходимо указать ссылку --url или файл конфигурации -c. Справка: -h")
        return 
     
    # Обработка ссылок или подписок
    for link in links:
        if link[0].startswith("https://"):
            config_urls = parse_subscribtion(link[0])
            for config_url in config_urls:
                if config_url.strip(): 
                    outbound = url2json(unquote(config_url), link[1], args.tag) 
                    outbounds["outbounds"].append(outbound)
        else:
            outbound = url2json(unquote(link[0]), link[1], args.tag) 
            outbounds["outbounds"].append(outbound)
        
    # Завершающие операции
    if not outbounds["outbounds"]:
        print("[E] Конфигурации не найдены. Файл не создан.")
        return

    if args.index: 
        add_index_tag(outbounds)
        
    create_json_config(outbounds, file_name=f"{base_filename}.json", path=args.dir)

if __name__ == "__main__":
    main()