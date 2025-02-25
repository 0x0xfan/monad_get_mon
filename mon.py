from eth_utils import to_checksum_address
import requests
import time
import random
from tools.log_settings.log import logger
import uuid
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

proxys = "你的代理信息"

proxy = {
    "http": f"http://{proxys}",
    "https": f"http://{proxys}"
}

def generate_ga_value():
    # 生成 GA 版本信息，通常是 GA1.1
    version = "GA1.1"
    # 生成首次访问时间戳，这里使用当前时间戳模拟
    first_visit_timestamp = int(time.time())
    # 生成当前会话时间戳，这里也使用当前时间戳模拟
    current_session_timestamp = int(time.time())
    return f"{version}.{first_visit_timestamp}.{current_session_timestamp}"

def generate_ga_BLC6FNVWFY_value():
    # 生成 GA 版本信息，通常是 GS1.1
    version = "GS1.1"
    # 生成随机数，用于模拟其他唯一标识信息
    random_numbers = [str(random.randint(0, 9)) for _ in range(10)]
    random_str = ".".join(random_numbers)
    return f"{version}.{random_str}"

def generate_visitor_id():
    # 生成一个随机的 UUID 并转换为十六进制字符串
    visitor_id = uuid.uuid4().hex
    return visitor_id

# 调用函数生成 visitorId
new_visitor_id = generate_visitor_id()

def create_session():
    session = requests.Session()
    
    # 配置重试策略
    retry_strategy = Retry(
        total=3,  # 最大重试次数
        backoff_factor=1,  # 重试间隔
        status_forcelist=[500, 502, 503, 504]  # 需要重试的HTTP状态码
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

def make_request(address=None, token=None, visitorId=None):
    try:
        checksum_address = to_checksum_address(address)

        url = f'https://testnet.monad.xyz/api/claim'

        # 生成 _ga 和 _ga_BLC6FNVWFY 值
        ga_value = generate_ga_value()
        ga_BLC6FNVWFY_value = generate_ga_BLC6FNVWFY_value()

        # 构建 Cookie 字符串
        new_cookie_dict = {
        '_ga_BLC6FNVWFY': ga_value,
        '_ga': ga_BLC6FNVWFY_value,
        'monad-cookie-consent': '%7B%22analytics%22%3Atrue%2C%22necessary%22%3Atrue%7D',
        '__Host-next-auth.csrf-token': token,
        '__Secure-next-auth.callback-url': 'https%3A%2F%2Ftestnet.monad.xyz',
        'wagmi.recentConnectorId': '"io.metamask"',
        'wagmi.store': '{"state":{"connections":{"__type":"Map","value":[["02a83075a9e",{"accounts":["'+address+'"],"chainId":10143,"connector":{"id":"io.metamask","name":"MetaMask","type":"injected","uid":"02a83075a9e"}}]]},"chainId":10143,"current":"02a83075a9e"},"version":2}'
    }

        # 构造 Cookie 字符串
        new_cookie_str = "; ".join([f"{key}={value}" for key, value in new_cookie_dict.items()])

        headers = {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-length": "2335",
        "content-type": "application/json",
        "cookie": new_cookie_str,
        "origin": "https://testnet.monad.xyz",
        "priority": "u=1, i",
        "referer": "https://testnet.monad.xyz/",
        "sec-ch-ua": "\"Not(A:Brand\";v=\"99\", \"Google Chrome\";v=\"133\", \"Chromium\";v=\"133\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
    }
        data = {
            "address": checksum_address,
            "visitorId": visitorId,
            "recaptchaToken": token
        }


        req_ip = requests.get("https://ipinfo.io/", proxies=proxy).json()
        ip = f"当前ip: {req_ip['ip']} \t  当前地区: {req_ip['region']}"
        logger.info(ip)


        logger.info("开始领水")
        response = requests.post(url, headers=headers, json=data, proxies=proxy, verify=True)
        response.raise_for_status()  # 添加错误检查
        return response.json()
        
    except Exception as e:
        logger.error(f"领水请求失败: {str(e)}")
        return None

def sign_request(address:str):
    try:
        session = create_session()
        create_task_url = "http://api.nocaptcha.io/api/wanda/recaptcha/universal"
        headers = {
            "User-Token": "填写你的nocaptcha的api秘钥",
            "Content-Type": "application/json"
        }
        body = {
            "sitekey": "6LdOf-EqAAAAAAKJ2QB6IqnJfsOl13El4XZwRD8c",
            "referer": "https://testnet.monad.xyz/",
            "size": "invisible",
            "title": "Monad Testnet: Test, Play and Build on Monad Testnet",
            "action": "drip_request",
            "proxy": proxys
        }

        # 首次请求验证码
        logger.info("开始请求验证码")
        response = session.post(create_task_url, headers=headers, json=body, proxies=proxy, verify=True)
        
        # 添加响应状态码检查
        logger.info(f"验证码请求状态码: {response.status_code}")
        logger.info(f"验证码原始响应: {response.text}")
        
        try:
            token_response = response.json()
            logger.info(f"验证码初始响应: {token_response}")
        except json.JSONDecodeError as e:
            logger.error(f"验证码响应解析失败: {str(e)}")
            logger.error(f"原始响应内容: {response.text}")
            return None
            
        token = ""
        
        # 循环检查验证码状态
        for i in range(10):
            # 先判断是否已成功
            if token_response.get("status") == 1:
                logger.info("验证码返回成功")
                token = token_response["data"]["token"]  # 直接访问token
                break
                
            logger.info(f"等待验证返回第{i+1}次")
            time.sleep(3)
            
            # 发送请求并检查响应
            response = session.post(create_task_url, headers=headers, json=body, proxies=proxy, verify=True)
            try:
                token_response = response.json()
                logger.info(f"验证码响应: {token_response}")
                if token_response.get("status") == 1:
                    token = token_response["data"]["token"]  # 直接访问token
            except json.JSONDecodeError as e:
                logger.error(f"验证码响应解析失败: {str(e)}")
                continue
        
        if not token:
            logger.error("未能获取验证码token")
            return
            
        # 发送领水请求
        logger.info("开始发送领水请求")
        response = make_request(address, token, new_visitor_id)
        logger.info(f"领水响应: {response}")
        return response

    except requests.exceptions.RequestException as e:
        logger.error(f"请求发生错误: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"发生未知错误: {str(e)}")
        return None

if __name__ == "__main__":
    with open("领水钱包.txt", "r", encoding="utf-8") as f:
        for line in f:
            try:
                address = line.strip()
                sign_request(address)
            except Exception as e:
                logger.error(f"{address}失败")
                with open(r"失败钱包.txt", "a", encoding="utf-8") as f:
                    f.write(f"{address}\n")
            continue
