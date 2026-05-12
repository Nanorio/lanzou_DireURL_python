#!/usr/bin/env python3
from curl_cffi import requests
import re
import json
import sys
import html

def solve_aliyun_waf(arg1):
    """纯 Python 逆向 WAF 算法"""
    m = [15, 35, 29, 24, 33, 16, 1, 38, 10, 9, 19, 31, 40, 27, 22, 23, 25, 13, 6, 11, 39, 18, 20, 8, 14, 21, 32, 26, 2, 30, 7, 4, 17, 5, 3, 28, 34, 37, 12, 36]
    q = [''] * 40
    for i in range(min(len(arg1), 40)):
        for j in range(len(m)):
            if m[j] == i + 1:
                q[j] = arg1[i]
    u = "".join(q)
    p = "3000176000856006061501533003690027800375"
    v = ""
    for i in range(0, min(len(u), len(p)), 2):
        xor_val = int(u[i:i+2], 16) ^ int(p[i:i+2], 16)
        hex_val = hex(xor_val)[2:]
        if len(hex_val) == 1: hex_val = '0' + hex_val
        v += hex_val
    return v

def get_lanzou_direct_link(url, password=""):
    """
    全能解析逻辑：支持双模切换 + 防误杀蜜罐机制
    """
    domain_match = re.search(r"https?://([^/]+)", url)
    if not domain_match: 
        return False, "链接格式错误", ""
    domain = domain_match.group(1)
    
    session = requests.Session(impersonate="chrome110")
    my_cookies = {}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept-Language": "zh-CN,zh;q=0.9",
    }

    # 1. 获取主页面
    try:
        resp1 = session.get(url, headers=headers, timeout=10)
    except Exception as e:
        return False, f"网络请求失败: {e}", ""

    # 2. WAF 破解
    arg1_match = re.search(r"var\s+arg1\s*=\s*'([A-F0-9]+)'", resp1.text)
    if arg1_match:
        acw_cookie = solve_aliyun_waf(arg1_match.group(1))
        my_cookies["acw_sc__v2"] = acw_cookie
        resp1 = session.get(url, headers=headers, cookies=my_cookies, timeout=10)

    html_text = resp1.text

    # 3. 拦截失效页面
    if 'class="off"' in html_text or "文件取消" in html_text or "不存在" in html_text:
        return False, "违规文件或文件不存在!", ""

    # 4. 提取文件名
    file_name = "未知文件名"
    title_match = re.search(r"<title>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
    if title_match:
        raw_title = title_match.group(1).strip()
        file_name = re.sub(r'\s*-\s*(蓝奏云|Lanzou).*$', '', raw_title, flags=re.IGNORECASE).strip()
        file_name = html.unescape(file_name)

    # 5. 全图扫描 API
    target_html = html_text
    referer_url = url
    
    ajax_urls = re.findall(r"url\s*:\s*['\"](/?ajaxm\.php[^'\"]+)['\"]", target_html)
    # 【核心修正】：使用 endswith 替代 in，防止误杀以 1 开头的真实 ID
    valid_urls = [link for link in ajax_urls if not link.endswith('file=1')]
    ajax_url = valid_urls[-1] if valid_urls else None

    # 6. 若主页无 API，下潜 iframe
    if not ajax_url:
        iframe_pattern = re.compile(r'<iframe.*?src="([^"]+)".*?></iframe>')
        matches = iframe_pattern.findall(html_text)
        if matches:
            iframe_src = next((m for m in matches if '/fn?' in m or '/includes/' in m), matches[0])
            try:
                resp2 = session.get(f"https://{domain}{iframe_src}", headers=headers, cookies=my_cookies, timeout=10)
                target_html = resp2.text
                referer_url = f"https://{domain}{iframe_src}"
                # 同样在子页面应用新的防误杀逻辑
                ajax_urls = re.findall(r"url\s*:\s*['\"](/?ajaxm\.php[^'\"]+)['\"]", target_html)
                valid_urls = [link for link in ajax_urls if not link.endswith('file=1')]
                ajax_url = valid_urls[-1] if valid_urls else None
            except Exception as e:
                return False, f"潜入子页面失败: {e}", ""

    if not ajax_url:
        return False, "提取 API 地址失败（可能是文件夹或风控拦截）", ""
        
    if not ajax_url.startswith('/'):
        ajax_url = '/' + ajax_url

    # 7. 提取 sign (过滤短字符蜜罐)
    sign_val = ""
    literal_sign_matches = re.findall(r"'sign'\s*:\s*['\"]([^'\"]+)['\"]", target_html)
    valid_signs = [s for s in literal_sign_matches if len(s) > 20]
    
    if valid_signs:
        sign_val = valid_signs[-1]
    else:
        var_match = re.search(r"'sign'\s*:\s*([a-zA-Z0-9_]+)", target_html)
        if var_match:
            sign_var = var_match.group(1)
            val_match = re.search(r"var\s+" + sign_var + r"\s*=\s*'([^']+)'", target_html)
            if val_match:
                sign_val = val_match.group(1)

    # 8. 组装 POST
    data = {
        'action': 'downprocess',
        'sign': sign_val,
        'p': password,
        'kd': 1,
        'ves': 1
    }
    
    post_headers = {
        'Origin': f"https://{domain}",
        'Referer': referer_url,
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.9'
    }
    
    # 9. 获取直链
    try:
        resp3 = session.post(f"https://{domain}{ajax_url}", headers=post_headers, data=data, cookies=my_cookies, timeout=10)
        res_json = json.loads(resp3.text.strip())
    except Exception as e:
         return False, f"解析失败！\n现场源码:\n{resp3.text[:300]}", ""

    if res_json.get('zt') != 1:
        return False, res_json.get('inf', '解析被拒绝'), ""

    if str(res_json.get('inf', '')) != '0':
        file_name = html.unescape(res_json.get('inf'))

    full_url = res_json['dom'] + "/file/" + res_json['url']
    my_cookies['down_ip'] = '1'
    
    try:
        resp4 = session.get(full_url, headers=headers, cookies=my_cookies, allow_redirects=False, timeout=10)
        final_url = resp4.headers.get('Location', full_url)
    except Exception as e:
        return False, f"跳转失败: {e}", ""
    
    return True, file_name, final_url

def main():
    if len(sys.argv) < 2:
        print("用法: python lanzou.py [链接] [密码(可选)]")
        sys.exit(1)

    share_url = sys.argv[1].strip()
    password = sys.argv[2].strip() if len(sys.argv) > 2 else ""

    print(f"[*] 解析链接: {share_url}")
    success, name, direct_url = get_lanzou_direct_link(share_url, password)
    
    if success:
        print(f"✅ 成功！\n📦 文件: {name}\n🔗 直链：\n{direct_url}")
    else:
        print(f"❌ 失败: {name}")

if __name__ == "__main__":
    main()
