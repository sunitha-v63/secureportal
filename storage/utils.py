import requests
from user_agents import parse

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
        return ip

    x_real_ip = request.META.get("HTTP_X_REAL_IP")
    if x_real_ip:
        return x_real_ip

    return request.META.get("REMOTE_ADDR")


def get_geo_data(ip):

    private_ips = ("127.", "192.168", "172.", "10.", "::1")
    if ip.startswith(private_ips):
        try:
            ip = requests.get("https://api.ipify.org", timeout=3).text
        except:
            return {"country": None, "city": None}

    try:
        url = f"https://ipinfo.io/{ip}/json"
        data = requests.get(url, timeout=3).json()

        return {
            "country": data.get("country"),
            "city": data.get("city")
        }

    except Exception as e:
        return {"country": None, "city": None}


def get_device_info(request):
    ua_string = request.META.get("HTTP_USER_AGENT")
    user_agent = parse(ua_string)
    return {
        "browser": user_agent.browser.family,
        "os": user_agent.os.family,
    }
