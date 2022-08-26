from utils import *


if __name__ == "__main__":
    local_ip = get_local_ip()
    print(local_ip)
    local_gdpname = generate_gdpname(local_ip)

    register_proxy(local_ip, "128.32.37.42", local_gdpname)

    