import nmap


def print_scan_internet(iprange, portrange):
    nm = nmap.PortScanner()
    result = ""
    nm.scan(iprange, portrange, '-v -sS -sV')
    for ip in nm.all_hosts():
        try:
            for port in nm[ip]['tcp'].keys():
                str = f"Port Open:----> {port} -- {nm[ip]['tcp'][port]['name']} -- {nm[ip]['tcp'][port]['product']} -- {nm[ip]['tcp'][port]['version']}"
                print(str)
                result += str + "\n"
        except:
            pass
    return result


if __name__ == '__main__':
    iprange = "89.43.3.0/24"
    iprange2 = "89.43.4.0/24"
    portrange = "1-300"

    testrange = "89.43.3.170/30"

    result_portscan = print_scan_internet(testrange, portrange)
    f = open("result_hostservicefinder.txt", "w")
    f.write(result_portscan)
    f.close()
