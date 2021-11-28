import nmap


def scan_ip(ip, args):
    nmy = nmap.PortScannerYield()
    result = ""
    # print("scanning in progress...\n")
    for progressive_result in nmy.scan(hosts=ip + '/24', arguments=args):
        if int(progressive_result[1]["nmap"]["scanstats"]["uphosts"]):
            result += progressive_result[0]
    return result


def scan_port(target, start, end):
    nm = nmap.PortScanner()
    result = ""
    for i in range(start, end + 1):
        res = nm.scan(target, str(i))
        res = res['scan'][target]['tcp'][i]['state']
        result += f'\nport {i} is {res}.\np'
    return result


if __name__ == '__main__':
    iprange = "89.43.3.0"
    iprange2 = "89.43.4.0"
    start = 0
    end = 300
    args = "-sn"
    result_ipscan = scan_ip(iprange, args)
    result_portscan = ""
    for ip in result_ipscan:
        result_portscan += scan_port(ip, start, end)

    f = open("result_hostservicefinder.txt", "w")
    f.write(result_portscan)
    f.close()