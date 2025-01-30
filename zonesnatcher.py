import dns.resolver
import dns.query
import dns.zone
import argparse
import textwrap
import concurrent.futures


CUSTOM_DNS_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
resolver = dns.resolver.Resolver()
resolver.nameservers = CUSTOM_DNS_SERVERS


def print_banner():
    banner = textwrap.dedent(r"""
         _____                   _____             __       __             
        /__  /  ____  ____  ___ / ___/____  ____ _/ /______/ /_  ___  _____
          / /  / __ \/ __ \/ _ \\__ \/ __ \/ __ `/ __/ ___/ __ \/ _ \/ ___/
         / /__/ /_/ / / / /  __/__/ / / / / /_/ / /_/ /__/ / / /  __/ /    
        /____/\____/_/ /_/\___/____/_/ /_/\__,_/\__/\___/_/ /_/\___/_/     

         Crafted by ello_guvnor                                                                  
    """)
    print(banner)


def read_file(filename):
    try:
        with open(filename, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"File {filename} not found")
    except PermissionError:
        print(f"Permission denied for file {filename}")
    except Exception as error:
        print(error)

    return []


def write_file(filename, data):
    try:
        with open(filename, "w") as file:
            for line in data:
                file.write(line + "\n")
        print(f"Results saved to {filename}")
    except Exception as error:
        print(f"Error writing to {filename}: {error}")


def get_name_servers(domain):
    try:
        name_servers = resolver.resolve(domain, "NS")
        return {ns.to_text() for ns in name_servers}
    except Exception:
        return set()


def resolve_ns_ip(name_server):
    try:
        answer = resolver.resolve(name_server, "A")
        if answer:
            return answer[0].to_text()

        answer = resolver.resolve(name_server, "AAAA", raise_on_no_answer=False)
        if answer:
            return answer[0].to_text()
    except Exception:
        print(f"Could not resolve NS {name_server} to IP")
        return None


def query_zone_transfer(name_server, domain):
    ns_ip = resolve_ns_ip(name_server)
    if not ns_ip:
        return None

    results = []
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))
        for name, node in zone.nodes.items():
            subdomain = f"{name.to_text()}.{domain}"
            results.append(subdomain)

        print(f"[!] Vulnerability detected: Zone transfer successful for {domain} via {name_server} ({ns_ip})")
        for result in results:
            print(result)
    except Exception:
        return None

    return results


def check_domain(domain):
    print(f"[*] Checking {domain} for zone transfer vulnerability...")
    name_servers = get_name_servers(domain)
    all_results = []
    if name_servers:
        for name_server in name_servers:
            results = query_zone_transfer(name_server, domain)
            if results:
                all_results.extend(results)
    
    return all_results


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="DNS Zone Transfer Vulnerability Scanner")
    parser.add_argument("-d", "--domain", help="Target domain to check for zone transfer")
    parser.add_argument("-l", "--list", help="List of target domains to check for zone transfer")
    parser.add_argument("-o", "--output", help="Save results to a file")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    args = parser.parse_args()

    all_results = []

    if args.domain:
        all_results.extend(check_domain(args.domain))

    elif args.list:
        domains = read_file(args.list)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(check_domain, domain): domain for domain in domains}

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    all_results.extend(result)
    else:
        print("No valid options provided. Use -d for a single domain or -l for a list.")

    if args.output and all_results:
        write_file(args.output, all_results)


if __name__ == "__main__":
    main()
