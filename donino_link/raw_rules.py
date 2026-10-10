"""Only touch narrowly scoped, tagged rules. Never flush a table or alter SSH."""
import argparse
import ipaddress
import subprocess


def rule_specs(peer, port):
    ipaddress.ip_address(peer)
    if not 1024 <= port <= 65535:
        raise ValueError("Paqet rule needs an IP peer and dedicated high port")
    tag=["-m","comment","--comment","donino-link-paqet"]
    return [
        ("raw","PREROUTING",["-p","tcp","-s",peer,"--dport",str(port),*tag,"-j","NOTRACK"]),
        ("raw","OUTPUT",["-p","tcp","-d",peer,"--sport",str(port),*tag,"-j","NOTRACK"]),
        ("mangle","OUTPUT",["-p","tcp","-d",peer,"--sport",str(port),"--tcp-flags","RST","RST",*tag,"-j","DROP"]),
    ]


def change(action, peer, port):
    applied=[]
    try:
        for table,chain,spec in rule_specs(peer,port):
            prefix=["ip6tables" if ipaddress.ip_address(peer).version==6 else "iptables","-w","5","-t",table]
            exists=subprocess.run(prefix+["-C",chain]+spec,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if exists.returncode not in (0,1):
                raise RuntimeError("cannot inspect iptables rule")
            if action=="apply" and exists.returncode:
                subprocess.run(prefix+["-A",chain]+spec,check=True)
                applied.append((prefix,chain,spec))
            elif action=="remove" and exists.returncode==0:
                subprocess.run(prefix+["-D",chain]+spec,check=True)
    except BaseException:
        if action=="apply":
            for prefix,chain,spec in reversed(applied):
                subprocess.run(prefix+["-D",chain]+spec,check=False)
        raise


def main():
    p=argparse.ArgumentParser()
    p.add_argument("action",choices=["apply","remove"])
    p.add_argument("--peer",required=True)
    p.add_argument("--port",type=int,required=True)
    a=p.parse_args()
    change(a.action,a.peer,a.port)


if __name__=="__main__":
    main()
