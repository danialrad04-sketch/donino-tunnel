import argparse
import asyncio
import getpass
import json
import signal
import sys
from pathlib import Path
from .config import load_config,endpoint
from .health import start_responder,probe
from .gateway import Gateway
from .panel import Panel
from .store import Store


async def serve(config):
    done=asyncio.Event()
    loop=asyncio.get_running_loop()
    for sig in (signal.SIGTERM,signal.SIGINT):
        loop.add_signal_handler(sig,done.set)
    if config['role']=='foreign':
        server=await start_responder(config['health_listen'],config['health_key'],config.get('targets'))
        try:
            await done.wait()
        finally:
            server.close()
            await server.wait_closed()
        return
    store=Store(config['state_db'])
    gateway=Gateway(config,store)
    panel=Panel(gateway)
    try:
        await gateway.start()
        await panel.start()
        print('Donino Link ready; panel: '+config['panel']['listen'],flush=True)
        await done.wait()
    finally:
        await panel.stop()
        await gateway.stop()
        store.close()


async def doctor(config):
    if config['role']=='foreign':
        addresses=[('foreign-responder',config['health_listen'])]
    else:
        addresses=[(p['id'],p['health']) for p in config['paths']]
    rows=[]
    for name,address in addresses:
        try:
            ms,stats=await probe(address,config['health_key'],5)
            rows.append({'path':name,'ok':True,'latency_ms':round(ms,2),'services':stats.get('services',{})})
        except (OSError,ValueError,KeyError,TypeError,asyncio.TimeoutError) as e:
            rows.append({'path':name,'ok':False,'error':type(e).__name__})
    return rows


def main():
    parser=argparse.ArgumentParser(description='Donino Link: measured two-node tunnel management')
    sub=parser.add_subparsers(dest='command',required=True)
    for name in ['run','doctor','validate']:
        p=sub.add_parser(name)
        p.add_argument('--config',required=True)
    p=sub.add_parser('plan')
    p.add_argument('--iran',required=True)
    p.add_argument('--foreign',required=True)
    p.add_argument('--service',action='append',required=True,help='id=listen,target, e.g. vpn=0.0.0.0:443,127.0.0.1:443')
    p.add_argument('--transport',action='append',choices=['frp-wss','frp-quic','backpack-wss','paqet','backhaul-wss','browser-wss'])
    p.add_argument('--experimental',action='store_true')
    p.add_argument('--output',required=True)
    p.add_argument('--password-file',help='read private password file; otherwise ask interactively')
    p.add_argument('--base-port',type=int,default=30000)
    p.add_argument('--carrier-base',type=int,default=24443)
    p.add_argument('--health-port',type=int,default=19090)
    p.add_argument('--paqet-port',type=int,default=33434)
    p.add_argument('--browser-port',type=int,help='foreign HTTPS carrier port; e.g. 443 on an owned domain')
    p=sub.add_parser('deploy')
    p.add_argument('--plan',required=True)
    p.add_argument('--iran-host',required=True)
    p.add_argument('--foreign-host',required=True)
    p.add_argument('--identity')
    p.add_argument('--dry-run',action='store_true')
    p=sub.add_parser('fetch-engines')
    p.add_argument('--engine',action='append',choices=['frp','paqet','backpack','backhaul'],required=True)
    p.add_argument('--destination',required=True)
    p.add_argument('--cache')
    p=sub.add_parser('prepare-paqet')
    p.add_argument('--node',required=True)
    p=sub.add_parser('renew')
    p.add_argument('--plan',required=True)
    args=parser.parse_args()
    try:
        if args.command=='plan':
            from .plan import make_plan
            services=[]
            for value in args.service:
                name,rest=value.split('=',1)
                listen,target=rest.split(',',1)
                endpoint(listen);endpoint(target)
                services.append({'id':name,'listen':listen,'target':target})
            password=Path(args.password_file).read_text().rstrip('\r\n') if args.password_file else getpass.getpass('Admin password (12+ characters): ')
            summary=make_plan(args.output,args.iran,args.foreign,services,args.transport or ['frp-wss','frp-quic'],password,args.experimental,args.base_port,args.carrier_base,args.health_port,args.paqet_port,args.browser_port)
            print(json.dumps(summary,indent=2))
            print('Private plan created. Keep the entire plan directory out of git; certificates expire in 90 days.')
        elif args.command=='deploy':
            from .deploy import deploy
            print(json.dumps(deploy(args.plan,args.iran_host,args.foreign_host,args.identity,args.dry_run),indent=2))
        elif args.command=='fetch-engines':
            from .artifacts import install_engines
            install_engines(args.engine,args.destination,args.cache)
            print('Verified pinned engine binaries installed.')
        elif args.command=='prepare-paqet':
            from .network import prepare_paqet
            prepare_paqet(args.node)
        elif args.command=='renew':
            from .plan import renew_plan
            renew_plan(args.plan)
            print('Leaf certificates renewed with the existing private CA. Redeploy the same plan to both nodes.')
        else:
            config=load_config(args.config)
            if args.command=='validate':
                print('Configuration valid.')
            elif args.command=='doctor':
                rows=asyncio.run(doctor(config))
                print(json.dumps(rows,indent=2))
                if not all(r['ok'] for r in rows):
                    return 1
            else:
                asyncio.run(serve(config))
    except (ValueError,OSError,KeyError) as e:
        print(f'Error: {e}',file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    sys.exit(main())
