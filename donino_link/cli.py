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
        panel=None;monitor=None;store=None
        try:
            if 'panel' in config:
                from .foreign import ForeignMonitor
                store=Store(config['state_db']);monitor=ForeignMonitor(config,store)
                panel=Panel(monitor);await monitor.start();await panel.start()
                print('Donino foreign panel ready: '+config['panel']['listen'],flush=True)
            await done.wait()
        finally:
            if panel:await panel.stop()
            if monitor:await monitor.stop()
            if store:store.close()
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
        if not addresses:return [{'path':'unconfigured','ok':False,'error':'no tunnels installed yet'}]
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
    p.add_argument('--transport',action='append',choices=['frp-wss','frp-quic','backpack-wss','paqet','backhaul-wss','browser-wss','donino-mux','donino-continuum'])
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
    p=sub.add_parser('control-enable',help='enable the local two-node installation controller (root on Iran)')
    p.add_argument('--allow-private-peers',action='store_true',help='operator opt-in for a private VPC/LAN SSH peer')
    sub.add_parser('control-run',help='internal root installation worker')
    sub.add_parser('foreign-agent-run',help='internal foreign pairing and service agent')
    p=sub.add_parser('init-node',help='install an independent Iran or foreign panel on this server')
    p.add_argument('--role',required=True,choices=['iran','foreign'])
    p.add_argument('--address',required=True)
    p.add_argument('--panel-port',type=int)
    p.add_argument('--agent-port',type=int,default=9444)
    p.add_argument('--password-file')
    p.add_argument('--no-open-ufw',action='store_true')
    p.add_argument('--allow-private-peers',action='store_true')
    p.add_argument('--upgrade',action='store_true')
    p=sub.add_parser('panel-access',help='configure the real admin panel listener')
    p.add_argument('--config',required=True)
    p.add_argument('--listen',required=True)
    p.add_argument('--http',action='store_true')
    p.add_argument('--cert')
    p.add_argument('--key')
    p.add_argument('--public-host')
    args=parser.parse_args()
    try:
        if args.command=='init-node':
            from .bootstrap import install
            from .provision import LIVE
            existing=load_config(LIVE) if LIVE.exists() else None
            password=None
            if not existing or 'panel' not in existing:
                password=Path(args.password_file).read_text().rstrip('\r\n') if args.password_file else getpass.getpass('Panel password (12+ characters): ')
                if not args.password_file and password!=getpass.getpass('Confirm panel password: '):raise ValueError('passwords do not match')
            print(json.dumps(install(args.role,args.address,password,args.panel_port,args.agent_port,not args.no_open_ufw,args.allow_private_peers,args.upgrade),indent=2))
        elif args.command=='foreign-agent-run':
            from .peer import serve_agent
            asyncio.run(serve_agent())
        elif args.command=='control-enable':
            from .provision import enable_control
            enable_control(args.allow_private_peers)
        elif args.command=='control-run':
            from .provision import serve_control
            asyncio.run(serve_control())
        elif args.command=='plan':
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
        elif args.command=='panel-access':
            from .panel_access import configure_panel
            result=configure_panel(args.config,args.listen,args.http,args.cert,args.key,args.public_host)
            print(json.dumps(result,indent=2))
            if result['http']:
                print('HTTP does not encrypt admin passwords or sessions in transit. Authentication and CSRF remain enabled.')
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
