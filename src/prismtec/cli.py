import argparse
import json
import logging
from pathlib import Path

from prismtec.utils.enrichment.enrich import (
    enrich_ip,
    enrich_hash,
    enrich_domain
)
from prismtec.utils.general.path import validate_path
from prismtec.utils.enrichment.process_iocs import (
    load_iocs, 
    process_iocs
)
from prismtec.utils.report.generation import generate_report

# globals
DEFAULT_SERVICES = [
    'virustotal',
    'abuseipdb',
    'ipinfo'
]
HASH_SERVICES = [
    'virustotal'
]
DOMAIN_SERVICES = [
    'virustotal'
]

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='prismtec',
        description='PrismTEC: IOC Threat Enrichment and Correlation Engine'
    )
    
    subparsers = parser.add_subparsers(
        dest='command',
        required=True
    )
    
    enrich_parser = subparsers.add_parser(
        'enrich',
        help='Enrich IP addresses, domains, and file hashes.'
    )
    
    # ip
    enrich_parser.add_argument(
        '-ip', '--ip',
        nargs='+',
        metavar='IP',
        help='One or more IP addresses to enrich, separated by spaces.'
    )
    
    # domain
    enrich_parser.add_argument(
        '-domain', '--domain',
        nargs='+',
        metavar='DOMAIN',
        help='One or more domains to enrich, separated by spaces.'
    )
    
    # hash
    enrich_parser.add_argument(
        '-hash', '--hash',
        nargs='+',
        metavar='HASH',
        help='One or more hashes to enrich, separated by spaces.'
    )
    
    # optional input
    enrich_parser.add_argument(
        '-i', '--input',
        type=Path,
        metavar='FILE',
        help='[OPTIONAL] Path to a JSON-formatted input file.'
    )
    
    # optional output
    enrich_parser.add_argument(
        '-o', '--output',
        type=Path,
        metavar='FILE',
        help='[OPTIONAL] Path to save the JSON-formatted report.'
    )
    
    # threat intelligence services
    enrich_parser.add_argument(
        '-s', '--services',
        nargs='+',
        choices=DEFAULT_SERVICES,
        default=None,
        help='[OPTIONAL] Threat intelligence services to query.'
    )
    
    # verbosity
    enrich_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='[OPTIONAL] Enable verbose logging.'
    )
    
    return parser

def merge_report(report: dict, target_report: dict) -> None:
    # merge enrichment results into the category-based report
    for category, results in target_report.items():
        report.setdefault(category, [])
        if isinstance(results, list):
            report[category].extend(results)
        else:
            report[category].append(results)

# ---

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format='%(levelname)s: %(message)s'
    )
    
    if args.command != 'enrich':
        parser.error(f'Unknown command `{args.command}`.')
    
    if not any((args.ip, args.hash, args.domain, args.input)):
        parser.error(
            'Provide at least one of -ip, -domain, -hash, or --input.'
        )
    
    # structured to match process_iocs() output
    report = {
        'IP': [],
        'HASH': [],
        'DOMAIN': []
    }
    
    if args.input:
        input_path = args.input.expanduser().resolve()
        
        if not validate_path(path=input_path, path_type='file'):
            parser.error(f'Input file could not be located at `{input_path}`')
        else:
            logging.debug(f'Loading IOCs from {input_path}...')
            
            try:
                iocs = load_iocs(file_path=input_path)
            except (ValueError, OSError) as exception:
                parser.error(f'[!] Could not load input file at `{input_path}`: {exception}')
                
            if not iocs:
                parser.error(
                    'No IOCs successfully loaded.'
                )
                
            input_report = process_iocs(data=iocs)
            merge_report(report=report, target_report=input_report)
            
    # manual enrichment of supplied iocs
    if args.ip:
        for ip in args.ip:
            logging.debug(f'Enriching IP: {ip}')
            result = enrich_ip(
                ip_address=ip,
                services=args.services or DEFAULT_SERVICES
            )
            report['IP'].append(result)
            
    if args.hash:
        for file_hash in args.hash:
            logging.debug(f'Enriching hash: {file_hash}')
            result = enrich_hash(
                hash=file_hash,
                services=HASH_SERVICES
            )
            report['HASH'].append(result)
            
    if args.domain:
        for domain in args.domain:
            logging.debug(f'Enriching domain: {domain}')
            result = enrich_domain(
                domain=domain,
                services=DOMAIN_SERVICES
            )
            report['DOMAIN'].append(result)
    
    total_indicators = 0
    for indicators in report.values():
        if isinstance(indicators, list):
            total_indicators += len(indicators)
    logging.info(f'Processed {total_indicators} total indicators.')
    
    # generate output
    if args.output:
        output_path = args.output.expanduser()

        extension = output_path.suffix or '.json'
        base_path = output_path.with_suffix('') if output_path.suffix else output_path

        # use the reports directory only for a filename
        use_reports_path = len(output_path.parts) == 1 and not output_path.is_absolute()

        if not use_reports_path:
            base_path = base_path.resolve()

        generated_path = generate_report(
            data=report,
            file_path=str(base_path),
            extension=extension,
            use_reports_path=use_reports_path
        )
        logging.info(f'Report generated at `{generated_path}`')
    else:
        print(
            json.dumps(
                report, indent=4, ensure_ascii=False
            )
        )
        
if __name__ == '__main__':
    main()