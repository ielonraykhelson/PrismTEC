# explain everything
# credits

from prismtec.utils.enrichment.process_iocs import load_iocs, process_iocs
from prismtec.utils.report.generation import generate_report

if __name__ == '__main__':
    IOCS_PATH = 'TARGET.json'
    REPORT_PATH = '\\test\\test1'
    
    iocs = load_iocs(file_path=IOCS_PATH)
    generate_report(
        data=process_iocs(data=iocs),
        file_path=REPORT_PATH,
        extension='.json'
    )
