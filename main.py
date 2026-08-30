import json
import sys
from pathlib import Path

# Import Block 3 evaluator
from compliance_engine.evaluator import load_rule_pack, evaluate_report

# Import Block 4 PDF generator
from report_gen.report_gen import generate_pdf_file

def run_compliance_pipeline(converter_json_path: str, output_pdf_path: str = "compliance_report.pdf"):
    print(f"1. Loading converter JSON: {converter_json_path}")
    json_path = Path(converter_json_path)
    if not json_path.exists():
        print(f"Error: File '{converter_json_path}' does not exist.", file=sys.stderr)
        return

    with json_path.open(encoding="utf-8") as f:
        converter_data = json.load(f)

    print("2. Loading CIS Rule Pack...")
    rules, framework = load_rule_pack()

    print("3. Executing Block 3 Compliance Evaluation...")
    eval_result = evaluate_report(converter_data, rules)

    print("4. Executing Block 4 PDF Generation...")
    generate_pdf_file(eval_result, output_filename=output_pdf_path, framework=framework)

    print(f"🎉 Success! Final PDF compiled and saved to: {output_pdf_path}")

if __name__ == "__main__":
    sample_fixture = Path(__file__).parent / "compliance_engine" / "fixtures" / "cisco_type5.json"
    run_compliance_pipeline(str(sample_fixture))