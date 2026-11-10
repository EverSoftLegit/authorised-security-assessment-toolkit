import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_script(script, *args):
    return subprocess.run([sys.executable, str(ROOT / "scripts" / script), *map(str, args)],
                          capture_output=True, text=True, check=False)


def test_nmap_parser_reads_sample_xml(tmp_path):
    output = tmp_path / "nmap.json"
    result = run_script("05_nmap_xml_analyzer.py", ROOT / "sample_data" / "nmap-sample.xml",
                        "--output", output)
    assert result.returncode == 0, result.stderr
    data = json.loads(output.read_text())
    assert data["tool"] == "nmap-xml-analyser"
    assert any("445" in item["title"] for item in data["findings"])


def test_zap_parser_reads_sample_json(tmp_path):
    output = tmp_path / "zap.json"
    result = run_script("06_zap_json_analyzer.py", ROOT / "sample_data" / "zap-sample.json",
                        "--output", output)
    assert result.returncode == 0, result.stderr
    data = json.loads(output.read_text())
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "LOW"


def test_report_builder_combines_offline_results(tmp_path):
    nmap = tmp_path / "nmap.json"
    zap = tmp_path / "zap.json"
    report = tmp_path / "report.md"
    assert run_script("05_nmap_xml_analyzer.py", ROOT / "sample_data" / "nmap-sample.xml",
                      "--output", nmap).returncode == 0
    assert run_script("06_zap_json_analyzer.py", ROOT / "sample_data" / "zap-sample.json",
                      "--output", zap).returncode == 0
    result = run_script("07_report_builder.py", nmap, zap, "--client", "Demo Lab",
                        "--output", report)
    assert result.returncode == 0, result.stderr
    text = report.read_text()
    assert "Executive summary" in text
    assert "Analyst review checklist" in text
    assert "Demo Lab" in text
