import click
import asyncio
from pathlib import Path
from .core import InspectorConfig, validate_token, perform_scan, AuthorizationError
from .report import save_report
from .logger import get_logger
import json

logger = get_logger()

@click.group()
def main():
    pass

@main.command()
@click.argument("target")
@click.option("--auth-token", required=True)
@click.option("--output", default="reports")
@click.option("--ports", default="", help="Comma separated ports to banner grab")
@click.option("--rate", default=10.0, help="Requests per second rate limit")
@click.option("--concurrency", default=5, help="Max concurrent tasks")
@click.option("--timeout", default=5.0, help="Network timeout seconds")
def scan(target, auth_token, output, ports, rate, concurrency, timeout):
    config = InspectorConfig(token_file=Path("authorized_tokens.json"), rate_limit=float(rate), concurrency=int(concurrency), timeout=float(timeout))
    try:
        validate_token(auth_token, config)
    except AuthorizationError as e:
        logger.error("authorization failed %s", str(e))
        raise click.Abort()
    Path(output).mkdir(parents=True, exist_ok=True)
    p_list = [int(x) for x in ports.split(",") if x.strip()] if ports else None
    logger.info("starting scan target=%s", target)
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(perform_scan(target, config, ports=p_list))
    report_path = save_report(result)
    logger.info("report saved %s", report_path)
    click.echo(json.dumps({"status": "ok", "report": str(report_path)}))

@main.command()
@click.option("--auth-token", required=True)
def validate_token_cmd(auth_token):
    config = InspectorConfig(token_file=Path("authorized_tokens.json"))
    try:
        validate_token(auth_token, config)
        click.echo("valid")
    except AuthorizationError:
        click.echo("invalid")
        raise click.Abort()

@main.command()
@click.argument("report_path", type=click.Path(exists=True))
@click.option("--pretty", is_flag=True)
def report(report_path, pretty):
    path = Path(report_path)
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if pretty:
        click.echo(json.dumps(data, indent=2))
    else:
        click.echo(json.dumps(data))
