"""Read-only native inventory, actual agent loop and owned-process crash recovery.

No enrollment, elevation, provider installation, policy changes or live DB access.
The runtime uses only a verified owned scratch spool and missing test identity.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from verify_endpoint_https import owned_scratch


def json_lines(path: Path) -> list[dict]:
    values = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue  # diagnostic line or currently incomplete write
        if isinstance(value, dict):
            values.append(value)
    return values


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    build = root / "panopticon-agent/build-verify-x64"
    with owned_scratch() as scratch:
        spool = scratch / "runtime-spool"
        output_path, error_path = scratch / "records.ndjson", scratch / "diagnostics.txt"
        with output_path.open("wb") as output, error_path.open("wb") as errors:
            process = subprocess.Popen(
                [
                    str(build / "officer-agent.exe"),
                    "--source",
                    "etw",
                    "--spool-directory",
                    str(spool),
                    "--identity-path",
                    str(scratch / "missing-test-identity.json"),
                ],
                cwd=scratch,
                stdout=output,
                stderr=errors,
            )
            try:
                deadline = time.monotonic() + 15
                snapshot = None
                health = None
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("owned agent exited before inventory/health capture")
                    snapshots = [
                        record
                        for record in json_lines(output_path)
                        if record.get("kind") == "state"
                        and record.get("category") == "host_inventory"
                    ]
                    health_records = [
                        record
                        for record in json_lines(error_path)
                        if int(record.get("host_inventory", {}).get("committed_snapshots", "0")) > 0
                        and int(
                            record.get("process_inventory", {}).get("committed_snapshots", "0")
                        ) > 0
                        and int(
                            record.get("service_inventory", {}).get("committed_snapshots", "0")
                        ) > 0
                        and int(record.get("loaded_driver_inventory", {}).get(
                            "committed_snapshots", "0"
                        )) > 0
                        and int(record.get("socket_inventory", {}).get(
                            "committed_snapshots", "0"
                        )) > 0
                        and int(record.get("route_inventory", {}).get(
                            "committed_snapshots", "0"
                        )) > 0
                        and int(record.get("ip_interface_inventory", {}).get(
                            "committed_snapshots", "0"
                        )) > 0
                        and int(record.get("firewall_profile_state", {}).get(
                            "committed_snapshots", "0"
                        )) > 0
                        and int(record.get("firewall_rule_inventory", {}).get(
                            "committed_snapshots", "0"
                        )) > 0
                        and int(record.get("security_center_state", {}).get(
                            "committed_snapshots", "0"
                        )) > 0
                        and int(record.get("defender_status", {}).get(
                            "committed_snapshots", "0"
                        )) > 0
                    ]
                    process_snapshots = [
                        record for record in json_lines(output_path)
                        if record.get("kind") == "state"
                        and record.get("category") == "process_inventory"
                    ]
                    service_snapshots = [
                        record for record in json_lines(output_path)
                        if record.get("kind") == "state"
                        and record.get("category") == "service_inventory"
                    ]
                    driver_snapshots = [record for record in json_lines(output_path)
                                        if record.get("category") == "loaded_driver_inventory"]
                    socket_snapshots = [record for record in json_lines(output_path)
                                        if record.get("category") == "socket_inventory"]
                    route_snapshots = [record for record in json_lines(output_path)
                                       if record.get("category") == "route_inventory"]
                    ip_interface_snapshots = [record for record in json_lines(output_path)
                                              if record.get("category") == "ip_interface_inventory"]
                    firewall_snapshots = [record for record in json_lines(output_path)
                                          if record.get("category") == "firewall_profile_state"]
                    firewall_rule_snapshots = [
                        record for record in json_lines(output_path)
                        if record.get("category") == "firewall_rule_inventory"
                    ]
                    security_center_snapshots = [
                        record for record in json_lines(output_path)
                        if record.get("category") == "security_center_state"
                    ]
                    defender_snapshots = [record for record in json_lines(output_path)
                                          if record.get("category") == "defender_status"]
                    if (snapshots and process_snapshots and service_snapshots
                            and driver_snapshots and socket_snapshots and route_snapshots
                            and ip_interface_snapshots and firewall_snapshots
                            and firewall_rule_snapshots and security_center_snapshots
                            and defender_snapshots and health_records):
                        snapshot, health = snapshots[-1], health_records[-1]
                        process_snapshot = process_snapshots[-1]
                        service_snapshot = service_snapshots[-1]
                        driver_snapshot = driver_snapshots[-1]
                        socket_snapshot = socket_snapshots[-1]
                        route_snapshot = route_snapshots[-1]
                        ip_interface_snapshot = ip_interface_snapshots[-1]
                        firewall_snapshot = firewall_snapshots[-1]
                        firewall_rule_snapshot = firewall_rule_snapshots[-1]
                        security_center_snapshot = security_center_snapshots[-1]
                        defender_snapshot = defender_snapshots[-1]
                        break
                    time.sleep(0.05)
                if snapshot is None or health is None:
                    raise RuntimeError("native inventory/health capture timed out")
                if snapshot["data"]["inventory_complete"] is not False:
                    raise RuntimeError("partial inventory misrepresented as complete")
                inventory_health = health["host_inventory"]
                for key in ("host_inventory", "process_inventory", "service_inventory",
                            "loaded_driver_inventory", "socket_inventory", "route_inventory",
                            "ip_interface_inventory", "firewall_profile_state",
                            "firewall_rule_inventory", "security_center_state", "defender_status"):
                    status = health[key]
                    freshness = status["capture_freshness"]
                    if (freshness["state"] != "healthy"
                            or freshness["record_id"] != status["last_committed_record_id"]
                            or int(freshness["capture_age_ms"]) < int(freshness["commit_age_ms"])):
                        raise RuntimeError("committed state capture freshness is invalid")
                if (
                    health["process_inventory"].get("last_committed_record_id")
                    != process_snapshot["record_id"]
                ):
                    raise RuntimeError(
                        "process query health is not bound to its committed snapshot"
                    )
                process_status = health["process_inventory"]["last_committed_query_status"]
                defender_health = health["defender_status"]
                if (defender_health["last_committed_record_id"] != defender_snapshot["record_id"]
                        or defender_health["last_committed_query_status"]
                        != defender_snapshot["data"]):
                    raise RuntimeError("Defender query health is not bound to committed snapshot")
                if (defender_snapshot["data"]["inventory_complete"]
                        or defender_snapshot["data"]["protection_verified"]):
                    raise RuntimeError("Defender status claimed full protection")
                defender_quality = defender_snapshot["data"]["modern_property_quality"]
                for name, quality in defender_quality.items():
                    capability = next(value for value in health["capabilities"]
                                      if value["id"] == f"state.defender_status.{name}")
                    if capability["state"] != quality["state"]:
                        raise RuntimeError(
                            "Defender property coverage diverges from durable evidence"
                        )
                    if quality["protection_verified"]:
                        raise RuntimeError("Defender property quality attested protection")
                for row in defender_snapshot["data"]["entries"]:
                    if len(row["fields"]) != 36:
                        raise RuntimeError("selected Defender property surface incomplete")
                    for name in defender_quality:
                        if row["fields"][name]["contract_group"] != "modern_optional":
                            raise RuntimeError("modern Defender property contract omitted")
                wsc_health = health["security_center_state"]
                if (wsc_health["last_committed_record_id"] != security_center_snapshot["record_id"]
                        or wsc_health["last_committed_query_status"]
                        != security_center_snapshot["data"]):
                    raise RuntimeError("WSC category health diverges from its committed snapshot")
                if security_center_snapshot["data"]["protection_verified"]:
                    raise RuntimeError("WSC aggregate reports claimed verified protection")
                platform = security_center_snapshot["data"]["platform_compatibility"]
                if platform["platform_qualified"]:
                    raise RuntimeError("native version probe claimed full platform qualification")
                if platform["state"] == "healthy":
                    if platform["wsc_contract_supported"] is not True:
                        raise RuntimeError("client WSC contract eligibility is inconsistent")
                elif platform["state"] == "unsupported":
                    if (platform["wsc_contract_supported"] is not False
                            or security_center_snapshot["data"]["state"] != "unsupported"):
                        raise RuntimeError("unsupported WSC platform became trusted coverage")
                elif platform["wsc_contract_supported"] is not None:
                    raise RuntimeError("unknown native version evidence guessed WSC support")
                service_health = health["service_inventory"]
                if service_health["last_committed_record_id"] != service_snapshot["record_id"]:
                    raise RuntimeError("service query health not bound to committed manifest")
                for key, value in service_health["last_committed_query_status"].items():
                    if service_snapshot["data"].get(key) != value:
                        raise RuntimeError("service query status diverges from manifest")
                service_page_ids = service_snapshot["data"]["page_record_ids"]
                all_records = {record["record_id"]: record for record in json_lines(output_path)}
                socket_health = health["socket_inventory"]
                if socket_health["last_committed_record_id"] != socket_snapshot["record_id"]:
                    raise RuntimeError("socket health not bound to committed manifest")
                for key, value in socket_health["last_committed_query_status"].items():
                    if socket_snapshot["data"].get(key) != value:
                        raise RuntimeError("socket query health diverges from committed manifest")
                socket_pages = [all_records[rid]
                                for rid in socket_snapshot["data"]["page_record_ids"]]
                socket_entries = [row for page in socket_pages for row in page["data"]["entries"]]
                if socket_snapshot["data"]["entries_delivered"] != str(len(socket_entries)):
                    raise RuntimeError("socket row accounting disagrees with durable pages")
                for index, page in enumerate(socket_pages):
                    if (page["data"]["page_index"] != str(index)
                            or page["data"]["capture_id"] != socket_snapshot["data"]["capture_id"]):
                        raise RuntimeError("socket page capture/index mismatch")
                for row in socket_entries:
                    if (row["process_reference"] is not None
                            or row["socket_instance_reference"] is not None):
                        raise RuntimeError("socket table PID promoted to verified instance")
                for key, query in socket_snapshot["data"]["tables"].items():
                    accepted = sum(row["source_table"] == key for row in socket_entries)
                    if query["rows_in_accepted_pages"] != str(accepted):
                        raise RuntimeError("socket table acceptance disagrees with durable rows")
                    capability = next((c for c in health["capabilities"]
                                       if c["id"] == "state.socket_table." + key), None)
                    if capability is None or capability["state"] != query["state"]:
                        raise RuntimeError("socket table coverage disagrees with committed query")
                firewall_rule_health = health["firewall_rule_inventory"]
                if (firewall_rule_health["last_committed_record_id"]
                        != firewall_rule_snapshot["record_id"]):
                    raise RuntimeError("firewall rule health not bound to committed manifest")
                for key, value in firewall_rule_health["last_committed_query_status"].items():
                    if firewall_rule_snapshot["data"].get(key) != value:
                        raise RuntimeError("firewall rule query status not bound to manifest")
                firewall_rule_pages = [next(r for r in json_lines(output_path)
                                           if r["record_id"] == rid)
                                       for rid in firewall_rule_snapshot["data"]["page_record_ids"]]
                firewall_rule_rows = [row for page in firewall_rule_pages
                                      for row in page["data"]["entries"]]
                if (firewall_rule_snapshot["data"]["entries_delivered"]
                        != str(len(firewall_rule_rows))):
                    raise RuntimeError("firewall rule durable row count mismatch")
                for index, page in enumerate(firewall_rule_pages):
                    if (page["data"]["page_index"] != str(index)
                            or page["data"]["capture_id"]
                            != firewall_rule_snapshot["data"]["capture_id"]):
                        raise RuntimeError("firewall rule page ordering or scope mismatch")
                if any(row["rule_reference"] is not None or row["process_reference"] is not None
                       for row in firewall_rule_rows):
                    raise RuntimeError("firewall rule descriptors became verified lifetime")
                for row in firewall_rule_rows:
                    if not row["fields"]:
                        continue
                    if len(row["fields"]) != 25 or set(row["extension_interface_queries"]) != {
                        "QueryInterface(INetFwRule2)", "QueryInterface(INetFwRule3)"
                    }:
                        raise RuntimeError("firewall extension getter/interface evidence missing")
                    for field in row["fields"].values():
                        if not field["query_attempted"] and (
                            field["hresult_code"] is not None or field["value"] is not None
                        ):
                            raise RuntimeError("unattempted firewall getter fabricated a result")
                firewall_health = health["firewall_profile_state"]
                if (firewall_health["last_committed_record_id"] != firewall_snapshot["record_id"]
                        or firewall_health["last_committed_query_status"]
                        != firewall_snapshot["data"]):
                    raise RuntimeError("firewall health does not match committed query record")
                if (firewall_snapshot["data"]["inventory_complete"]
                        or firewall_snapshot["data"]["effective_packet_policy_verified"]):
                    raise RuntimeError("firewall profile subset claimed full enforcement")
                firewall_coverage = next(c for c in health["capabilities"]
                                         if c["id"] == "state.firewall_profiles")
                if firewall_coverage["state"] != firewall_snapshot["data"]["state"]:
                    raise RuntimeError("firewall coverage does not match committed query state")
                for profile in firewall_snapshot["data"]["profiles"]:
                    capability = next(c for c in health["capabilities"]
                                      if c["id"] == "state.firewall_exclusions."
                                      + profile["profile_name"])
                    if capability["state"] != profile["fields"]["excluded_interfaces"]["state"]:
                        raise RuntimeError("exclusion coverage does not match committed getter")
                ip_interface_health = health["ip_interface_inventory"]
                if (ip_interface_health["last_committed_record_id"]
                        != ip_interface_snapshot["record_id"]):
                    raise RuntimeError("ip_interface health not bound to committed manifest")
                for key, value in ip_interface_health["last_committed_query_status"].items():
                    if ip_interface_snapshot["data"].get(key) != value:
                        raise RuntimeError("IP interface query health diverges from manifest")
                ip_interface_pages = [all_records[rid]
                                for rid in ip_interface_snapshot["data"]["page_record_ids"]]
                ip_interface_entries = [row for page in ip_interface_pages
                                        for row in page["data"]["entries"]]
                if (ip_interface_snapshot["data"]["entries_delivered"]
                        != str(len(ip_interface_entries))):
                    raise RuntimeError("ip_interface row accounting disagrees with durable pages")
                for index, page in enumerate(ip_interface_pages):
                    if (page["data"]["page_index"] != str(index)
                            or page["data"]["capture_id"]
                            != ip_interface_snapshot["data"]["capture_id"]):
                        raise RuntimeError("ip_interface page capture/index mismatch")
                for row in ip_interface_entries:
                    if row["value"]["interface_instance_reference"] is not None:
                        raise RuntimeError("IP interface census invented persistent lifetime")
                    if row["source"] != "GetIpInterfaceTable":
                        raise RuntimeError("IP interface census lost independent table provenance")
                for key, query in ip_interface_snapshot["data"]["tables"].items():
                    accepted = sum(row["source_table"] == key for row in ip_interface_entries)
                    if query["rows_in_accepted_pages"] != str(accepted):
                        raise RuntimeError("IP interface table acceptance disagrees with pages")
                    capability = next((c for c in health["capabilities"]
                                       if c["id"] == "state.ip_interface_table." + key), None)
                    if capability is None or capability["state"] != query["state"]:
                        raise RuntimeError("IP interface table coverage disagrees with query")
                route_health = health["route_inventory"]
                if route_health["last_committed_record_id"] != route_snapshot["record_id"]:
                    raise RuntimeError("route health not bound to committed manifest")
                for key, value in route_health["last_committed_query_status"].items():
                    if route_snapshot["data"].get(key) != value:
                        raise RuntimeError("route query health diverges from committed manifest")
                route_pages = [all_records[rid]
                                for rid in route_snapshot["data"]["page_record_ids"]]
                route_entries = [row for page in route_pages for row in page["data"]["entries"]]
                if route_snapshot["data"]["entries_delivered"] != str(len(route_entries)):
                    raise RuntimeError("route row accounting disagrees with durable pages")
                for index, page in enumerate(route_pages):
                    if (page["data"]["page_index"] != str(index)
                            or page["data"]["capture_id"] != route_snapshot["data"]["capture_id"]):
                        raise RuntimeError("route page capture/index mismatch")
                for row in route_entries:
                    if (row["interface_instance_reference"] is not None
                            or row["route_instance_reference"] is not None
                            or row["effective_route_metric"] is not None):
                        raise RuntimeError("route fields promoted to instance/effective path")
                    lookup = row["later_ip_interface_query"]
                    if "unverified" not in lookup["route_relation"]:
                        raise RuntimeError("later interface lookup claimed verified route lifetime")
                    if row["reported_metric_sum"] is not None:
                        if (not lookup.get("lookup_key_matches_returned_fields")
                                or row["reported_metric_offset"] == "4294967295"
                                or int(row["reported_metric_sum"]) != (
                                    int(row["reported_metric_offset"])
                                    + int(lookup["value"]["reported_metric"]))):
                            raise RuntimeError("route/interface metric arithmetic mismatch")
                interface_summary = route_snapshot["data"]["ip_interface_query_summary"]
                unique_lookups = {}
                reuse = unattempted = 0
                for row in route_entries:
                    lookup = row["later_ip_interface_query"]
                    if "requested_interface_luid" not in lookup:
                        unattempted += 1
                        continue
                    key = (lookup["requested_address_family"], lookup["requested_interface_luid"],
                           lookup["requested_interface_index"])
                    if key in unique_lookups:
                        reuse += 1
                        if unique_lookups[key] != lookup:
                            raise RuntimeError("cached later query changed within one capture")
                    else:
                        unique_lookups[key] = lookup
                success = sum(v["native_query_succeeded"] for v in unique_lookups.values())
                unknown = sum(v["native_query_succeeded"] and v["state"] != "healthy"
                              for v in unique_lookups.values())
                expected = {"successful_native_queries": str(success),
                            "failed_native_queries": str(len(unique_lookups) - success),
                            "uninterpreted_or_mismatched_results": str(unknown),
                            "cached_row_reuses": str(reuse),
                            "row_queries_not_attempted": str(unattempted)}
                if any(interface_summary[k] != v for k, v in expected.items()):
                    raise RuntimeError("later interface query accounting disagrees with pages")
                interface_capability = next((c for c in health["capabilities"]
                                             if c["id"] == "state.route_ip_interface"), None)
                if (interface_capability is None
                        or interface_capability["state"] != interface_summary["state"]):
                    raise RuntimeError("later interface query health diverges from manifest")
                for key, query in route_snapshot["data"]["tables"].items():
                    accepted = sum(row["source_table"] == key for row in route_entries)
                    if query["rows_in_accepted_pages"] != str(accepted):
                        raise RuntimeError("route table acceptance disagrees with durable rows")
                    capability = next((c for c in health["capabilities"]
                                       if c["id"] == "state.route_table." + key), None)
                    if capability is None or capability["state"] != query["state"]:
                        raise RuntimeError("route table coverage disagrees with committed query")
                driver_health = health["loaded_driver_inventory"]
                if driver_health["last_committed_record_id"] != driver_snapshot["record_id"]:
                    raise RuntimeError("loaded-driver health not bound to committed manifest")
                for key, value in driver_health["last_committed_query_status"].items():
                    if driver_snapshot["data"].get(key) != value:
                        raise RuntimeError("loaded-driver query status diverges from manifest")
                driver_pages = [all_records[record_id]
                                for record_id in driver_snapshot["data"]["page_record_ids"]]
                driver_entries = [row for page in driver_pages for row in page["data"]["entries"]]
                if driver_snapshot["data"].get("enumeration_complete"):
                    if str(len(driver_entries)) != driver_snapshot["data"]["entries_delivered"]:
                        raise RuntimeError("loaded-driver delivered slots disagree with manifest")
                    nulls = sum(row["reported_image_base"] == "0" for row in driver_entries)
                    if driver_entries and nulls == len(driver_entries):
                        if driver_snapshot["data"]["state"] != "blind":
                            raise RuntimeError(
                                "restricted driver addresses presented as healthy census"
                            )
                for index, page in enumerate(driver_pages):
                    if (page["data"]["page_index"] != str(index)
                            or page["data"]["capture_id"] != driver_snapshot["data"]["capture_id"]):
                        raise RuntimeError("loaded-driver page capture/index mismatch")
                service_pages = [all_records[record_id] for record_id in service_page_ids]
                service_count = sum(len(page["data"]["entries"]) for page in service_pages)
                if service_snapshot["data"]["state"] == "degraded" and (
                    service_snapshot["data"]["entries_delivered"] != str(service_count)
                ):
                    raise RuntimeError("service delivered counts disagree with durable pages")
                if service_snapshot["data"].get("inventory_complete"):
                    raise RuntimeError("caller-visible service capture claimed full inventory")
                for index, page in enumerate(service_pages):
                    if page["data"]["page_index"] != str(index) or (
                        page["data"]["capture_id"] != service_snapshot["data"]["capture_id"]
                    ):
                        raise RuntimeError("service page scope/index mismatch")
                    for entry in page["data"]["entries"]:
                        if entry["process_reference"] or entry["service_instance_reference"]:
                            raise RuntimeError("SCM reported name/PID was promoted to an instance")
                if service_snapshot["data"].get("enumeration_complete"):
                    security_facts = [entry["later_security_query"]
                                      for page in service_pages
                                      for entry in page["data"]["entries"]]
                    security_summary = service_snapshot["data"]["security_query_summary"]
                    security_expected = {
                        "successful_native_queries": sum(
                            fact.get("native_query_succeeded") is True for fact in security_facts
                        ),
                        "failed_native_queries": sum(
                            fact.get("native_query_succeeded") is False for fact in security_facts
                        ),
                        "failed_security_opens": sum(
                            fact.get("source") == "OpenServiceW/READ_CONTROL"
                            for fact in security_facts
                        ),
                        "queries_not_attempted": sum(
                            fact.get("source") == "OpenServiceW/READ_CONTROL/input"
                            for fact in security_facts
                        ),
                        "validation_failures": sum(
                            int(fact.get("validation_failure_count", "0"))
                            for fact in security_facts
                        ),
                        "bounded_results": sum(
                            fact.get("bound_exceeded", False) for fact in security_facts
                        ),
                    }
                    if any(security_summary.get(key) != str(count)
                           for key, count in security_expected.items()):
                        raise RuntimeError("service security summary disagrees with retained facts")
                    configs = [entry["later_configuration_query"]
                               for page in service_pages for entry in page["data"]["entries"]]
                    not_attempted = sum("optional_configuration_queries" not in config
                                        for config in configs)
                    coverage = {item["id"]: item["state"] for item in health["capabilities"]}
                    if (
                        coverage.get("state.service_security_descriptor")
                        != security_summary["state"]
                    ):
                        raise RuntimeError(
                            "service security coverage diverges from committed query"
                        )
                    for name, summary in service_snapshot["data"][
                        "optional_configuration_query_summary"
                    ].items():
                        facts = [config["optional_configuration_queries"][name]
                                 for config in configs
                                 if "optional_configuration_queries" in config]
                        successful = sum(fact["native_query_succeeded"] for fact in facts)
                        invalid = sum(fact["native_query_succeeded"] and fact["state"] != "healthy"
                                      for fact in facts)
                        if (
                            summary["successful_native_queries"] != str(successful)
                            or summary["failed_native_queries"] != str(len(facts) - successful)
                            or summary["uninterpreted_or_invalid_results"] != str(invalid)
                            or summary["queries_not_attempted"] != str(not_attempted)
                            or coverage.get("state.service_configuration." + name)
                            != summary["state"]
                        ):
                            raise RuntimeError(
                                "service configuration query accounting/coverage diverges"
                            )
                page_ids = process_snapshot["data"]["page_record_ids"]
                process_pages = {
                    record["record_id"]: record for record in json_lines(output_path)
                    if record.get("category") == "process_inventory_page"
                }
                if any(record_id not in process_pages for record_id in page_ids):
                    raise RuntimeError("native manifest precedes durable page output")
                process_entry_count = sum(
                    len(process_pages[record_id]["data"]["entries"]) for record_id in page_ids
                )
                if str(process_entry_count) != process_snapshot["data"]["entries_delivered"]:
                    raise RuntimeError("paged native manifest disagrees with delivered entries")
                for key, value in process_status.items():
                    if process_snapshot["data"].get(key) != value:
                        raise RuntimeError(
                            "committed process query status diverged from native state"
                        )
                security_summary = process_snapshot["data"]["security_query_summary"]
                if process_status.get("security_query_summary") != security_summary:
                    raise RuntimeError("process security query health is not bound to manifest")
                not_attempted = sum(
                    "reference" not in entry["later_pid_query"]
                    for record_id in page_ids
                    for entry in process_pages[record_id]["data"]["entries"]
                )
                if process_snapshot["data"].get("enumeration_complete") and (
                    security_summary["process_queries_not_attempted"] != str(not_attempted)
                ):
                    raise RuntimeError("unattempted process security queries missing from summary")
                if not_attempted and any(
                    security_summary[field]["state"] == "healthy"
                    for field in ("critical_process", "protection_level", "architecture")
                ):
                    raise RuntimeError("partial process security coverage misreported healthy")
                for field in ("critical_process", "protection_level", "architecture"):
                    succeeded = failed = unsupported = unknown = 0
                    for record_id in page_ids:
                        for entry in process_pages[record_id]["data"]["entries"]:
                            query = entry["later_pid_query"]
                            if "reference" not in query:
                                continue
                            fact = query[field]
                            if fact["state"] == "unsupported":
                                unsupported += 1
                                if fact["value"] is not None or fact["error_domain"] != "Win32":
                                    raise RuntimeError(
                                        "architecture absence lost its native status"
                                    )
                            elif fact["error_code"] is None:
                                succeeded += 1
                                unknown += fact["state"] == "degraded"
                            else:
                                failed += 1
                                if fact["value"] is not None or fact["error_domain"] != "Win32":
                                    raise RuntimeError("process security refusal lost native error")
                    if process_snapshot["data"].get("enumeration_complete") and (
                        security_summary[field]["successful_queries"] != str(succeeded)
                        or security_summary[field]["failed_queries"] != str(failed)
                    ):
                        raise RuntimeError(
                            "complete enumeration security counts disagree with pages"
                        )
                    if field == "architecture" and process_snapshot["data"].get(
                        "enumeration_complete"
                    ) and (
                        security_summary[field]["unsupported_queries"] != str(unsupported)
                        or security_summary[field]["uninterpreted_results"] != str(unknown)
                    ):
                        raise RuntimeError("architecture unknown/unsupported count lost in summary")
                opened = open_failed = fields_ok = fields_failed = uninterpreted = 0
                for record_id in page_ids:
                    for entry in process_pages[record_id]["data"]["entries"]:
                        query = entry["later_pid_query"]
                        if "reference" not in query:
                            continue
                        token = query["primary_token"]
                        if "fields" not in token:
                            open_failed += 1
                            if token["value"] is not None or token["error_domain"] != "Win32":
                                raise RuntimeError("token open refusal lost its native status")
                            continue
                        opened += 1
                        if token["inventory_complete"] or token["state"] not in {
                            "degraded", "unavailable"
                        }:
                            raise RuntimeError(
                                "selected token attributes claimed full token coverage"
                            )
                        for fact in token["fields"].values():
                            if fact["state"] == "unavailable":
                                fields_failed += 1
                                if fact["value"] is not None or not fact["error_domain"]:
                                    raise RuntimeError("token field refusal lost status")
                            else:
                                fields_ok += 1
                                uninterpreted += fact["state"] == "degraded"
                if process_snapshot["data"].get("enumeration_complete"):
                    expected = {
                        "opened_tokens": str(opened), "failed_token_opens": str(open_failed),
                        "successful_field_queries": str(fields_ok),
                        "failed_field_queries": str(fields_failed),
                        "uninterpreted_fields": str(uninterpreted),
                    }
                    if any(security_summary["primary_token"].get(k) != v
                           for k, v in expected.items()):
                        raise RuntimeError("token query summary disagrees with retained pages")
                admission = health["journal"]["storage_admission"]
                handoff = health["pipeline"]["raw_handoff"]
                if (
                    handoff["state"] != "degraded"
                    or int(handoff["event_limit"]) != 8192
                    or int(handoff["byte_limit"]) != 64 * 1024 * 1024
                    or int(handoff["fixed_ring_bytes"]) <= 0
                    or handoff["contention_refused"] != "0"
                    or int(handoff["exception_refused"]) < 0
                    or "allocation_refused" in handoff
                    or int(handoff["owned_events"]) > int(handoff["event_limit"])
                    or int(handoff["charged_bytes"]) > int(handoff["byte_limit"])
                    or int(handoff["admitted_volatile"]) != (
                        int(handoff["completed_durable"])
                        + int(handoff["failed"]) + int(handoff["owned_events"])
                    )
                ):
                    raise RuntimeError("native handoff misreports volatility, accounting or bounds")
                if admission["state"] != "degraded" or admission["refusals"] != "0":
                    raise RuntimeError(
                        "sampled storage safeguard claimed complete or refused normal capture"
                    )
                for key in (
                    "physical_admission_limit", "minimum_free_bytes", "caller_available_bytes",
                ):
                    if not isinstance(admission[key], str) or int(admission[key]) <= 0:
                        raise RuntimeError("journal storage sample missing exact decimal capacity")
                if inventory_health.get("last_committed_record_id") != snapshot["record_id"]:
                    raise RuntimeError(
                        "field query health is not bound to the committed host snapshot"
                    )
                coverage = {value["id"]: value["state"] for value in health["capabilities"]}
                for field, capability in (
                    ("tpm", "state.tpm_device"), ("entra_join", "state.entra_default_join"),
                    ("storage", "state.storage_volumes"),
                    ("system_audit_policy", "state.system_audit_policy"),
                ):
                    fact = snapshot["data"]["fields"][field]
                    status = inventory_health["field_query_status"][field]
                    if (
                        status["state"] != fact["state"]
                        or coverage.get(capability) != fact["state"]
                    ):
                        raise RuntimeError("native field failure/availability was lost in health")
                    for key in (
                        "source", "error_code", "error_domain", "query_status_code",
                        "enumeration_error_code", "query_failures", "query_failures_scope",
                        "bound_exceeded", "enumerated_subcategory_count", "scope",
                    ):
                        if key in fact and status.get(key) != fact[key]:
                            raise RuntimeError(
                                "native field query provenance/error was lost in health"
                            )
                time.sleep(0.1)
                if process.poll() is not None:
                    raise RuntimeError("agent did not continue after collector startup failure")
            finally:
                # Only our live Popen handle is terminated, intentionally without
                # destructors, to exercise retained state after abrupt exit.
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        recovered = json.loads(
            subprocess.check_output(
                [str(build / "officer-host-inventory-tests.exe"), "--read-spool", str(spool)],
                text=True,
                encoding="utf-8",
            )
        )
        state_capture_gaps = [record for record in json_lines(output_path)
                              if record.get("kind") == "gap" and record.get("data", {}).get(
                                  "gap_kind") == "state_capture_freshness_transition"]
        if not state_capture_gaps:
            raise RuntimeError("no sampled state capture transition was durably emitted")
        for gap in state_capture_gaps:
            if [record for record in recovered if record["record_id"] == gap["record_id"]] != [gap]:
                raise RuntimeError("exact state capture transition did not survive abrupt exit")
            if gap["data"]["lost_native_events"] is not None:
                raise RuntimeError("state capture transition fabricated native event loss")
        if [r for r in recovered if r["record_id"] == defender_snapshot["record_id"]] != [
            defender_snapshot
        ]:
            raise RuntimeError("exact Defender state did not survive abrupt exit")
        if not any(r["kind"] == "health" and r["data"].get("defender_status") == defender_health
                   for r in recovered):
            raise RuntimeError("exact record-bound Defender health did not survive abrupt exit")
        if [r for r in recovered if r["record_id"] == security_center_snapshot["record_id"]] != [
            security_center_snapshot
        ]:
            raise RuntimeError("exact WSC category snapshot did not survive abrupt exit")
        if not any(r["kind"] == "health" and r["data"].get("security_center_state") == wsc_health
                   for r in recovered):
            raise RuntimeError("record-bound WSC category health did not survive abrupt exit")
        if [r for r in recovered if r["record_id"] == firewall_snapshot["record_id"]] != [
            firewall_snapshot
        ]:
            raise RuntimeError("exact firewall profile state did not survive abrupt exit")
        if not any(record["kind"] == "health"
                   and record["data"].get("firewall_profile_state") == firewall_health
                   for record in recovered):
            raise RuntimeError("record-bound firewall health did not survive abrupt exit")
        for record in [firewall_rule_snapshot, *firewall_rule_pages]:
            if [r for r in recovered if r["record_id"] == record["record_id"]] != [record]:
                raise RuntimeError("exact firewall rule state did not survive abrupt exit")
        if not any(record["kind"] == "health"
                   and record["data"].get("firewall_rule_inventory") == firewall_rule_health
                   for record in recovered):
            raise RuntimeError("record-bound firewall rule health did not survive abrupt exit")
        matching = [record for record in recovered if record["record_id"] == snapshot["record_id"]]
        for record in [socket_snapshot, *socket_pages]:
            if [r for r in recovered if r["record_id"] == record["record_id"]] != [record]:
                raise RuntimeError("exact socket state did not survive abrupt exit")
        if not any(record["kind"] == "health"
                   and record["data"].get("socket_inventory") == socket_health
                   for record in recovered):
            raise RuntimeError("record-bound socket health did not survive abrupt exit")
        for record in [route_snapshot, *route_pages]:
            if [r for r in recovered if r["record_id"] == record["record_id"]] != [record]:
                raise RuntimeError("exact route state did not survive abrupt exit")
        if not any(record["kind"] == "health"
                   and record["data"].get("route_inventory") == route_health
                   for record in recovered):
            raise RuntimeError("record-bound route health did not survive abrupt exit")
        for record in [ip_interface_snapshot, *ip_interface_pages]:
            if [r for r in recovered if r["record_id"] == record["record_id"]] != [record]:
                raise RuntimeError("exact ip_interface state did not survive abrupt exit")
        if not any(record["kind"] == "health"
                   and record["data"].get("ip_interface_inventory") == ip_interface_health
                   for record in recovered):
            raise RuntimeError("record-bound ip_interface health did not survive abrupt exit")
        for record in [driver_snapshot, *driver_pages]:
            if [r for r in recovered if r["record_id"] == record["record_id"]] != [record]:
                raise RuntimeError("exact loaded-driver state did not survive abrupt exit")
        if not any(record["kind"] == "health"
                   and record["data"].get("loaded_driver_inventory") == driver_health
                   for record in recovered):
            raise RuntimeError("record-bound loaded-driver health did not survive abrupt exit")
        if matching != [snapshot]:
            raise RuntimeError("native host state did not survive abrupt exit byte-for-byte")
        if [r for r in recovered if r["record_id"] == process_snapshot["record_id"]] != [
            process_snapshot
        ]:
            raise RuntimeError("exact native process state did not survive abrupt exit")
        for record_id in page_ids:
            if [r for r in recovered if r["record_id"] == record_id] != [process_pages[record_id]]:
                raise RuntimeError("exact native process page did not survive abrupt exit")
        for record in [service_snapshot, *service_pages]:
            found = [r for r in recovered if r["record_id"] == record["record_id"]]
            if found != [record]:
                raise RuntimeError(
                    f"exact service manifest/page did not survive abrupt exit: "
                    f"expected={record['record_id']} category={record['category']} "
                    f"recovered={len(recovered)} bytes="
                    f"{sum(len(json.dumps(r).encode()) for r in recovered)}"
                )
        if not any(
            record["kind"] == "health"
            and record["data"].get("service_inventory") == service_health
            for record in recovered
        ):
            raise RuntimeError("exact record-bound service query health did not survive exit")
        if not any(record["kind"] == "health" for record in recovered):
            raise RuntimeError("endpoint health was not durably retained")
        if not any(
            record["kind"] == "health"
            and record["data"].get("journal", {}).get("storage_admission") == admission
            for record in recovered
        ):
            raise RuntimeError("exact storage admission health did not survive abrupt exit")
        if not any(
            record["kind"] == "health"
            and record["data"].get("pipeline", {}).get("raw_handoff") == handoff
            for record in recovered
        ):
            raise RuntimeError("exact volatile handoff health did not survive abrupt exit")
        capabilities = {value["id"]: value["state"] for value in health["capabilities"]}
        if capabilities.get("state.loaded_driver_inventory") != driver_snapshot["data"]["state"]:
            raise RuntimeError("loaded-driver coverage diverges from committed snapshot")
        if capabilities.get("response.process_target") != "disabled":
            raise RuntimeError("unconfigured process response did not expose disabled coverage")
        if capabilities["sensor.etw"] == "unavailable" and capabilities["B.process"] != "blind":
            raise RuntimeError("missing process events did not expose blind coverage")
        print(
            json.dumps(
                {
                    "check": "actual native host inventory and owned-process crash recovery",
                    "inventory_fields": len(snapshot["data"]["fields"]),
                    "durable_process_snapshot_recovered": True,
                    "process_snapshot_entries": process_entry_count,
                    "durable_process_pages_recovered": len(page_ids),
                    "service_snapshot_entries": service_count,
                    "firewall_query_summary": firewall_snapshot["data"]["query_summary"],
                    "firewall_exclusion_summary": firewall_snapshot["data"][
                        "exclusion_query_summary"
                    ],
                    "durable_firewall_state_and_health_recovered": True,
                    "firewall_rule_entries": len(firewall_rule_rows),
                    "firewall_rule_pages": len(firewall_rule_pages),
                    "firewall_rule_getter_surface": 25,
                    "state_capture_freshness_domains": 11,
                    "durable_defender_state_and_health_recovered": True,
                    "defender_native_steps": defender_snapshot["data"]["native_steps"],
                    "defender_query_summary": defender_snapshot["data"].get("query_summary"),
                    "defender_modern_property_quality": defender_quality,
                    "security_center_query_summary":
                        security_center_snapshot["data"]["query_summary"],
                    "durable_security_center_state_and_health_recovered": True,
                    "security_center_platform": platform,
                    "durable_state_capture_transitions_recovered": len(state_capture_gaps),
                    "durable_firewall_rule_state_and_health_recovered": True,
                    "ip_interface_entries": len(ip_interface_entries),
                    "ip_interface_tables": ip_interface_snapshot["data"]["tables"],
                    "durable_ip_interface_pages_recovered": len(ip_interface_pages),
                    "route_entries": len(route_entries),
                    "route_ip_interface_query_summary": interface_summary,
                    "route_tables": route_snapshot["data"]["tables"],
                    "durable_route_pages_recovered": len(route_pages),
                    "socket_entries": len(socket_entries),
                    "socket_tables": socket_snapshot["data"]["tables"],
                    "durable_socket_pages_recovered": len(socket_pages),
                    "loaded_driver_reported_slots": len(driver_entries),
                    "loaded_driver_state": driver_snapshot["data"]["state"],
                    "durable_loaded_driver_pages_recovered": len(driver_pages),
                    "durable_service_pages_recovered": len(service_page_ids),
                    "service_query_status": service_health["last_committed_query_status"],
                    "process_snapshot_enumeration_complete": (
                        process_snapshot["data"].get("enumeration_complete")
                    ),
                    "process_security_query_summary": security_summary,
                    "telemetry_source_state": capabilities["sensor.etw"],
                    "process_coverage": capabilities["B.process"],
                    "host_coverage": capabilities["A.host"],
                    "process_response_coverage": capabilities["response.process_target"],
                    "durable_host_snapshot_recovered": True,
                    "durable_health_recovered": True,
                    "tpm_query_state": snapshot["data"]["fields"]["tpm"]["state"],
                    "entra_query_state": snapshot["data"]["fields"]["entra_join"]["state"],
                    "volume_query_state": snapshot["data"]["fields"]["storage"]["state"],
                    "system_audit_policy_state": (
                        snapshot["data"]["fields"]["system_audit_policy"]["state"]
                    ),
                    "field_query_health_bound_to_snapshot": True,
                    "offline_journal_storage_admission_state": admission["state"],
                    "durable_storage_admission_health_recovered": True,
                    "raw_handoff_state": handoff["state"],
                    "durable_raw_handoff_health_recovered": True,
                }
            )
        )


if __name__ == "__main__":
    main()
