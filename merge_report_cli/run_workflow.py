import json
import uuid
import re
import os
import argparse # Thêm thư viện argparse

## --- Các hàm từ wapiti_to_sarif.py (giữ nguyên) ---

def _build_wstg_taxonomy_entry(wstg_ids: set) -> dict:
    wstg_taxonomy = {
        "downloadUri": "https://owasp.org/www-project-web-security-testing-guide/stable/",
        "guid": str(uuid.uuid4()),
        "informationUri": "https://owasp.org/www-project-web-security-testing-guide/",
        "isComprehensive": False,
        "language": "en",
        "name": "OWASP WSTG",
        "organization": "OWASP",
        "shortDescription": {"text": "The OWASP Web Security Testing Guide (WSTG)."},
        "taxa": []
    }

    wstg_uri_map = {
        "WSTG-CONF-04": "02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information.html",
        "WSTG-ATHN-07": "04-Authentication_Testing/07-Testing_for_Weak_Password_Policy.html",
        "WSTG-INPV-15": "07-Input_Validation_Testing/15-Testing_for_HTTP_Splitting_Smuggling.html",
        "WSTG-CONF-12": "02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy.html",
        "OSHP-Content-Security-Policy": "02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy.html", 
        "WSTG-SESS-05": "06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery.html",
        "WSTG-CONF-01": "02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration.html",
        "WSTG-INPV-12": "07-Input_Validation_Testing/12-Testing_for_Command_Injection.html",
        "WSTG-ATHZ-01": "05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.html", 
        "WSTG-INFO-08": "01-Information_Gathering/08-Fingerprint_Web_Application_Framework.html",
        "WSTG-INFO-02": "01-Information_Gathering/02-Fingerprint_Web_Server.html",
        "WSTG-CONF-06": "02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.html",
        "WSTG-CLNT-03": "11-Client_Side_Testing/03-Testing_for_HTML_Injection.html",
        "OSHP-X-Frame-Options": "11-Client-side_Testing/09-Testing_for_Clickjacking.html",
        "WSTG-CONF-07": "02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security.html",
        "OSHP-HTTP-Strict-Transport-Security": "02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security.html",
        "OSHP-X-Content-Type-Options": "02-Configuration_and_Deployment_Management_Testing/13-Test_for_MIME_Type_Sniffing.html", 
        "WSTG-SESS-02": "06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html",
        "WSTG-CRYP-03": "09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels.html",
        "WSTG-INPV-06": "07-Input_Validation_Testing/06-Testing_for_LDAP_Injection.html", 
        "WSTG-INPV-11": "07-Input_Validation_Testing/11-Testing_for_Code_Injection.html", 
        "WSTG-CLNT-04": "11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect.html",
        "WSTG-INPV-01": "07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.html",
        "WSTG-INPV-05": "07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html", 
        "WSTG-CRYP-01": "09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_SSL_TLS_Ciphers_Insufficient_Transport_Layer_Protection.html",
        "WSTG-INPV-19": "07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery.html",
        "WSTG-INPV-02": "07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting.html",
        "WSTG-CONF-10": "02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover.html",
        "WSTG-BUSL-08": "10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types.html",
        "WSTG-ERRH-01": "08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling.html", 
        "WSTG-INFO-03": "01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage.html",
    }
    
    for wstg_id in sorted(list(wstg_ids)):
        help_uri = "https://owasp.org/www-project-web-security-testing-guide/stable/UNMAPPED.html" 
        mapped_path = wstg_uri_map.get(wstg_id, None)

        if mapped_path:
            if wstg_id in ["OSHP-X-Content-Type-Options"]:
                help_uri = "https://owasp.org/www-community/attacks/MIME_sniffing.html" 
            elif wstg_id in ["OSHP-X-Frame-Options"]:
                help_uri = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking.html"
            else:
                help_uri = f"https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/{mapped_path}"
        else:
            match = re.match(r"(WSTG|OSHP)-(\w+)-(\d+)", wstg_id)
            if match:
                prefix = match.group(1)
                category_code = match.group(2)
                number = match.group(3).zfill(2)
                
                general_category_map = {
                    "INFO": "Information_Gathering", "CONF": "Configuration_and_Deployment_Management_Testing",
                    "ATHN": "Authentication_Testing", "SESS": "Session_Management_Testing",
                    "ATHZ": "Authorization_Testing", "INPV": "Input_Validation_Testing",
                    "ERRH": "Error_Handling", "CRYP": "Cryptography",
                    "BUSL": "Business_Logic_Testing", "CLNT": "Client-side_Testing",
                }
                path_segment = general_category_map.get(category_code, "General_Testing")
                help_uri = f"https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/{path_segment}/{number}-{wstg_id.lower().replace(prefix.lower() + '-', '').replace('-', '_')}.html"
            
            if help_uri == "https://owasp.org/www-project-web-security-testing-guide/stable/UNMAPPED.html":
                print(f"⚠️ Cảnh báo: Không tìm thấy URI WSTG chính xác cho ID: {wstg_id}. Sử dụng URI mặc định.")


        wstg_taxonomy["taxa"].append({
            "guid": str(uuid.uuid4()),
            "helpUri": help_uri,
            "id": wstg_id
        })
    
    return wstg_taxonomy

def _build_cwe_taxonomy_entry(cwe_ids: set) -> dict:
    cwe_taxonomy = {
        "downloadUri": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "guid": str(uuid.uuid4()),
        "informationUri": "https://cwe.mitre.org/data/published/cwe_latest.pdf",
        "isComprehensive": False,
        "language": "en",
        "name": "CWE",
        "organization": "MITRE",
        "shortDescription": {"text": "The MITRE Common Weakness Enumeration."},
        "taxa": []
    }

    for cwe_id in sorted(list(cwe_ids)):
        cwe_number = cwe_id.replace("CWE-", "")
        help_uri = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"
        cwe_taxonomy["taxa"].append({
            "guid": str(uuid.uuid4()),
            "helpUri": help_uri,
            "id": cwe_id
        })
    return cwe_taxonomy

def wapiti_to_sarif_converter(wapiti_json_data: dict) -> dict:
    sarif_data = {
        "runs": [],
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
    }

    run_entry = {
        "results": [],
        "taxonomies": [],
        "tool": {
            "driver": {
                "name": "Wapiti",
                "informationUri": "https://wapiti.sourceforge.io/",
                "rules": []
            }
        }
    }

    wapiti_infos = wapiti_json_data.get("infos", {})
    target_base_uri = wapiti_infos.get("target", "https://example.com")
    run_entry["tool"]["driver"]["version"] = wapiti_infos.get("version", "Unknown Wapiti Version")

    rule_map = {} 
    all_unique_wstg_ids = set() 
    all_unique_cwe_ids = set()

    default_rule_id = "wapiti-general-finding" 
    
    classifications = wapiti_json_data.get("classifications", {})
    for classification_name, details in classifications.items():
        final_rule_id = f"wapiti-{classification_name.lower().replace(' ', '-')}"

        original_final_rule_id = final_rule_id
        while final_rule_id in rule_map:
            final_rule_id = f"{original_final_rule_id}-{uuid.uuid4().hex[:4]}" 
        
        rule_entry = {
            "id": final_rule_id,
            "name": classification_name,
            "fullDescription": {
                "text": details.get("desc", f"No description for {classification_name}.")
            },
            "properties": {
                "solution": details.get("sol", "No solution provided."),
                "references": []
            },
            "relationships": []
        }
        
        if "ref" in details and isinstance(details["ref"], dict):
            for ref_name, ref_uri in details["ref"].items():
                rule_entry["properties"]["references"].append({
                    "uri": ref_uri,
                    "text": ref_name 
                })
                cwe_match = re.search(r"cwe\.mitre\.org\/data\/definitions\/(\d+)\.html", ref_uri)
                if cwe_match:
                    cwe_id = f"CWE-{cwe_match.group(1)}"
                    all_unique_cwe_ids.add(cwe_id)
                    rule_entry["relationships"].append({
                        "target": { "toolComponent": {"name": "CWE"}, "id": cwe_id },
                        "kind": "relevant" 
                    })

        if "wstg" in details and details["wstg"]:
            wstg_list_for_rule = []
            if isinstance(details["wstg"], list):
                wstg_list_for_rule = details["wstg"]
            elif isinstance(details["wstg"], str):
                wstg_list_for_rule = [details["wstg"]]
            
            all_unique_wstg_ids.update(wstg_list_for_rule)
            
            for wstg_id_item in wstg_list_for_rule:
                rule_entry["relationships"].append({
                    "target": { "toolComponent": {"name": "OWASP WSTG"}, "id": wstg_id_item },
                    "kind": "relevant"
                })

        run_entry["tool"]["driver"]["rules"].append(rule_entry)
        rule_map[final_rule_id] = rule_entry 
    
    if default_rule_id not in [r["id"] for r in run_entry["tool"]["driver"]["rules"]]:
        run_entry["tool"]["driver"]["rules"].append({
            "id": default_rule_id,
            "name": "Wapiti General Finding",
            "fullDescription": {"text": "A general vulnerability or anomaly reported by Wapiti, or one without a specific classification in the report."}
        })


    all_findings = []
    vulnerabilities_section = wapiti_json_data.get("vulnerabilities", {})
    if isinstance(vulnerabilities_section, dict):
        for vuln_type_name, vuln_instances_list in vulnerabilities_section.items():
            if isinstance(vuln_instances_list, list):
                for instance in vuln_instances_list:
                    if isinstance(instance, dict):
                        instance["_wapiti_type_name"] = vuln_type_name
                        all_findings.append(instance)
                        if "wstg" in instance and instance["wstg"]:
                            if isinstance(instance["wstg"], list):
                                all_unique_wstg_ids.update(instance["wstg"])
                            elif isinstance(instance["wstg"], str):
                                all_unique_wstg_ids.add(instance["wstg"])

    anomalies_list = wapiti_json_data.get("anomalies", [])
    if isinstance(anomalies_list, list):
        for anomaly in anomalies_list:
            if isinstance(anomaly, dict):
                if "info" in anomaly and "error" in anomaly["info"].lower():
                    anomaly["_wapiti_type_name"] = "Internal Server Error"
                else:
                    anomaly["_wapiti_type_name"] = "Anomaly"
                all_findings.append(anomaly)
                if "wstg" in anomaly and anomaly["wstg"]:
                    if isinstance(anomaly["wstg"], list):
                        all_unique_wstg_ids.update(anomaly["wstg"])
                    elif isinstance(anomaly["wstg"], str):
                        all_unique_wstg_ids.add(anomaly["wstg"])

    if all_unique_wstg_ids:
        run_entry["taxonomies"].append(_build_wstg_taxonomy_entry(all_unique_wstg_ids))
    
    if all_unique_cwe_ids:
        run_entry["taxonomies"].append(_build_cwe_taxonomy_entry(all_unique_cwe_ids))

    for finding in all_findings:
        sarif_level = finding.get("level", 0) 

        found_rule_id = default_rule_id 
        type_name = finding.get("_wapiti_type_name", "")
        if type_name:
            potential_id_prefix = f"wapiti-{type_name.lower().replace(' ', '-')}"
            
            for r_obj in run_entry["tool"]["driver"]["rules"]:
                if r_obj["id"].startswith(potential_id_prefix):
                    found_rule_id = r_obj["id"]
                    break

        web_request = {}
        raw_request_text = finding.get("http_request", "")
        if raw_request_text:
            request_lines = raw_request_text.split('\n')
            
            req_protocol = "HTTP"
            req_version = "1.1"
            req_method = finding.get("method", "GET")
            req_target = finding.get("path", target_base_uri)
            req_headers = {}
            req_body_text = ""

            if request_lines:
                first_line_match = re.match(r"(\w+)\s+(\S+)\s+(HTTP\/(\d\.\d))", request_lines[0])
                if first_line_match:
                    req_method = first_line_match.group(1)
                    request_path_query = first_line_match.group(2)
                    req_protocol = first_line_match.group(3).split('/')[0]
                    req_version = first_line_match.group(4)

                    if not request_path_query.startswith(('http://', 'https://')):
                            parsed_base_uri = re.match(r"(https?:\/\/[^\/]+)", target_base_uri)
                            if parsed_base_uri:
                                req_target = parsed_base_uri.group(0) + request_path_query
                            else:
                                req_target = request_path_query
                    else:
                        req_target = request_path_query
                
                header_body_separator_found = False
                for line in request_lines[1:]:
                    if not line.strip():
                        header_body_separator_found = True
                        continue
                    
                    if not header_body_separator_found:
                        if ': ' in line:
                            header_name, header_value = line.split(': ', 1)
                            req_headers[header_name.strip()] = header_value.strip()
                    else:
                        req_body_text += line + '\n'
            
            web_request["protocol"] = req_protocol
            web_request["version"] = req_version
            web_request["target"] = req_target
            web_request["method"] = req_method
            web_request["headers"] = req_headers
            
            if req_body_text.strip():
                web_request["body"] = {"text": req_body_text.strip()}
            else:
                web_request["body"] = {}


        web_response = {
            "statusCode": finding.get("detail", {}).get("response", {}).get("status_code", 0),
            "reasonPhrase": "",
            "protocol": "HTTP",
            "version": "1.1",
            "headers": {}
        }

        raw_response_body = finding.get("detail", {}).get("response", {}).get("body", "")
        if raw_response_body:
            decoded_body = raw_response_body.replace("&#x2f;", "/").replace("&#x3a;", ":").replace("&#xa;", "\n").replace("&#x3b;", ";").replace("&#x3d;", "=")
            web_response["body"] = {"text": decoded_body}
        else:
            web_response["body"] = {}
        
        response_headers_list = finding.get("detail", {}).get("response", {}).get("headers", [])
        resp_headers_dict = {}
        for header_pair in response_headers_list:
            if isinstance(header_pair, list) and len(header_pair) == 2:
                resp_headers_dict[header_pair[0].strip()] = header_pair[1].strip()
        web_response["headers"] = resp_headers_dict

        result_entry = {
            "level": sarif_level,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("path", target_base_uri)
                        },
                        "region": {
                            "startLine": 1,
                            "properties": {
                                "comment": "Start line is an estimation as Wapiti doesn't provide specific line numbers."
                            }
                        },
                        "properties": {
                            "attack_parameter": finding.get("parameter", "N/A")
                        }
                    }
                }
            ],
            "message": {
                "text": finding.get("info", "No information provided.")
            },
            "ruleId": found_rule_id
        }
        
        result_entry_relationships = []
        
        wstg_list_for_result = []
        if "wstg" in finding and finding["wstg"]:
            if isinstance(finding["wstg"], list):
                wstg_list_for_result = finding["wstg"]
            elif isinstance(finding["wstg"], str):
                wstg_list_for_result = [finding["wstg"]]
            
            for wstg_id_item in wstg_list_for_result:
                result_entry_relationships.append({
                    "target": {
                        "toolComponent": {"name": "OWASP WSTG"},
                        "id": wstg_id_item
                    },
                    "kind": "relevant"
                })
        
        if result_entry_relationships:
            result_entry["relationships"] = result_entry_relationships


        if web_request:
            result_entry["webRequest"] = web_request
        if web_response["statusCode"] or web_response["headers"] or web_response["body"]:
            result_entry["webResponse"] = web_response

        run_entry["results"].append(result_entry)

    sarif_data["runs"].append(run_entry)
    return sarif_data

# -----------------------------------------------------------------------------

## --- Các hàm từ merge_sarif.py (đã sửa đổi để nhận dữ liệu Wapiti trong bộ nhớ) ---

def merge_sarif_reports(zap_sarif_filepath: str, wapiti_sarif_data: dict, output_sarif_filepath: str):
    """
    Hợp nhất các phần 'runs.results', 'runs.taxonomies' và 'runs.tool.driver'
    từ một báo cáo SARIF của ZAP (từ tệp) và dữ liệu SARIF của Wapiti (trong bộ nhớ)
    vào một báo cáo SARIF mới.

    Args:
        zap_sarif_filepath (str): Đường dẫn đến tệp SARIF của ZAP.
        wapiti_sarif_data (dict): Dữ liệu SARIF của Wapiti dưới dạng dictionary (đã chuyển đổi).
        output_sarif_filepath (str): Đường dẫn đến tệp SARIF đầu ra.
    """
    try:
        # 1. Đọc dữ liệu từ tệp SARIF của ZAP
        with open(zap_sarif_filepath, 'r', encoding='utf-8') as f:
            zap_data = json.load(f)
        
        # Dữ liệu Wapiti đã được truyền vào hàm dưới dạng dictionary
        wapiti_data = wapiti_sarif_data

        # Kiểm tra xem cả hai báo cáo có ít nhất một "run" không
        if not zap_data.get("runs") or not zap_data["runs"]:
            print(f"❌ Lỗi: Tệp ZAP SARIF '{zap_sarif_filepath}' không chứa dữ liệu 'runs' hợp lệ.")
            return
        if not wapiti_data.get("runs") or not wapiti_data["runs"]:
            print(f"❌ Lỗi: Dữ liệu Wapiti SARIF trong bộ nhớ không chứa dữ liệu 'runs' hợp lệ.")
            return

        # Lấy "run" đầu tiên từ mỗi báo cáo
        zap_run = zap_data["runs"][0]
        wapiti_run = wapiti_data["runs"][0]

        # 2. Chuẩn bị cấu trúc SARIF đầu ra
        merged_sarif_data = {
            "$schema": zap_data.get("$schema", "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"),
            "version": zap_data.get("version", "2.1.0"),
            "runs": []
        }

        merged_run = {
            "results": [],
            "taxonomies": [],
            "tool": {
                "driver": {
                    "name": "Merged Report Driver",
                    "rules": []
                }
            }
        }

        # 3. Hợp nhất runs.results: ZAP trước, Wapiti sau
        if zap_run.get("results"):
            merged_run["results"].extend(zap_run["results"])
        if wapiti_run.get("results"):
            merged_run["results"].extend(wapiti_run["results"])

        # 4. Hợp nhất runs.taxonomies: ZAP trước, Wapiti sau (và xử lý trùng lặp)
        unique_taxonomies = {}

        if zap_run.get("taxonomies"):
            for tax in zap_run["taxonomies"]:
                if tax.get("name"):
                    unique_taxonomies[tax["name"]] = tax
        
        if wapiti_run.get("taxonomies"):
            for tax in wapiti_run["taxonomies"]:
                if tax.get("name") and tax["name"] not in unique_taxonomies:
                    unique_taxonomies[tax["name"]] = tax
                elif tax.get("name") and tax["name"] in unique_taxonomies:
                    existing_taxa_ids = {t.get('id') for t in unique_taxonomies[tax["name"]].get('taxa', [])}
                    for wapiti_taxa in tax.get('taxa', []):
                        if wapiti_taxa.get('id') not in existing_taxa_ids:
                            unique_taxonomies[tax["name"]].get('taxa', []).append(wapiti_taxa)
                            
        merged_run["taxonomies"] = list(unique_taxonomies.values())
        for tax in merged_run["taxonomies"]:
            if tax.get('taxa'):
                tax['taxa'].sort(key=lambda x: x.get('id', ''))

        # 5. Hợp nhất runs.tool.driver (rules): ZAP trước, Wapiti sau
        if zap_run.get("tool", {}).get("driver", {}).get("rules"):
            merged_run["tool"]["driver"]["rules"].extend(zap_run["tool"]["driver"]["rules"])
        
        zap_rule_ids = {r.get('id') for r in zap_run.get("tool", {}).get("driver", {}).get("rules", [])}
        
        if wapiti_run.get("tool", {}).get("driver", {}).get("rules"):
            for wapiti_rule in wapiti_run["tool"]["driver"]["rules"]:
                original_wapiti_rule_id = wapiti_rule.get('id')
                if original_wapiti_rule_id in zap_rule_ids:
                    wapiti_rule['id'] = f"wapiti-merged-{original_wapiti_rule_id}-{uuid.uuid4().hex[:4]}"
                    print(f"⚠️ Cảnh báo: Rule ID '{original_wapiti_rule_id}' trùng lặp. Đã đổi tên thành '{wapiti_rule['id']}'. "
                          f"Các results của Wapiti cần được cập nhật để trỏ đến ID mới này.")

                merged_run["tool"]["driver"]["rules"].append(wapiti_rule)

        merged_sarif_data["runs"].append(merged_run)

        # 6. Ghi báo cáo SARIF đã hợp nhất vào tệp đầu ra
        with open(output_sarif_filepath, 'w', encoding='utf-8') as f:
            json.dump(merged_sarif_data, f, indent=2, ensure_ascii=False)

        print(f"✅ Đã hợp nhất thành công từ '{zap_sarif_filepath}' và dữ liệu Wapiti trong bộ nhớ")
        print(f"   và lưu vào '{output_sarif_filepath}'")

    except FileNotFoundError as e:
        print(f"❌ Lỗi: Không tìm thấy tệp đầu vào ZAP: {e}")
    except json.JSONDecodeError as e:
        print(f"❌ Lỗi: Không thể phân tích cú pháp tệp JSON của ZAP. Đảm bảo tệp hợp lệ: {e}")
    except KeyError as e:
        print(f"❌ Lỗi: Cấu trúc tệp SARIF của ZAP không như mong đợi (thiếu khóa: {e}).")
    except Exception as e:
        print(f"❌ Đã xảy ra lỗi không mong muốn khi hợp nhất: {e}")

# -----------------------------------------------------------------------------

## 🚀 Script Chính để Điều phối (đã cập nhật cho CLI)

def orchestrate_sarif_conversion_and_merge(
    input_wapiti_json: str,
    input_zap_sarif: str,
    final_merged_sarif: str
):
    """
    Điều phối quá trình:
    1. Chuyển đổi wapiti.json sang định dạng SARIF (trong bộ nhớ).
    2. Hợp nhất dữ liệu SARIF của Wapiti (trong bộ nhớ) với zap_sarif.json thành merged_sarif.json.

    Args:
        input_wapiti_json (str): Đường dẫn đến tệp JSON gốc của Wapiti.
        input_zap_sarif (str): Đường dẫn đến tệp SARIF của ZAP.
        final_merged_sarif (str): Đường dẫn nơi tệp SARIF hợp nhất cuối cùng sẽ được lưu.
    """
    print(f"🚀 Bắt đầu quá trình điều phối...")

    # Bước 1: Chuyển đổi Wapiti JSON sang SARIF (trong bộ nhớ)
    print(f"\n--- Bước 1: Chuyển đổi '{input_wapiti_json}' sang SARIF trong bộ nhớ ---")
    sarif_converted_wapiti = None
    try:
        if not os.path.exists(input_wapiti_json):
            raise FileNotFoundError(f"Tệp Wapiti JSON không tìm thấy: {input_wapiti_json}")

        with open(input_wapiti_json, 'r', encoding='utf-8') as f:
            wapiti_data = json.load(f)
        
        sarif_converted_wapiti = wapiti_to_sarif_converter(wapiti_data)
        
        print(f"✅ Chuyển đổi Wapiti sang SARIF trong bộ nhớ thành công.")
    except FileNotFoundError as e:
        print(f"❌ Lỗi: {e}. Vui lòng kiểm tra đường dẫn.")
        return
    except json.JSONDecodeError:
        print(f"❌ Lỗi: Không thể phân tích cú pháp tệp JSON của Wapiti '{input_wapiti_json}'. Đảm bảo đó là định dạng JSON hợp lệ.")
        return
    except Exception as e:
        print(f"❌ Đã xảy ra lỗi khi chuyển đổi Wapiti sang SARIF: {e}")
        return

    # Kiểm tra nếu quá trình chuyển đổi Wapiti thất bại
    if sarif_converted_wapiti is None:
        print("🛑 Quá trình chuyển đổi Wapiti thất bại, không thể tiếp tục hợp nhất.")
        return

    # Bước 2: Hợp nhất các báo cáo SARIF
    print(f"\n--- Bước 2: Hợp nhất dữ liệu Wapiti trong bộ nhớ và '{input_zap_sarif}' ---")
    merge_sarif_reports(input_zap_sarif, sarif_converted_wapiti, final_merged_sarif)
    
    print(f"\n🎉 Quá trình điều phối đã hoàn tất. Báo cáo hợp nhất cuối cùng là: '{final_merged_sarif}'")


if __name__ == "__main__":
    # Tạo đối tượng ArgumentParser
    parser = argparse.ArgumentParser(
        description="Chuyển đổi báo cáo Wapiti sang SARIF và hợp nhất với báo cáo ZAP SARIF.",
        formatter_class=argparse.RawTextHelpFormatter # Giúp hiển thị mô tả với xuống dòng
    )

    # Định nghĩa các đối số mong đợi
    # Sử dụng tên đối số rõ ràng hơn để phân biệt input của Wapiti và ZAP
    parser.add_argument(
        '-w', '--wapiti-json', 
        type=str, 
        required=True,
        help="Đường dẫn đến tệp JSON gốc của Wapiti (ví dụ: wapiti.json)"
    )
    parser.add_argument(
        '-z', '--zap-sarif', 
        type=str, 
        required=True,
        help="Đường dẫn đến tệp SARIF của ZAP (ví dụ: zap_sarif.json)"
    )
    parser.add_argument(
        '-o', '--output', 
        type=str, 
        required=True,
        help="Đường dẫn đến tệp SARIF đầu ra đã hợp nhất (ví dụ: merged_report.json)"
    )

    # Phân tích cú pháp các đối số từ dòng lệnh
    args = parser.parse_args()

    # Gọi hàm điều phối chính với các đối số đã được phân tích cú pháp
    orchestrate_sarif_conversion_and_merge(
        input_wapiti_json=args.wapiti_json,
        input_zap_sarif=args.zap_sarif,
        final_merged_sarif=args.output
    )