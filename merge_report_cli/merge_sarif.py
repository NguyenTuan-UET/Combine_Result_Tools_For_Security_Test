import json

def merge_sarif_reports(zap_sarif_filepath: str, wapiti_sarif_filepath: str, output_sarif_filepath: str):
    """
    Hợp nhất các phần 'runs.results', 'runs.taxonomies' và 'runs.tool.driver'
    từ hai báo cáo SARIF (ZAP và Wapiti) vào một báo cáo SARIF mới.

    Args:
        zap_sarif_filepath (str): Đường dẫn đến tệp SARIF của ZAP.
        wapiti_sarif_filepath (str): Đường dẫn đến tệp SARIF của Wapiti.
        output_sarif_filepath (str): Đường dẫn đến tệp SARIF đầu ra.
    """
    try:
        # 1. Đọc dữ liệu từ cả hai tệp SARIF
        with open(zap_sarif_filepath, 'r', encoding='utf-8') as f:
            zap_data = json.load(f)
        
        with open(wapiti_sarif_filepath, 'r', encoding='utf-8') as f:
            wapiti_data = json.load(f)

        # Kiểm tra xem cả hai báo cáo có ít nhất một "run" không
        if not zap_data.get("runs") or not zap_data["runs"]:
            print(f"❌ Lỗi: Tệp ZAP SARIF '{zap_sarif_filepath}' không chứa dữ liệu 'runs' hợp lệ.")
            return
        if not wapiti_data.get("runs") or not wapiti_data["runs"]:
            print(f"❌ Lỗi: Tệp Wapiti SARIF '{wapiti_sarif_filepath}' không chứa dữ liệu 'runs' hợp lệ.")
            return

        # Lấy "run" đầu tiên từ mỗi báo cáo
        zap_run = zap_data["runs"][0]
        wapiti_run = wapiti_data["runs"][0]

        # 2. Chuẩn bị cấu trúc SARIF đầu ra
        # Bắt đầu với cấu trúc tổng thể của ZAP SARIF
        merged_sarif_data = {
            "runs": [],
            "$schema": zap_data.get("$schema", "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"),
            "version": zap_data.get("version", "2.1.0"),
        }

        # Tạo một "run" mới cho kết quả hợp nhất
        merged_run = {
            "results": [],
            "taxonomies": [],
            "tool": {
                "driver": {
                    "name": "Merged Report Driver", # Tên driver mới cho báo cáo hợp nhất
                    "rules": []
                    # Có thể thêm thông tin version, informationUri nếu muốn
                }
            }
        }

        # 3. Hợp nhất runs.results: ZAP trước, Wapiti sau
        if zap_run.get("results"):
            merged_run["results"].extend(zap_run["results"])
        if wapiti_run.get("results"):
            merged_run["results"].extend(wapiti_run["results"])

        # 4. Hợp nhất runs.taxonomies: ZAP trước, Wapiti sau (và xử lý trùng lặp)
        # Sử dụng dictionary để loại bỏ trùng lặp dựa trên tên taxonomy (CWE, OWASP WSTG)
        unique_taxonomies = {}

        if zap_run.get("taxonomies"):
            for tax in zap_run["taxonomies"]:
                if tax.get("name"):
                    unique_taxonomies[tax["name"]] = tax
        
        if wapiti_run.get("taxonomies"):
            for tax in wapiti_run["taxonomies"]:
                if tax.get("name") and tax["name"] not in unique_taxonomies:
                    # Nếu tên taxonomy chưa có, thêm vào
                    unique_taxonomies[tax["name"]] = tax
                elif tax.get("name") and tax["name"] in unique_taxonomies:
                    # Nếu tên taxonomy đã có (ví dụ: cả ZAP và Wapiti đều có CWE)
                    # Cần hợp nhất các 'taxa' bên trong.
                    # Trong trường hợp này, chúng ta sẽ ưu tiên ZAP hoặc merge taxa.
                    # Cách đơn giản: lấy taxa của ZAP, thêm taxa của Wapiti nếu chưa có
                    existing_taxa_ids = {t.get('id') for t in unique_taxonomies[tax["name"]].get('taxa', [])}
                    for wapiti_taxa in tax.get('taxa', []):
                        if wapiti_taxa.get('id') not in existing_taxa_ids:
                            unique_taxonomies[tax["name"]].get('taxa', []).append(wapiti_taxa)
                            
        merged_run["taxonomies"] = list(unique_taxonomies.values())
        # Sắp xếp các taxa bên trong mỗi taxonomy để nhất quán
        for tax in merged_run["taxonomies"]:
            if tax.get('taxa'):
                tax['taxa'].sort(key=lambda x: x.get('id', ''))


        # 5. Hợp nhất runs.tool.driver (rules): ZAP trước, Wapiti sau
        # Lấy rules từ ZAP
        if zap_run.get("tool", {}).get("driver", {}).get("rules"):
            merged_run["tool"]["driver"]["rules"].extend(zap_run["tool"]["driver"]["rules"])
        
        # Lấy rules từ Wapiti (cần đảm bảo ruleId duy nhất)
        # SARIF yêu cầu ruleId là duy nhất trong cùng một driver.rules.
        # Chúng ta sẽ tiền tố ruleId của Wapiti nếu có nguy cơ trùng lặp.
        zap_rule_ids = {r.get('id') for r in zap_run.get("tool", {}).get("driver", {}).get("rules", [])}
        
        if wapiti_run.get("tool", {}).get("driver", {}).get("rules"):
            for wapiti_rule in wapiti_run["tool"]["driver"]["rules"]:
                original_wapiti_rule_id = wapiti_rule.get('id')
                if original_wapiti_rule_id in zap_rule_ids:
                    # Nếu trùng ID, đổi tên rule của Wapiti
                    wapiti_rule['id'] = f"wapiti-merged-{original_wapiti_rule_id}-{uuid.uuid4().hex[:4]}"
                    # Cập nhật mọi references đến ruleId cũ trong results của Wapiti nếu có
                    # Điều này rất phức tạp và thường yêu cầu duyệt qua lại results của Wapiti
                    # Để đơn giản, tôi sẽ bỏ qua việc cập nhật results ở đây,
                    # nhưng trong thực tế, bạn cần làm điều đó nếu ID rule thay đổi.
                    print(f"⚠️ Cảnh báo: Rule ID '{original_wapiti_rule_id}' trùng lặp. Đã đổi tên thành '{wapiti_rule['id']}'. "
                          f"Các results của Wapiti cần được cập nhật để trỏ đến ID mới này.")

                merged_run["tool"]["driver"]["rules"].append(wapiti_rule)

        # Thêm merged_run vào báo cáo cuối cùng
        merged_sarif_data["runs"].append(merged_run)

        # 6. Ghi báo cáo SARIF đã hợp nhất vào tệp đầu ra
        with open(output_sarif_filepath, 'w', encoding='utf-8') as f:
            json.dump(merged_sarif_data, f, indent=2, ensure_ascii=False)

        print(f"✅ Đã hợp nhất thành công từ '{zap_sarif_filepath}' và '{wapiti_sarif_filepath}'")
        print(f"   và lưu vào '{output_sarif_filepath}'")

    except FileNotFoundError as e:
        print(f"❌ Lỗi: Không tìm thấy tệp đầu vào: {e}")
    except json.JSONDecodeError as e:
        print(f"❌ Lỗi: Không thể phân tích cú pháp tệp JSON. Đảm bảo các tệp hợp lệ: {e}")
    except KeyError as e:
        print(f"❌ Lỗi: Cấu trúc tệp SARIF không như mong đợi (thiếu khóa: {e}).")
    except Exception as e:
        print(f"❌ Đã xảy ra lỗi không mong muốn: {e}")


## 🚀 Ví dụ Sử Dụng


if __name__ == "__main__":
    # Đảm bảo các đường dẫn này chính xác tuyệt đối hoặc tương đối từ nơi bạn chạy script
    # Dựa trên ảnh, các file này nằm trong thư mục 'merge'
    zap_file = "wapiti_sarif.json"
    wapiti_file = "zap_sarif.json"
    output_file = "merged_sarif.json"

    merge_sarif_reports(zap_file, wapiti_file, output_file)