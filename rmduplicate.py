import json
import os


def compare_api(quark_rule_list, generated_rule_list):
    
    for quark_rule in quark_rule_list:
        for generated_rule in generated_rule_list:
            api1_class = quark_rule["api"][0]["class"]
            api1_md = quark_rule["api"][0]["method"]
            api1_des = quark_rule["api"][0]["descriptor"]
            
            api2_class = generated_rule["api"][1]["class"]
            api2_md = generated_rule["api"][1]["method"]
            api2_des = generated_rule["api"][1]["descriptor"]
            
            if api1_class == api2_class and api1_md == api2_md and api1_des == api2_des:
                print("Duplicated rule detected!")
                print(json.dumps(generated_rule, indent=4))
                
    return

def load_rules(rule_dir_path):
    rule_list = []
    
    for rule in os.listdir(rule_dir_path):
        
        if not os.path.basename(rule).endswith(".json"):
            continue
        
        with open(os.path.join(rule_dir_path, rule), "r") as rule_file:
            rule_data = json.load(rule_file)
            rule_list.append(rule_data)
    
    return rule_list



if __name__ == "__main__":
    
    QUARK_RULE_DIR_PATH = "/Users/shaun/.quark-engine/quark-rules"
    GENERATED_RULES_DIR_PATH = "/Users/shaun/quark-rule-generate/test/data/rule_set1/"
    
    quark_rules = load_rules(QUARK_RULE_DIR_PATH)
    generated_rules = load_rules(GENERATED_RULES_DIR_PATH)
    
    compare_api(quark_rules, generated_rules)