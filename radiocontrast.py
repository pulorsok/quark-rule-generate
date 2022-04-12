
import os
import json

from parso import parse
from tqdm import tqdm
from generator.method_generator import MethodCombGenerator
from generator.api_generator import ApiGenerator
from quark.core.quark import Quark
from model.android_sample_model import AndroidSampleModel
from db.database import DataBase

MAX_SEARCH_LAYER = 3

db = DataBase()

class Radiocontrast():
    
    def __init__(self, apk_path, method):
        self.apk_model = AndroidSampleModel(apk_path)
        self.quark = Quark(apk_path)
        self.apk = self.quark.apkinfo
        self.method = self.apk.find_method(
            class_name=method[0], method_name=method[1], descriptor=method[2])
        
        if method == None:
            print("ERROR: start method or end method not found")
            return
        
        self.api_set = set()

    def method_recursive_search(self, method_set, depth=1):
        # Not found same method usage, try to find the next layer.
        depth += 1
        if depth > MAX_SEARCH_LAYER:
            return
        
        # Append first layer into next layer.
        next_level_set = method_set.copy()

        # Extend the xref from function into next layer.
        for md in next_level_set:
            if md[0].is_android_api():
                self.api_set.add(md[0])
                continue
            
            self.method_recursive_search(self.apk.lowerfunc(md[0]), depth)
                
    def find_apis_in_method(self):    
        lower_funcs = set(self.apk.lowerfunc(self.method))
        self.method_recursive_search(lower_funcs)
        
        print(f"Number of native APIs is {len(self.api_set)}")
            
            
             
        return
    
    def api_generate(self):
        api_generator = ApiGenerator(self.api_set)
        apis = list(api_generator.initialize())
        generator = MethodCombGenerator(self.apk_model)
        generator.first_stage_rule_generate(apis, apis)
        
        

def parse_api(method_str):

    classname = method_str.split("->")[0]
    method_name = method_str.split("->")[1].split("(")[0]
    descriptor = "(" + method_str.split("->")[1].split("(")[1]
    method = [classname, method_name, descriptor]
    
    return method

def export(apk, export_dir):
    result = db.find_rules_by_sample(apk.id)
    
    rules_num = len(result)

    tqdm.write(f"Rules number: {rules_num}")
    count = 1
    tqdm.write(f"Start export rule into {export_dir}")
    
    for obj in tqdm(result):
        rules = rule_obj_generate(obj, count)
        f_name = f"{str(count)}.json"
        path = os.path.join(export_dir, f_name)

        with open(path, "w") as f:
            json.dump(rules, f, indent=4)

        count += 1
    return

def rule_obj_generate(rule, f_name):

    api1 = rule["api1"]
    api2 = rule["api2"]
    cls1 = api1["class_name"]
    cls2 = api2["class_name"]
    md1 = api1["method_name"]
    md2 = api2["method_name"]
    des1 = api1["descriptor"]
    des2 = api2["descriptor"]

    description = f"{f_name}. {cls1}{md1}->{cls2}{md2}"
    rule_obj = {
        "crime": description,
        "permission": [],
        "api": [
            {
                "class": cls1,
                "method": md1,
                "descriptor": des1
            },
            {
                "class": cls2,
                "method": md2,
                "descriptor": des2
            }
        ],
        "score": 1,
        "label": []
    }
    return rule_obj


if __name__ == "__main__":
    
    APK_PATH = "/Users/shaun/quark-rule-generate/test/data/malware/BladeHawk.apk"
    METHOD = "Lcom/example/dat/a8andoserverx/MainService;->startUp(I)V"
    RULE_DIR = "/Users/shaun/quark-rule-generate/test/data/rule_set1"
    
    method = parse_api(METHOD)
    
    radiocontrast = Radiocontrast(APK_PATH, method)
    radiocontrast.find_apis_in_method()
    radiocontrast.api_generate()
    
    export(radiocontrast.apk_model, RULE_DIR)