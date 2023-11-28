from androguard.misc import *
import os
import gc
import json
import re
import subprocess
import shutil
environment_constant = {'APKS_FOLDER':"apks", 'OUT_FOLDER':"out", "RULE_PATH": "rules"} # 폴더 이름 저장해 놓는 상수 딕셔너리
class Node:
    total_node = 0

    def __init__(self, class_name):
        self.class_name = class_name
        self.methods = []
        Node.total_node +=1

    def addMethod(self, method):
        if method not in self.methods:
            self.methods.append(method)


def extract_jsinterface(APK_NAME): # apk에서 @javascriptinterface annotation이 붙은 메소드 객체들을 추출함
    androguard_apk_obj, androguard_d_array,androguard_dx = AnalyzeAPK(environment_constant['APKS_FOLDER']+'/'+APK_NAME + '.apk', session = None)
    EncodedMethodList = []
    MethodAnalysisList = []
    for dvm in androguard_d_array:
        for adi in dvm.map_list.get_item_type("TYPE_ANNOTATIONS_DIRECTORY_ITEM"):
            if adi.get_method_annotations() == []:
                continue
            for mi in adi.get_method_annotations():
                ann_set_item = dvm.CM.get_obj_by_offset(mi.get_annotations_off())
                for aoffitem in ann_set_item.get_annotation_off_item():
                    annotation_item = dvm.CM.get_obj_by_offset(aoffitem.get_annotation_off())
                    encoded_annotation = annotation_item.get_annotation()
                    if "Landroid/webkit/JavascriptInterface" in str(dvm.CM.get_type(encoded_annotation.get_type_idx())):
                        #print(type(dvm.get_method_by_idx(mi.get_method_idx())))
                        EncodedMethodList.append(dvm.get_method_by_idx(mi.get_method_idx()))


    interface_and_method = list()

    for encoded_method in EncodedMethodList:
            class_name = encoded_method.get_class_name()
            
            class_exist = False

            for node in interface_and_method:
                if class_name == node.class_name:
                    node.addMethod(encoded_method)
                    class_exist = True
                    break

            if not class_exist:
                temp = Node(class_name)
                temp.addMethod(encoded_method)
                interface_and_method.append(temp)

    return interface_and_method # Node 객체로 저장된 메소드 리스트들을 반환

def convert_signature(signature):
        # Java 형식의 시그니처에서 '/'를 '.'으로 대체하고, L과 ;를 제거
        return signature.replace('/', '.')[1:-1]
def parse_and_convert_method_signature(signature_string):

    # 정규표현식을 사용하여 파라미터와 반환 변수 추출
    pattern = r'\((.*?)\)(.*)'
    match = re.match(pattern, signature_string)
    
    if match:
        parameters = match.group(1).split(',')
        parameters = [convert_signature(param.strip()) for param in parameters if param.strip()]  # 각 파라미터에 convert_signature 적용
        return_type = convert_signature(match.group(2).strip())
        
        return parameters, return_type
    else:
        return None, None

def write_template(class_name, method,APK_NAME): # 추출된 메소드들의 정보를 기반으로 taint analysis를 위한 sink & source template을 작성
    parameters, return_type = parse_and_convert_method_signature(method.get_descriptor())
    if(not(return_type)):
        return_type = "void"
    # 주어진 JSON 데이터
    json_data = {
        f"{method.get_name()}": {
            "enable": True,
            "DirectMode": True,
            "traceDepth": 6,
            "desc": {
                "name": f"{method.get_name()}",
                "category": "interface_analysis",
                "detail": "identify if it's a vulnerable Javascript interface",
                "class_name": f"{convert_signature(class_name)}"
            },
            "entry": {
                "methods": [
                    f"<{convert_signature(class_name)}: {return_type} {method.get_name()}(*)>"
                ]
            },
            "source": {
                "Param": {
                    f"<{convert_signature(class_name)}: {return_type} {method.get_name()}(*)>": [
                        "p*"
                    ]
                }
            },
            "sink": {
                "<*: * loadUrl*(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                "<*: * makeText*(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                }
            }
        }
    }

    # JSON 파일에 쓰기
    current_directory = os.getcwd()

    rule_folder_path = os.path.join(current_directory,environment_constant['OUT_FOLDER'], APK_NAME, environment_constant['RULE_PATH'])

    with open(f'{rule_folder_path}/{method.get_name()}.json', 'w') as json_file:
        json.dump(json_data, json_file, indent=2) 

def make_analysis_template(interface_and_method,APK_NAME): # 앱에서 taint analysis를 위한 template을 작성하기 위해 write_template를 호출
    for node in interface_and_method:
        print('[class]:', node.class_name)
        for method in node.methods:
            print('\t ->', method.get_name())
            print('\t\t->', method.get_descriptor())
            write_template(node.class_name, method,APK_NAME)

def create_json_config(APK_NAME): # AppShark 툴이 작동하기 위해 rule과 apk 파일 위치들을 정의하는 JSON 파일 생성

    current_directory = os.getcwd()
    apk_path = os.path.join(current_directory,environment_constant['APKS_FOLDER'],APK_NAME + '.apk')
    rule_path = os.path.join(current_directory, environment_constant['OUT_FOLDER'],APK_NAME, environment_constant['RULE_PATH'])
    out_path = os.path.join(current_directory,environment_constant['OUT_FOLDER'],APK_NAME)

    json_content = {
        "apkPath": apk_path,
        "rulePath": rule_path,
        "javaSource": True,
        "out": out_path
        # 여기에 필요한 다른 속성 추가 가능
    }

    json_file_path = os.path.join(out_path, f'{APK_NAME}_config.json')

    

    print(f'[*] {json_file_path} 생성')
    with open(json_file_path, 'w') as json_file:    
        json.dump(json_content, json_file, indent=2)

    return json_file_path

def run_appshark(config_file_path): # CLI 명령어를 사용해서 AppShark 실행
    command = f'java -jar build/libs/AppShark-0.1.2-all.jar {config_file_path}'

    subprocess.run(command,shell=True, stdout=subprocess.PIPE)


def make_structure(APK_NAME): # 앱마다 분석을 위해 폴더들을 미리생성함
    current_directory = os.getcwd()

    output_folder_path = os.path.join(current_directory,environment_constant['OUT_FOLDER'])

    if not os.path.exists(output_folder_path):
        os.makedirs(output_folder_path)
        print(f"[*]'{environment_constant['OUT_FOLDER']}' 폴더가 생성되었습니다.")

    
    apk_folder_path = os.path.join(output_folder_path, APK_NAME)
    if not os.path.exists(apk_folder_path):
        os.makedirs(apk_folder_path)
        print(f"[*]'{environment_constant['OUT_FOLDER']}/{APK_NAME}' 폴더가 생성되었습니다.")
    
    rule_folder_path = os.path.join(apk_folder_path, environment_constant['RULE_PATH'])

    if not os.path.exists(rule_folder_path):
        os.makedirs(rule_folder_path)
        print(f"[*]'{environment_constant['OUT_FOLDER']}/{APK_NAME}/{environment_constant['RULE_PATH']}' 폴더가 생성되었습니다.")

def analyze_apk(TEMP_APK): # APK 마다 method들을 추출하여 AppShark 실행

    make_structure(TEMP_APK)
    
    extracted_JSinterface = extract_jsinterface(TEMP_APK)
    make_analysis_template(extracted_JSinterface,TEMP_APK)

    config_file_path = create_json_config(TEMP_APK)

    run_appshark(config_file_path)



def make_result(APK_NAME): # AppShark를 실행시켜 나온 결과를 기반으로 간단하게 취약한 인터페이스 메소드만 정리함
    current_directory = os.getcwd()

    result_path = os.path.join(current_directory,environment_constant['OUT_FOLDER'],APK_NAME,'results.json')
    vuln_list_path= os.path.join(current_directory,environment_constant['OUT_FOLDER'],APK_NAME,'vuln_list.json')

    with open(result_path, 'r') as file:
        json_data = json.load(file)

    result_json = {
        "APK_NAME": f"{APK_NAME}",
        "Vulnerable_Method": {

        }
    }
    for method in json_data['SecurityInfo']['interface_analysis']:
        result_json['Vulnerable_Method'][method] = dict()
        result_json['Vulnerable_Method'][method]['Source'] = json_data['SecurityInfo']['interface_analysis'][method]['vulners'][0]['details']['Source']
        result_json['Vulnerable_Method'][method]['Sink'] = json_data['SecurityInfo']['interface_analysis'][method]['vulners'][0]['details']['Sink']

    with open(vuln_list_path, 'w') as json_file:
        json.dump(result_json, json_file, indent=2) 

            
            

def main():
    current_directory = os.getcwd()
    apk_files_path = os.path.join(current_directory,environment_constant['APKS_FOLDER'])

    apk_files = [f for f in os.listdir(apk_files_path) if f.endswith(".apk")]
    print(apk_files)

    for APK_NAME in apk_files:
        APK_NAME = APK_NAME[:-4] # '.apk' 제거

        decompiled_java_path = os.path.join(current_directory,environment_constant['OUT_FOLDER'],APK_NAME,'java')

        analyze_apk(APK_NAME)
        make_result(APK_NAME)

        shutil.rmtree(decompiled_java_path) # 디컴파일 된 자바 코드 삭제(용량 확보)


if __name__ == "__main__":
    
    main()