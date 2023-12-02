from androguard.misc import *
import os
import gc
import json
import re
import subprocess
import shutil
import time
environment_constant = {'APKS_FOLDER':"apks", 'OUT_FOLDER':"out", "RULE_PATH": "rules", 'LIST_PATH':'list.txt','ERROR_PATH':'error.txt'} # 폴더 이름 저장해 놓는 상수 딕셔너리
class Node:
    total_node = 0

    def __init__(self, class_name):
        self.class_name = class_name
        self.methods = []
        Node.total_node +=1

    def addMethod(self, method):
        if method not in self.methods:
            self.methods.append(method)

class AppSharkError(Exception):
    def __init__(self, message="[*] AppShark can't analyze this apk"):
        self.message = message
        super().__init__(self.message)


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
                },
                "Return":[ "<android.content.SharedPreferences: * getAll*(*)>",
                          "<android.webkit.CookieManager: * getInstance(*)>","<android.webkit.CookieManager: * getCookie(*)>",
                          "<android.location.LocationManager: * getLastKnownLocation(*)>","<android.os.Environment: * getExternalFilesDir(*)>",
                          "<android.database.Cursor: * getColumnIndex*(*)>","<android.graphics.BitmapFactory: * decodeFile*(*)>"
                ]
            },
            "sink": {
                "<android.content.SharedPreferences: * getString*(*)>": {
                    "TaintCheck": [
                        "p0"
                    ]
                },
                "<*: * putString*(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                
                "<android.webkit.WebView: * loadUrl*(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                "<android.webkit.WebView: * loadData*(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                "<android.webkit.WebView: * postUrl*(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                "<android.webkit.CookieManager: * getCookie(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                "<android.webkit.CookieManager: * setCookie(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                "<android.content.Intent: * setData*(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                "<*: * openFile*(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                "<android.os.Environment: * getExternalFilesDir(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                "<android.app.Activity: * startActivity*(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                "<android.database.Cursor: * getColumnIndex*(*)>": {
                    "TaintCheck": [
                        "p*"
                    ]
                },
                "<android.graphics.BitmapFactory: * decodeFile*(*)>": {
                    "TaintCheck": [
                        "p0"
                    ]
                },
                f"<{convert_signature(class_name)}: {return_type} {method.get_name()}(*)>": {
                    "Taintcheck":[
                        "return"
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

    current_directory = os.getcwd()
    result_path = os.path.join(current_directory,environment_constant['OUT_FOLDER'],TEMP_APK,'results.json')

    make_structure(TEMP_APK)
    
    extracted_JSinterface = extract_jsinterface(TEMP_APK)
    make_analysis_template(extracted_JSinterface,TEMP_APK)

    config_file_path = create_json_config(TEMP_APK)

    run_appshark(config_file_path)

    if not os.path.exists(result_path): 
        raise AppSharkError()




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
    if 'SecurityInfo' in json_data.keys():
        for method in json_data['SecurityInfo']['interface_analysis']:
            result_json['Vulnerable_Method'][method] = dict()
            result_json['Vulnerable_Method'][method]['Source'] = json_data['SecurityInfo']['interface_analysis'][method]['vulners'][0]['details']['Source']
            result_json['Vulnerable_Method'][method]['Sink'] = json_data['SecurityInfo']['interface_analysis'][method]['vulners'][0]['details']['Sink']

        with open(vuln_list_path, 'w') as json_file:
            json.dump(result_json, json_file, indent=2) 

    return True

def check_list_error(analyzed_list_path, error_list_path):

    if not os.path.exists(analyzed_list_path):
        with open(analyzed_list_path, 'w'):
            pass
        print(f"[*]'{environment_constant['LIST_PATH']}' 파일이 생성되었습니다.")
    
    if not os.path.exists(error_list_path):
        with open(error_list_path, 'w'):
            pass
        print(f"[*]'{environment_constant['ERROR_PATH']}' 파일이 생성되었습니다.")

    with open(analyzed_list_path,'r')as f:
        analyzed_list = f.read()

    with open(error_list_path,'r')as f:
        error_list = f.read()

    return analyzed_list, error_list

            
            

def main():
    current_directory = os.getcwd()
    apk_files_path = os.path.join(current_directory,environment_constant['APKS_FOLDER'])
    analyzed_list_path = os.path.join(current_directory, environment_constant["LIST_PATH"])
    error_list_path = os.path.join(current_directory, environment_constant["ERROR_PATH"])

    analyzed_list, error_list = check_list_error(analyzed_list_path, error_list_path)

    apk_files = [f for f in os.listdir(apk_files_path) if f.endswith(".apk")]
    print(apk_files)

    for APK_NAME in apk_files:
        APK_NAME = APK_NAME[:-4] # '.apk' 제거

        if(APK_NAME in analyzed_list ):
            print(f'[*]{APK_NAME} already analyzed')
            continue
        elif(APK_NAME in error_list):
            print(f'[*]{APK_NAME} had error while analyzing.')
            continue

        decompiled_java_path = os.path.join(current_directory,environment_constant['OUT_FOLDER'],APK_NAME,'java')
        try:
            analyze_apk(APK_NAME)
        except:
            print('Error occured while analyzing APK')
            print('APK: ', APK_NAME)

            with open(error_list_path,'a')as f:
                f.write(f'{APK_NAME}\n')
            
            analysis_folder_path = os.path.join(current_directory,environment_constant["OUT_FOLDER"],APK_NAME)
            if os.path.exists(analysis_folder_path):
                shutil.rmtree(analysis_folder_path)
            continue
        
        make_result(APK_NAME)

        with open(analyzed_list_path,'a')as f:
            f.write(f'{APK_NAME}\n')

        shutil.rmtree(decompiled_java_path) # 디컴파일 된 자바 코드 삭제(용량 확보)

        gc.collect()


if __name__ == "__main__":
    main()
