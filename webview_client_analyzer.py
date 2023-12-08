from androguard.misc import *
import os
import gc
import json
import re
import subprocess
import shutil
import time
environment_constant = {'APKS_FOLDER':"popular", 'OUT_FOLDER':"out_webviewClient", "RULE_PATH": "rules", 'LIST_PATH':'list.txt','ERROR_PATH':'error.txt'} # 폴더 이름 저장해 놓는 상수 딕셔너리
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


def create_json_config(APK_NAME): # AppShark 툴이 작동하기 위해 rule과 apk 파일 위치들을 정의하는 JSON 파일 생성

    current_directory = os.getcwd()
    apk_path = os.path.join(current_directory,environment_constant['APKS_FOLDER'],APK_NAME + '.apk')
    rule_path = './config/rules'
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

    config_file_path = create_json_config(TEMP_APK)

    run_appshark(config_file_path)

    if not os.path.exists(result_path): 
        raise AppSharkError()


def make_result(APK_NAME): # AppShark를 실행시켜 나온 결과를 기반으로 간단하게 취약한 인터페이스 메소드만 정리함
    current_directory = os.getcwd()

    result_path = os.path.join(current_directory,environment_constant['OUT_FOLDER'],APK_NAME,'results.json')
    vuln_list_path= os.path.join(current_directory,'vuln_list.json')

    if not os.path.exists(vuln_list_path):
        with open(vuln_list_path, 'w'):
            pass
        print(f"[*]'{vuln_list_path}' 파일이 생성되었습니다.")

    with open(vuln_list_path, 'r') as file:
        try:
            existing_data = json.load(file)
        except:
            existing_data = {}
    
    with open(result_path, 'r', encoding='utf-8') as file:
        json_data = json.load(file)

    result_json = {
        f"{APK_NAME}": {
            
        }
    }
    if 'SecurityInfo' in json_data.keys():
        for theme in json_data['SecurityInfo']['redirection']:
            idx = 0
            for details in json_data['SecurityInfo']['redirection'][theme]['vulners']:
                print(theme)
                print(details['details']['Sink'])
                print(details['details']['Source'])
            
                temp_theme = theme + str(idx)
                result_json[APK_NAME][temp_theme] = dict()
                result_json[APK_NAME][temp_theme]['Sink'] = details['details']['Sink']
                result_json[APK_NAME][temp_theme]['Source'] = details['details']['Source']
                idx +=1

        existing_data.update(result_json)
        
        with open(vuln_list_path, 'w') as json_file:
            json.dump(existing_data, json_file, indent=2) 
        
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
        if os.path.exists(decompiled_java_path):
            shutil.rmtree(decompiled_java_path) # 디컴파일 된 자바 코드 삭제(용량 확보)

        gc.collect()


if __name__ == "__main__":
    main()
