import os
import glob
import subprocess

# 현재 디렉토리에서 .exe 파일 찾기
exe_files = glob.glob("./aspack_fail_samples_unpacked/*.exe")
#input_files = glob.glob("./valid_parse_files/_input.txt")
for exe_file in exe_files:
    try:
        # input 파일 이름 만들기
        input_file = exe_file.replace(".exe", "_input.txt")
        input_file = input_file.replace("aspack_fail_samples_unpacked", "valid_parse_files")
        input_file = input_file.replace(".Restored", "")
        # input 파일에서 데이터 읽어오기
        print(input_file)
        with open(input_file, "r") as f:
            input_data = f.read()
        # 프로그램 실행 명령어와 인자
        print(exe_file)
        print(input_data)
        
        command = [exe_file]
        
    
        # Popen 객체 생성 및 stdin, stdout 설정
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        # 입력 데이터 전송
        output, error = process.communicate(input=input_data.encode('utf-8'), timeout=30)
        with open(exe_file.replace('.exe', '.txt'), 'w') as f:
            f.write(output.decode('utf-8').replace('\n', ''))
            

    except Exception as E:
        continue