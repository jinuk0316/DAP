@echo off
 :: BatchGotAdmin
 :-------------------------------------
 REM  --> Check for permissions
 >nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
 if '%errorlevel%' NEQ '0' (
     echo 관리자 권한을 요청하는 중입니다...
     goto UACPrompt
 ) else ( goto gotAdmin )

:UACPrompt
     echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
     echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
     exit /B

:gotAdmin
     if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
     pushd "%CD%"
     CD /D "%~dp0"
 :--------------------------------------

mkdir W1~82
mkdir W1~82\log
mkdir W1~82\good
mkdir W1~82\bad
mkdir W1~82\action
mkdir W1~82\SOLu

SET AccountScore=0
SET AccountScore3=0
SET AccountScore2=0
SET ServiceScore=0
SET ServiceScore1=0
SET ServiceScore2=0
SET ServiceScore3=0
SET PatchScore=0
SET PatchScore2=0
SET PatchScore3=0
SET LogScore=0
SET LogScore1=0
SET LogScore2=0
SET LogScore3=0
SET SecureScore=0
SET SecureScore2=0
SET SecureScore3=0

echo ============================================================윈도우 취약점 점검=========================================================== >>  W1~82\report.txt
echo 			                        [W-01] ~ [W-82]까지의 항목을 점검합니다. >>  W1~82\report.txt
echo. >>  W1~82\report.txt
echo 			 Windows Server 2012 R2를 기준으로 제작된 코드입니다.이하 버전에 대해서는 점검이 정상진행 되지 않을 수 있습니다. >>  W1~82\report.txt
echo 			 bad항목에서 번호 뒤에 S가 붙는 항목은 담당자와 상의하여 직접 점검해야하는 항목입니다. >>  W1~82\report.txt
echo 			 bad항목에서 번호 뒤에 SS가 붙으면 Windows Server 2012 이하 버전에서만 해당하기에 직접 점검해야 하는 항목입니다. >>  W1~82\report.txt

echo. >>  W1~82\report.txt

echo ===================================================================================================================================== >>  W1~82\report.txt

echo. >>  W1~82\report.txt

echo [W-01] Administrator 계정 이름 변경 >> W1~82\report.txt
echo. >>  W1~82\report.txt

net user > account.txt
net user > W1~82\log\[W-01]log.txt
net user >> W1~82\report.txt
echo. >>  W1~82\report.txt

type account.txt | find /I "Administrator" > NUL
if %errorlevel% EQU 0 (
	echo [W-01]  Administrator 계정이 존재함 - [취약] > W1~82\bad\[W-01]bad.txt 
	echo [W-01] 시작- 프로그램- 제어판- 관리도구- 로컬 보안 정책 - 로컬 정책 - 보안옵션 >> W1~82\action\[W-01]action.txt
	echo [W-01] 계정: Administrator 계정 이름 바꾸기를 유추하기 어려운 계정 이름으로 변경 >> W1~82\action\[W-01]action.txt
	echo [W-01]  Administrator 계정이 존재함 - [취약] >> W1~82\report.txt
	echo 시작- 프로그램- 제어판- 관리도구- 로컬 보안 정책 - 로컬 정책 - 보안옵션 >> W1~82\report.txt
	echo 계정: Administrator 계정 이름 바꾸기를 유추하기 어려운 계정 이름으로 변경 >> W1~82\report.txt

) else (
	echo [W-01] Administrator 계정이 존재하지 않음 - [양호] > W1~82\good\[W-01]good.txt
	echo [W-01] Administrator 계정이 존재하지 않음 - [양호] >> W1~82\report.txt
	SET/a AccountScore = %AccountScore%+12
	SET/a AccountScore3 = %AccountScore3%+1
)
echo. >>  W1~82\report.txt

del account.txt

echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-02] Guest 계정 상태 >>  W1~82\report.txt
echo. >>  W1~82\report.txt

net user guest > W1~82\log\[W-02]log.txt
net user guest | find "활성 계정" >>  W1~82\report.txt

echo. >>  W1~82\report.txt
net user guest | find "활성 계정" | find "아니요" > NUL
if %errorlevel% EQU  0 (
	echo [W-02] Guest 계정이 비활성화되어 있음 - [양호] >> W1~82\good\[W-02]good.txt 
	echo [W-02] Guest 계정이 비활성화되어 있음 - [양호] >>  W1~82\report.txt 	
	SET/a AccountScore = %AccountScore%+12
	SET/a AccountScore3 = %AccountScore3%+1	
) else (
	echo [W-02] Guest 계정이 활성화되어 있음 -  [취약] >> W1~82\bad\[W-02]bad.txt
	echo 시작- 실행- LUSRMGR.MSC 사용자- GUEST- 속성 계정 사용 안함에 체크 >> W1~82\action\[W-02]action.txt
	echo [W-02] Guest 계정이 활성화되어 있음 -  [취약] >>  W1~82\report.txt
	echo 시작- 실행- LUSRMGR.MSC 사용자- GUEST- 속성 계정 사용 안함에 체크 >>  W1~82\report.txt
)
echo. >>  W1~82\report.txt

echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-03] 불필요한 계정 제거 >>  W1~82\report.txt
echo. >>  W1~82\report.txt

net user > W1~82\log\[W-03]log.txt
net user >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-03] 불필요한 계정이 존재하는 경우 - [취약] > W1~82\bad\[W-03S]bad.txt
echo W1~82\log\[W-03]account.txt파일을 확인후 "net user 계정명 /delete" 을 입력하여 불필요한 계정을 제거하시오 > W1~82\action\[W-03]action.txt
echo 또한, 이 점검 부분에서 양호하다고 판단이 된다면 계정항목에 수동으로 3점을 부여해 주십시오. >> W1~82\action\[W-03]action.txt
echo [W-03] 불필요한 계정이 존재하는 경우 - [취약] >>  W1~82\report.txt
echo W1~82\log\[W-03]account.txt파일을 확인후 "net user 계정명 /delete" 을 입력하여 불필요한 계정을 제거하시오 >>  W1~82\report.txt
echo 또한, 이 점검 부분에서 양호하다고 판단이 된다면 계정항목에 수동으로 12점을 부여해 주십시오. >>  W1~82\report.txt

echo. >>  W1~82\report.txt

echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-04] 계정 잠금 임계값 설정

net accounts | find "임계값" > W1~82\log\[W-04]log.txt
net accounts | find "임계값" > thres.txt
net accounts | find "임계값" >>  W1~82\report.txt
echo. >>  W1~82\report.txt

for /f "tokens=3" %%a in (thres.txt) do set thres=%%a
if %thres% leq 5 (
	echo [W-04] 임계값이 5 이하값으로 설정되어 있음 - [양호] >> W1~82\good\[W-04]good.txt 
	echo [W-04] 임계값이 5 이하값으로 설정되어 있음 - [양호] >>  W1~82\report.txt 
	SET/a AccountScore = %AccountScore%+12
	SET/a AccountScore3 = %AccountScore3%+1
) else (
	echo [W-04] 임계값이 6 이상으로 설정되어 있음 - [취약] > W1~82\bad\[W-04]bad.txt
	echo 시작 - 실행 - secpol.msc - 계정 정책 - 계정 잠금 정책 >> W1~82\action\[W-04]action.txt
	echo 계정 잠금 임계값을 5이하로 설정  >> W1~82\action\[W-04]action.txt
	echo [W-04] 임계값이 6 이상으로 설정되어 있음 - [취약] >>  W1~82\report.txt
	echo 시작 - 실행 - secpol.msc - 계정 정책 - 계정 잠금 정책 >>  W1~82\report.txt
	echo 계정 잠금 임계값을 5이하로 설정  >>  W1~82\report.txt

)
echo. >>  W1~82\report.txt

del thres.txt

echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-05] 해독 가능한 암호화를 사용하여 암호 저장 해제

secedit /export /cfg secpol.txt   
echo f | Xcopy "secpol.txt" "W1~82\log\[W-05]log.txt"
type secpol.txt | find /I "ClearTextPassword" >>  W1~82\report.txt
echo. >>  W1~82\report.txt

type secpol.txt | find /I "ClearTextPassword" | find "0" > NUL
if %errorlevel% EQU 0 (
	echo [W-05] '사용 안 함'으로 설정되어 있음 - [양호] > W1~82\good\[W-05]good.txt
	echo [W-05] '사용 안 함'으로 설정되어 있음 - [양호] >>  W1~82\report.txt
	SET/a AccountScore = %AccountScore%+12
	SET/a AccountScore3 = %AccountScore3%+1
) else (
	echo [W-05] '사용'으로 설정되어 있음 - [취약] > W1~82\bad\[W-05]bad.txt
	echo 시작-실행-SECPOL.MSC-계정 정책-암호 정책 - 해독 가능한 암호화를 사용하여 암호 저장 설정 확인 해독 가능한 암호화를 사용하여 암호 저장을 사용 안 함으로 설정 >> W1~82\action\[W-05]action.txt
	echo [W-05] '사용'으로 설정되어 있음 - [취약] >>  W1~82\report.txt
	echo 시작-실행-SECPOL.MSC-계정 정책-암호 정책 - 해독 가능한 암호화를 사용하여 암호 저장 설정 확인 해독 가능한 암호화를 사용하여 암호 저장을 사용 안 함으로 설정 >>  W1~82\report.txt
)
echo. >>  W1~82\report.txt

del secpol.txt

echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-06] 관리자 그룹에 최소한의 사용자 포함 >>  W1~82\report.txt
echo. >>  W1~82\report.txt

net localgroup administrators | find /v "명령을 잘 실행했습니다." > W1~82\log\[W-06]log.txt
net localgroup administrators | find /v "명령을 잘 실행했습니다." >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-06] Administrators 그룹에 불필요한 관리자 계정이 존재하는 경우 - [취약] > W1~82\bad\[W-06S]bad.txt
echo W1~82\log\[W-06]log.txt 파일을 확인후 관리자 그룹에 포함된 불필요한 계정을 확인, 담당자와 상의하여 >> W1~82\action\[W-06]action.txt
echo 시작-실행-LUSRMGR.MSC-그룹-Administrators-속성-Administrators 그룹에서 불필요 계정 제거 후 그룹 변경 >> W1~82\action\[W-06]action.txt
echo 또한, 이 점검부분에서 양호하다고 판단이 된다면, 계정항목에 수동으로 12점을 부여해 주십시오. >> W1~82\action\[W-06]action.txt

echo [W-06] Administrators 그룹에 불필요한 관리자 계정이 존재하는 경우 - [취약] >>  W1~82\report.txt
echo W1~82\log\[W-06]log.txt 파일을 확인후 관리자 그룹에 포함된 불필요한 계정을 확인, 담당자와 상의하여 >>  W1~82\report.txt
echo 시작-실행-LUSRMGR.MSC-그룹-Administrators-속성-Administrators 그룹에서 불필요 계정 제거 후 그룹 변경 >>  W1~82\report.txt
echo 또한, 이 점검부분에서 양호하다고 판단이 된다면, 계정항목에 수동으로 점을 부여해 주십시오. >>  W1~82\report.txt

echo. >>  W1~82\report.txt

echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-07] 공유 권한 및 사용자 그룹 설정 >>  W1~82\report.txt
echo. >>  W1~82\report.txt

net share > W1~82\log\[W-07]log.txt
net share >>  W1~82\report.txt
echo. >>  W1~82\report.txt

echo [W-07] 일반 공유 디렉토리의 접근 권한에 Everyone 권한이 있는 경우 - [취약] > W1~82\bad\[W-07S]bad.txt
echo W1~82\log\[W-07]log.txt 파일에서 공유가 진행되고 있는 폴더 목록을 확인후 사용 권한에서 Everyone으로 된 공유를 제거 >> W1~82\action\[W-07]action.txt
echo 시작-실행-FSMGMT.MSC-공유-사용 권한에서 Everyone으로 된 공유를 제거하고 접근이 필요한 계정의 적절한 권한 추가 >> W1~82\action\[W-07]action.txt
echo 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 12점을 부여해 주십시오. >> W1~82\action\[W-07]action.txt

echo [W-07] 일반 공유 디렉토리의 접근 권한에 Everyone 권한이 있는 경우 - [취약] >>  W1~82\report.txt
echo W1~82\log\[W-07]log.txt 파일에서 공유가 진행되고 있는 폴더 목록을 확인후 사용 권한에서 Everyone으로 된 공유를 제거 >>  W1~82\report.txt
echo 시작-실행-FSMGMT.MSC-공유-사용 권한에서 Everyone으로 된 공유를 제거하고 접근이 필요한 계정의 적절한 권한 추가 >>  W1~82\report.txt
echo 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 12점을 부여해 주십시오. >>  W1~82\report.txt

echo. >>  W1~82\report.txt

echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-08] 하드디스크 기본 공유 제거 >> W1~82\report.txt
SET/a W8S=0

net share > log.txt
net share | find /v "명령을 잘 실행했습니다." > W1~82\log\[W-08]log.txt

type log.txt | findstr /I "C$ D$ IPC$" > NUL
if %errorlevel% EQU 0 (
	echo [W-08] 하드디스크 기본 공유 제거됨 - [양호] > W1~82\good\[W-08]good.txt
	echo [W-08] 하드디스크 기본 공유 제거됨 - [양호] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+6
	SET/a W8S=1
) else (
	echo [W-08] 하드디스크 기본 공유 제거 안 됨 - [취약] > W1~82\bad\[W-08]bad.txt
	echo [W-08] 하드디스크 기본 공유 제거 안 됨 - [취약] >> W1~82\report.txt
	echo [W-08]log.txt 파일을 확인하고 하드디스크 기본 공유를 제거하시오 > W1~82\action\[W-08]action.txt
	echo 시작-실행-FSMGMT.MSC-공유-기본공유선택-마우스 우클릭-공유 중지 >>  W1~82\action\[W-08]action.txt
	echo [W-08]log.txt 파일을 확인하고 하드디스크 기본 공유를 제거하시오 >> W1~82\report.txt
	echo 시작-실행-FSMGMT.MSC-공유-기본공유선택-마우스 우클릭-공유 중지 >> W1~82\report.txt
)

del log.txt

reg query "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" | findstr /I "autoshare" >> W1~82\log\[W-08-2]log.txt
reg query "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" | findstr /I "autoshare" >> reg.txt

type reg.txt | find "0x0"
if %errorlevel% EQU 0 (
	echo [W-08] 하드디스크 기본 공유 레지스트리 값 0 - [양호] > W1~82\good\[W-08]good.txt 
	echo [W-08] 하드디스크 기본 공유 레지스트리 값 0 - [양호]  >> W1~82\report.txt 
	SET/a ServiceScore = %ServiceScore%+6
	SET/a W8S=1
) else (
	echo [W-08] 하드디스크 기본 공유 레지스트리 값 0 아님 - [취약] >> W1~82\bad\[W-08]bad.txt
	echo [W-08] 하드디스크 기본 공유 레지스트리 값 0 아님 - [취약] >> W1~82\report.txt
	echo [W-08] 하드디스크 기본 공유 레지스트리 값 0으로 변경하십시오 >>  W1~82\action\[W-08]action.txt
	echo [W-08] 하드디스크 기본 공유 레지스트리 값 0으로 변경하십시오 >> W1~82\report.txt
	echo 시작-실행-REGEDIT >>  W1~82\action\[W-08]action.txt
	echo 시작-실행-REGEDIT>> W1~82\report.txt
	echo 아래 레지스트리 값을 0으로 수정 (키값이 없을 경우 새로 생성) >> W1~82\action\[W-08]action.txt
	echo 아래 레지스트리 값을 0으로 수정 (키값이 없을 경우 새로 생성) >> W1~82\report.txt
	echo “HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\AutoShareServer” >> W1~82\action\[W-08]action.txt
	echo “HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters\AutoShareServer” >> W1~82\report.txt
)
if %W8S% EQU 1 (
	SET/a ServiceScore3 = %ServiceScore3%+1
)

del reg.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-09] 불필요한 서비스 제거  >> W1~82\report.txt
net start > W1~82\log\[W-09]log.txt

echo [W-09] 일반적으로 불필요한 서비스(아래 목록 참고)가 구동 중인 경우 - [취약] > W1~82\bad\[W-09S]bad.txt
echo W1~82\log\[W-09]log.txt 파일을 확인하고 불필요한 서비스 제거하세요(가이드 내 표 참고) >> W1~82\action\[W-09]action.txt
echo 시작-실행-SERVICES.MSC-‘해당 서비스’선택-속성, 시작 유형-사용안함, 서비스 상태-중지설정으로 불필요한 서비스 중지 >> W1~82\action\[W-09]action.txt
echo 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 12점을 부여해 주십시오. >> W1~82\action\[W-09]action.txt

echo [W-09] 일반적으로 불필요한 서비스(아래 목록 참고)가 구동 중인 경우 - [취약] >> W1~82\report.txt
echo W1~82\log\[W-09]log.txt 파일을 확인하고 불필요한 서비스 제거하세요(가이드 내 표 참고) >> W1~82\report.txt
echo 시작-실행-SERVICES.MSC-‘해당 서비스’선택-속성, 시작 유형-사용안함, 서비스 상태-중지설정으로 불필요한 서비스 중지 >> W1~82\report.txt
echo 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 12점을 부여해 주십시오. >>  W1~82\report.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-10] IIS서비스 구동 점검 >> W1~82\report.txt


net start > W1~82\log\[W-10]log.txt

type W1~82\log\[W-10]log.txt | find /i "IIS ADMIN Service" >nul 2>&1
if %errorlevel% EQU 0 (
  echo [W-10] IIS서비스가 필요하지 않지만 사용하는 경우 - [취약] > W1~82\bad\[W-10]bad.txt
  echo 담당자와 상의 후 IIS 서비스가 불필요할 시 >> W1~82\action\[W-10]action.txt
  echo 시작-실행-SERVICE.MSC-IISADMIN-속성-시작 유형을 사용 안함 설정 후 중지로 IIS 서비스 중지 >> W1~82\action\[W-10]action.txt

  echo [W-10] IIS서비스가 필요하지 않지만 사용하는 경우 - [취약]  >> W1~82\report.txt
  echo 담당자와 상의 후 IIS 서비스가 불필요할 시  >> W1~82\report.txt
  echo 시작-실행-SERVICE.MSC-IISADMIN-속성-시작 유형을 사용 안함 설정 후 중지로 IIS 서비스 중지  >> W1~82\report.txt
) else (
  echo [W-10] IIS서비스가 필요하지 않아 이용하지 않는 경우 - [양호] > W1~82\good\[W-10]good.txt 
  echo [W-10] IIS서비스가 필요하지 않아 이용하지 않는 경우 - [양호]  >> W1~82\report.txt
  SET/a ServiceScore = %ServiceScore%+12
  SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-11] 디렉토리 리스팅 제거 >> W1~82\report.txt

type C:\inetpub\wwwroot\web.config | find /i "directoryBrowse" > W1~82\log\[W-11]log.txt
type C:\inetpub\wwwroot\web.config | find /i "directoryBrowse" > inform.txt

type inform.txt | find /i "false"
if %errorlevel% equ 0 (
	echo [W-11] 디렉토리 검색이 사용 안 함으로 설정되어 있음 - [양호] > W1~82\good\[W-11]good.txt
	echo [W-11] 디렉토리 검색이 사용 안 함으로 설정되어 있음 - [양호] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
) else (
	echo [W-11] 디렉토리 검색이 사용으로 설정되어 있음 - [취약] > W1~82\bad\[W-11]bad.txt
	echo [W-11] 제어판-관리도구-인터넷정보서비스 IIS관리-해당 웹 사이트-IIS-디렉토리 검색 선택-사용 안함 선택 >> W1~82\action\[W-11]action.txt
	echo [W-11] 디렉토리 검색이 사용으로 설정되어 있음 - [취약]  >> W1~82\report.txt
	echo [W-11] 제어판-관리도구-인터넷정보서비스 IIS관리-해당 웹 사이트-IIS-디렉토리 검색 선택-사용 안함 선택  >> W1~82\report.txt
)

del  inform.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-12] IIS CGI 실행 제한(scripts 존재여부) >> W1~82\report.txt
SET/a W12S=0

dir C:\inetpub /b > W1~82\log\[W-12]log.txt

type W1~82\log\[W-12]log.txt | find /I "scripts" > nul 
if %errorlevel% EQU 0 (
	echo [W-12] 해당 디렉토리에 scripts 파일이 존재할경우 설정값 - [취약] > W1~82\bad\[W-12]bad.txt 
	echo [W-12] 해당 디렉토리에 scripts 파일이 존재할경우 설정값 - [취약]  >> W1~82\report.txt 

) else (
	echo [W-12] scripts 파일이 존재하지 않는 경우 - [양호] >> W1~82\good\[W-12]good.txt
	echo [W-12] scripts 파일이 존재하지 않는 경우 - [양호] >> W1~82\report.txt 
      SET/a ServiceScore = %ServiceScore%+12
	SET/a W12S=1
	goto W12END
)

echo [W-12-1] IIS CGI 실행 제한 >> W1~82\report.txt
 
icacls C:\inetpub\scripts | findstr /i "EVERYONE" > W1~82\log\[W-12]log.txt
type W1~82\log\[W-12]log.txt | findstr /i "W M F"
if %errorlevel% EQU 0 (
	echo [W-12] 해당 디렉토리 Everyone에 모든 권한, 수정 권한, 쓰기 권한이 부여되어 있는 경우 - [취약] >> W1~82\bad\[W-12]bad.txt 
	echo [W-12] 탐색기-해당 디렉토리-속성-보안-Everyone의 모든 권한, 수정 권한, 쓰기 권한 제거 >> W1~82\action\[W-12]action.txt
	echo [W-12] 해당 디렉토리 Everyone에 모든 권한, 수정 권한, 쓰기 권한이 부여되어 있는 경우 - [취약]  >> W1~82\report.txt 
	echo [W-12] 탐색기-해당 디렉토리-속성-보안-Everyone의 모든 권한, 수정 권한, 쓰기 권한 제거  >> W1~82\report.txt 

) else (
	echo [W-12-1] 해당 디렉토리 Everyone에 모든 권한, 수정 권한, 쓰기 권한이 부여되지 않은 경우 - [양호] >> W1~82\good\[W-12]good.txt
	echo [W-12-1] 해당 디렉토리 Everyone에 모든 권한, 수정 권한, 쓰기 권한이 부여되지 않은 경우 - [양호] >> W1~82\report.txt 
      SET/a ServiceScore = %ServiceScore%+6
	SET/a W12S=1

)
:W12END
if %W12S% EQU 1 (
	SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-13] IIS 상위 디렉토리 접근 금지

type C:\Windows\System32\inetsrv\config\applicationHost.config  > W1~82\log\[W-13]log.txt
type W1~82\log\[W-13]log.txt | find /I "enableParentPaths" | find /i "false" > log.txt
if errorlevel 0 goto W13B
if not errorlevel 0 goto W13G

:W13B
	echo [W-13] 상위 디렉토리 접근 기능을 제거하지 않은 경우 - [취약] > W1~82\bad\[W-13]bad.txt 
	echo [W-13] 제어판-관리도구-인터넷 정보서비스(IIS) 관리자-해당 웹사이트-IIS-ASP 선택-부모경로 사용 항목-False 설정 >> W1~82\action\[W-13]action.txt
	echo [W-13] 상위 디렉토리 접근 기능을 제거하지 않은 경우 - [취약] >> W1~82\report.txt 
	echo [W-13] 제어판-관리도구-인터넷 정보서비스(IIS) 관리자-해당 웹사이트-IIS-ASP 선택-부모경로 사용 항목-False 설정 >> W1~82\report.txt
	goto W13

:W13G
	echo [W-13] 상위 디렉토리 접근 기능을 제거한 경우 - [양호] > W1~82\good\[W-13]good.txt
	echo [W-13] 상위 디렉토리 접근 기능을 제거한 경우 - [양호]  >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
	goto W13

:W13
del log.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-14] IIS 불필요한 파일 제거 >> W1~82\report.txt

echo [W-14] 해당 웹 사이트에 IIS Samples, IIS Help 가상디렉토리가 존재하는 경우 >> W1~82\bad\[W-14SS]bad.txt
echo [W-14] IIS 7.0(Windows 2008) 이상 버전 해당사항 없음 >> W1~82\action\[W-14SS]action.txt
echo [W-14] Windows 2000, 2003의 경우 Sample 디렉토리 확인 후 삭제 >> W1~82\action\[W-14SS]action.txt
echo [W-14] 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 12점을 부여해 주십시오. >> W1~82\action\[W-14SS]action.txt

echo [W-14] 해당 웹 사이트에 IIS Samples, IIS Help 가상디렉토리가 존재하는 경우  >> W1~82\report.txt
echo [W-14] IIS 7.0(Windows 2008) 이상 버전 해당사항 없음 >> W1~82\report.txt
echo [W-14] Windows 2000, 2003의 경우 Sample 디렉토리 확인 후 삭제  >> W1~82\report.txt
echo [W-14] 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 12점을 부여해 주십시오. >>  W1~82\report.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-15] 웹 프로세스 권한 제거 >> W1~82\report.txt

echo [W-15] 웹 프로세스가 관리자 권한이 부여된 계정으로 구동되고 있는 경우 >> W1~82\bad\[W-15S]bad.txt
echo [W-15] 시작 - 제어판 - 관리도구 - 컴퓨터 관리 - 로컬 사용자 및 그룹 - 사용자 선택 - nobody 계정 추가  >> W1~82\action\[W-15S]action.txt
echo [W-15] 시작 - 제어판 - 관리도구 - 로컬 보안 정책 - 사용자 권한 할당 선택, " 서비스 로그온" 에 "nobody" 계정 추가 >> W1~82\action\[W-15S]action.txt
echo [W-15] 시작 - 실행 - SERVICES.MSC - IIS Admin Service - 속성 - [로그온] 탭의 계정 지정에 nobody 계정 및 패스워드 입력 >> W1~82\action\[W-15S]action.txt
echo [W-15] 시작 - 프로그램 - 윈도우 탐색기 - IIS가 설치된 폴더 속성 - [보안] 탭에서 nobody 계정을 추가하고 모든 권한 체크 >> W1~82\action\[W-15S]action.txt

echo. >> W1~82\action\[W-15S]action.txt
echo [W-15] "웹사이트 등록정보" - 홈 디렉토리 - 응용프로그램 보호(iis 프로세스 권한 설정 ) >> W1~82\action\[W-15S]action.txt
echo [W-15] 높음 ,보통 ,낮음 중 낮음으로 되어있는 경우 >> W1~82\action\[W-15S]action.txt
echo [W-15] IIS 프로세스는 시스템 권한을 가지게 되므로 해커가 IIS 프로세스의 권한을 획득하면 관리자에 준하는 권한을 가질 수 있으므로 주의  >> W1~82\action\[W-15S]action.txt
echo [W-15] 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 12점을 부여해 주십시오. >> W1~82\action\[W-15S]action.txt

echo [W-15] 웹 프로세스가 관리자 권한이 부여된 계정으로 구동되고 있는 경우 >> W1~82\report.txt
echo [W-15] 시작 - 제어판 - 관리도구 - 컴퓨터 관리 - 로컬 사용자 및 그룹 - 사용자 선택 - nobody 계정 추가  >> W1~82\report.txt
echo [W-15] 시작 - 제어판 - 관리도구 - 로컬 보안 정책 - 사용자 권한 할당 선택, " 서비스 로그온" 에 "nobody" 계정 추가 >> W1~82\report.txt
echo [W-15] 시작 - 실행 - SERVICES.MSC - IIS Admin Service - 속성 - [로그온] 탭의 계정 지정에 nobody 계정 및 패스워드 입력 >> W1~82\report.txt
echo [W-15] 시작 - 프로그램 - 윈도우 탐색기 - IIS가 설치된 폴더 속성 - [보안] 탭에서 nobody 계정을 추가하고 모든 권한 체크 >> W1~82\report.txt

echo. >> W1~82\report.txt
echo [W-15] "웹사이트 등록정보" - 홈 디렉토리 - 응용프로그램 보호(iis 프로세스 권한 설정 ) >> W1~82\report.txt
echo [W-15] 높음 ,보통 ,낮음 중 낮음으로 되어있는 경우 >> W1~82\report.txt
echo [W-15] IIS 프로세스는 시스템 권한을 가지게 되므로 해커가 IIS 프로세스의 권한을 획득하면 관리자에 준하는 권한을 가질 수 있으므로 주의 >> W1~82\report.txt
echo [W-15] 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 12점을 부여해 주십시오. >>  W1~82\report.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-16] IIS 링크 사용금지 >> W1~82\report.txt

set file=C:\inetpub\wwwroot

for /f "tokens=*" %%a in ('dir %file% /S /B') do echo %%a >> W1~82\log\[W-16]log.txt
WHERE /r C:\inetpub\wwwroot *.htm *.url *.html 
if %errorlevel% EQU 0 (
	echo [W-16] 심볼릭 링크, aliases, 바로가기 등의 사용을 허용함 - [취약] >> W1~82\bad\[W-16]bad.txt
	echo [W-16] 등록된 웹 사이트의 홈 디렉토리에 있는 심볼릭 링크, aliases, 바로가기 파일을 삭제하십시오. >> W1~82\action\[W-16]action.txt
	echo 제어판-시스템 및 보안-관리도구-IIS관리자-해당 웹사이트-기본 설정-"실제 경로"에서 홈 디렉토리 위치 확인 >> W1~82\action\[W-16]action.txt
	echo 실제 경로에 입력된 홈 디렉토리로 이동하여 바로가기 파일을 삭제 >> W1~82\action\[W-16]action.txt

	echo [W-16] 심볼릭 링크, aliases, 바로가기 등의 사용을 허용함 - [취약] >> W1~82\report.txt
	echo [W-16] 등록된 웹 사이트의 홈 디렉토리에 있는 심볼릭 링크, aliases, 바로가기 파일을 삭제하십시오. >> W1~82\report.txt
	echo 제어판-시스템 및 보안-관리도구-IIS관리자-해당 웹사이트-기본 설정-"실제 경로"에서 홈 디렉토리 위치 확인 >> W1~82\report.txt
	echo 실제 경로에 입력된 홈 디렉토리로 이동하여 바로가기 파일을 삭제 >> W1~82\report.txt

)	else (
	echo [W-16] 심볼릭 링크, aliases, 바로가기 등의 사용을 허용하지 않음 - [양호] >> W1~82\good\[W-16]good.txt
	echo [W-16] 심볼릭 링크, aliases, 바로가기 등의 사용을 허용하지 않음 - [양호] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-17] IIS 파일 업로드 및 다운로드 제한 >> W1~82\report.txt 

type C:\inetpub\wwwroot\web.config | findstr /I "maxAllowedContentLength" >> W1~82\log\[W-17]log.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config | findstr /I "bufferingLimit maxRequestEntityAllowed" >> W1~82\log\[W-17]log.txt
echo [W-17] 웹 프로세스의 서버 자원을 관리하지 않는 경우 (업로드 및 다운로드 용량 미 제한) - [취약] >> W1~82\bad\[W-17S]bad.txt
echo [W-17] 웹 프로세스의 서버 자원을 관리하지 않는 경우 (업로드 및 다운로드 용량 미 제한) - [취약] >> W1~82\report.txt

echo IIS 7버전 이상에서는 기본값으로 컨텐츠용량 31457280byte(30MB), 다운로드 4194304byte(4MB), 업로드 200000byte(0.2MB)로 제한하고 있습니다. >> W1~82\action\[W-17]action.txt
echo 등록된 웹 사이트의 루트 디렉토리에 있는 web.config 파일 내 security 아래에 다음 항목을 추가하세요. >> W1~82\action\[W-17]action.txt
echo ^<requestFiltering^> >> W1~82\action\[W-17]action.txt
echo     ^<requestLimits maxAllowedContentLength="컨텐츠용량" /^> >> W1~82\action\[W-17]action.txt
echo ^<requestFiltering^> >>W1~82\action\[W-17]action.txt
echo - >> W1~82\action\[W-17]action.txt
echo %systemroot% \system32\inetsrv\config\applicationHost.config 파일 내 ^<asp/^>와 ^<asp^>사이에 다음 항목 추가 >> W1~82\report.txt

echo ^<limits bufferingLimit="파일다운로드용량" maxRequestEntityAllowed="파일업로드용량" /^> >> W1~82\report.txt
echo IIS 7버전 이상에서는 기본값으로 컨텐츠용량 31457280byte(30MB), 다운로드 4194304byte(4MB), 업로드 200000byte(0.2MB)로 제한하고 있습니다. >> W1~82\report.txt
echo 등록된 웹 사이트의 루트 디렉토리에 있는 web.config 파일 내 security 아래에 다음 항목을 추가하세요. >> W1~82\report.txt
echo ^<requestFiltering^> >> W1~82\report.txt
echo     ^<requestLimits maxAllowedContentLength="컨텐츠용량" /^> >> W1~82\report.txt
echo ^<requestFiltering^> >> W1~82\report.txt
echo - >> W1~82\report.txt
echo %systemroot% \system32\inetsrv\config\applicationHost.config 파일 내 ^<asp/^>와 ^<asp^>사이에 다음 항목 추가 >> W1~82\report.txt
echo ^<limits bufferingLimit="파일다운로드용량" maxRequestEntityAllowed="파일업로드용량" /^> >> W1~82\report.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-18] IIS DB 연결 취약점 점검 >> W1~82\report.txt
SET/a W18S=0

type C:\inetpub\wwwroot\web.config | findstr /I "path="*."" >> pathSite.txt
type C:\inetpub\wwwroot\web.config | findstr /I "fileExtension" >> filterSite.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config | findstr /I "path="*."" >> pathServer.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config | findstr /I "fileExtension" >> filterServer.txt
type pathSite.txt | findstr /I "*.asa *.asax" >> W1~82\log\[W-18]Sitepathlog.txt
type filterSite.txt | findstr /I "asa asax" >> W1~82\log\[W-18]Sitefilterlog.txt
type pathServer.txt | findstr /I "*.asa *.asax" >> W1~82\log\[W-18]Serverpathlog.txt
type filterServer.txt | findstr /I "asa asax" >> W1~82\log\[W-18]Serverfilterlog.txt

type pathServer.txt | findstr /I "*.asa *.asax"
if not %errorlevel% EQU 0 (
	echo [W-18] 서버 "처리기매핑"의 사용 항목에 asa, asax가 등록되어 있지 않습니다. - [양호] >> W1~82\good\[W-18]good.txt
	echo [W-18] 서버 "처리기매핑"의 사용 항목에 asa, asax가 등록되어 있지 않습니다. - [양호] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+3
	SET/a W18S=1

)	else (
	echo [W-18] 서버 "처리기매핑"의 사용항목에 asa, asax가 등록되어 있습니다. - [취약] >> W1~82\bad\[W-18]bad.txt
	echo [W-18] IIS관리자-해당서버- IIS-"처리기 매핑"선택-사용 항목에 *.asa 및 *.asax를 삭제하세요. >> W1~82\action\[W-18]action.txt
	echo [W-18] 서버 "처리기매핑"의 사용항목에 asa, asax가 등록되어 있습니다. - [취약] >> W1~82\report.txt
	echo [W-18] IIS관리자-해당서버- IIS-"처리기 매핑"선택-사용 항목에 *.asa 및 *.asax를 삭제하세요. >> W1~82\report.txt
)

type filterServer.txt | find /I "true" | findstr /I "asa asax"
if not %errorlevel% EQU 0 (
	echo [W-18] 서버 "요청 필터링"의 asa, asax 확장자가 false로 설정되어 있습니다. - [양호] >> W1~82\good\[W-18]good.txt
	echo [W-18] 서버 "요청 필터링"의 asa, asax 확장자가 false로 설정되어 있습니다. - [양호] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+3
	SET/a W18S=1
)	else (
	echo [W-18] 서버 "요청 필터링"의 asa, asax 확장자가 true로 설정되어 있습니다. - [취약] >> W1~82\bad\[W-18]bad.txt
	echo [W-18] IIS관리자-해당서버-IIS-"요청 필터링"선택-asa 및 asax 확장자를 false로 설정하세요. >> W1~82\action\[W-18]action.txt
	echo [W-18] 서버 "요청 필터링"의 asa, asax 확장자가 true로 설정되어 있습니다. - [취약] >> W1~82\report.txt
	echo [W-18] IIS관리자-해당서버-IIS-"요청 필터링"선택-asa 및 asax 확장자를 false로 설정하세요. >> W1~82\report.txt

)

type pathSite.txt | findstr /I "*.asa *.asax"
if not %errorlevel% EQU 0 (
	echo [W-18] 사이트 "처리기매핑"의 사용 항목에 asa, asax가 등록되어 있지 않습니다. - [양호] >> W1~82\good\[W-18]good.txt
	echo [W-18] 사이트 "처리기매핑"의 사용 항목에 asa, asax가 등록되어 있지 않습니다. - [양호] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+3
	SET/a W18S=1
)	else (
	echo [W-18] 사이트 "처리기매핑"의 사용항목에 asa, asax가 등록되어 있습니다. - [취약] >> W1~82\bad\[W-18]bad.txt
	echo [W-18] IIS관리자-해당 웹 사이트- IIS-"처리기 매핑"선택-사용 항목에 *.asa 및 *.asax를 삭제하세요. >> W1~82\action\[W-18]action.txt
	echo [W-18] 사이트 "처리기매핑"의 사용항목에 asa, asax가 등록되어 있습니다. - [취약] >> W1~82\report.txt
	echo [W-18] IIS관리자-해당 웹 사이트- IIS-"처리기 매핑"선택-사용 항목에 *.asa 및 *.asax를 삭제하세요. >> W1~82\report.txt

)

type filterSite.txt | find /I "true" | findstr /I "asa asax"
if not %errorlevel% EQU 0 (
	echo [W-18] 사이트 "요청 필터링"의 asa, asax 확장자가 false로 설정되어 있습니다. - [양호] >> W1~82\good\[W-18]good.txt
	echo [W-18] 사이트 "요청 필터링"의 asa, asax 확장자가 false로 설정되어 있습니다. - [양호] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+3
	SET/a W18S=1
)	else (
	echo [W-18] 사이트 "요청 필터링"의 asa, asax 확장자가 true로 설정되어 있습니다. - [취약] >> W1~82\bad\[W-18]bad.txt
	echo [W-18] IIS관리자-해당 웹 사이트-IIS-"요청 필터링"선택-asa 및 asax 확장자를 false로 설정하세요. >> W1~82\action\[W-18]action.txt
	echo [W-18] 사이트 "요청 필터링"의 asa, asax 확장자가 true로 설정되어 있습니다. - [취약] >> W1~82\report.txt
	echo [W-18] IIS관리자-해당 웹 사이트-IIS-"요청 필터링"선택-asa 및 asax 확장자를 false로 설정하세요. >> W1~82\report.txt

)
if %W18S% EQU 1 (
	SET/a ServiceScore3 = %ServiceScore3%+1
)

del pathSite.txt
del filterSite.txt
del pathServer.txt
del filterServer.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-19] IIS 가상 디렉토리 삭제 >> W1~82\report.txt

echo [W-19] 해당 웹 사이트에 IIS Admin, IIS Adminpwd 가상 디렉토리가 존재하는 경우 - [취약] > W1~82\bad\[W-19SS]bad.txt
echo [W-19] 해당 웹 사이트에 IIS Admin, IIS Adminpwd 가상 디렉토리가 존재하는 경우 - [취약] >> W1~82\report.txt

echo Windows 2003(6.0) 이상 버전 해당 사항 없음 >> W1~82\action\[W-19]action.txt
echo Windows 2000(5.0) >> W1~82\action\[W-19]action.txt
echo 시작-실행-INETMGR 입력-웹 사이트- IISAdmin, IISAdminpwd 선택-삭제 >> W1~82\action\[W-19]action.txt
echo 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 12점을 부여해 주십시오. >> W1~82\action\[W-19]action.txt


echo Windows 2003(6.0) 이상 버전 해당 사항 없음 >> W1~82\report.txt
echo Windows 2000(5.0) >> W1~82\report.txt
echo 시작-실행-INETMGR 입력-웹 사이트- IISAdmin, IISAdminpwd 선택-삭제 >> W1~82\report.txt
echo 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 3점을 부여해 주십시오. >>  W1~82\report.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-20] IIS 데이터 파일 ACL 적용 >> W1~82\report.txt

icacls "C:\inetpub\wwwroot" >> W1~82\log\[W-20]log.txt

icacls "C:\inetpub\wwwroot" | findstr /I "Everyone" > NUL
if %errorlevel% EQU 0 (
  echo [W-20] 홈 디렉토리 내에 있는 하위 파일들에 대해 Everyone 권한이 존재 - [취약] > W1~82\bad\[W-20]bad.txt
  echo 시작-실행-INETMGR 입력-사이트 클릭-해당 웹사이트-기본 설정- 홈 디렉토리 실제 경로 확인 >> W1~82\action\[W-20]action.txt
  echo 탐색기를 이용하여 홈 디렉토리의 등록 정보-[보안]탭에서 Everyone 권한 확인 >> W1~82\action\[W-20]action.txt
  echo 불필요한 Everyone 권한을 제거하십시오. >> W1~82\action\[W-20]action.txt

  echo [W-20] 홈 디렉토리 내에 있는 하위 파일들에 대해 Everyone 권한이 존재 - [취약] >> W1~82\report.txt
  echo 시작-실행-INETMGR 입력-사이트 클릭-해당 웹사이트-기본 설정- 홈 디렉토리 실제 경로 확인 >> W1~82\report.txt
  echo 탐색기를 이용하여 홈 디렉토리의 등록 정보-[보안]탭에서 Everyone 권한 확인 >> W1~82\report.txt
  echo 불필요한 Everyone 권한을 제거하십시오. >> W1~82\report.txt
)	else (
	echo [W-20] 홈 디렉토리 내에 있는 하위 파일들에 대해 Everyone 권한이 존재하지 않음 - [양호] > W1~82\good\[W-20]good.txt
	echo [W-20] 홈 디렉토리 내에 있는 하위 파일들에 대해 Everyone 권한이 존재하지 않음 - [양호] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-21] IIS Exec 명령어 쉘 호출 진단 >> W1~82\report.txt

dir C:\Windows\System32\inetsrv /b > W1~82\log\[W-21]log.txt
dir C:\Windows\System32\inetsrv /b > list.txt

type list.txt | findstr /i /l ".htr .IDC .stm .shtm .shtml .printer .htw .ida .idq htr.dll idc.dll stm.dll shtm.dll shtml.dll printer.dll htw.dll ida.dll idq.dll" > W1~82\log\[W-21]detectlog.txt
type list.txt | findstr /i /l ".htr .IDC .stm .shtm .shtml .printer .htw .ida .idq htr.dll idc.dll stm.dll shtm.dll shtml.dll printer.dll htw.dll ida.dll idq.dll" > list2.txt
if errorlevel 1 goto W21G
if not errorlevel 1 goto W21B


:W21B
	echo [W-21] htr IDC stm shtm shtml printer htw ida idq가 존재함 log에서 확인 - [취약] >> W1~82\bad\[W-21]bad.txt 
	echo [W-21] 시작 - 실행 - INETMGR - 웹사이트 - 해당 웹사이트 - 처리기 매핑 선택 >> W1~82\action\[W-21]action.txt
	echo [W-21] 취약한 매핑 제거 (htr idc stm shtm shtml printer htw ida idq) >> W1~82\action\[W-21]action.txt
	echo [W-21] htr IDC stm shtm shtml printer htw ida idq가 존재함 log에서 확인 - [취약] >> W1~82\report.txt 
	echo [W-21] 시작 - 실행 - INETMGR - 웹사이트 - 해당 웹사이트 - 처리기 매핑 선택 >> W1~82\report.txt
	echo [W-21] 취약한 매핑 제거 (htr idc stm shtm shtml printer htw ida idq) >> W1~82\report.txt
	goto W21

:W21G
	echo [W-21] htr IDC stm shtm shtml printer htw ida idq가 존재하지않음  - [양호] >> W1~82\good\[W-21]good.txt
	echo [W-21] htr IDC stm shtm shtml printer htw ida idq가 존재하지않음  - [양호] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
	goto W21

:W21
del list.txt
del list2.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-22] IIS Exec 명령어 쉘 호출 진단(레지스트리값 존재 유무) >> W1~82\report.txt
SET/a W22S=0

reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters /s | find /v "오류" > W1~82\log\[W-22]log.txt
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters /s | find /v "오류" > reg.txt
type reg.txt | find /I "SSIEnableCmdDirective" > NUL

if %errorlevel% EQU 1 (
	echo [W-22] 레지스트리값이 존재하지 않거나 IIS 6.0버전인 경우 - [양호] >> W1~82\good\[W-22]good.txt
	echo [W-22] 레지스트리값이 존재하지 않거나 IIS 6.0버전인 경우 - [양호] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
	SET/a W22S=1
	goto W22
) else (
	echo [W-22] 해당 레지스트리값이 존재함 - [취약] >> W1~82\bad\[W-22]bad.txt
	echo [W-22] 해당 레지스트리값이 존재함 - [취약] >> W1~82\report.txt
	goto W22-1
)

:W22-1
echo [W-22] IIS Exec 명령어 쉘 호출 진단 >> W1~82\report.txt

type reg.txt | find /I "SSIEnableCmdDirective" > ssl.txt

type ssl.txt | find "0x1"
if %errorlevel% EQU 1 (
	echo [W-22-1] 레지스트리값이 0임  - [양호] > W1~82\good\[W-22]good.txt
	echo [W-22-1] 레지스트리값이 0임  - [양호] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
	SET/a W22S=1
	del  W1~82\bad\[W-22]bad.txt
) else (
	echo [W-22-1] 해당 레지스트리값이 1임 [취약] >> W1~82\bad\[W-22]bad.txt
	echo 시작 - 실행 - REGEDIT - HKLM\SYSTEM\CurrentControlSet\Services\W32VC\Parameters 검색 > W1~82\action\[W-22]action.txt
	echo DWORD - SSIEnableCmdDirective 값을 찾아 값을 0으로 입력 >> W1~82\action\[W-22]action.txt

	echo [W-22-1] 해당 레지스트리값이 1임 [취약] >> W1~82\report.txt
	echo 시작 - 실행 - REGEDIT - HKLM\SYSTEM\CurrentControlSet\Services\W32VC\Parameters 검색 >> W1~82\report.txt
	echo DWORD - SSIEnableCmdDirective 값을 찾아 값을 0으로 입력 >> W1~82\report.txt

)

:W22
if %W22S% EQU 1 (
	SET/a ServiceScore3 = %ServiceScore3%+1
)

del reg.txt
del ssl.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-23] IIS WebDAV 비활성화 >> W1~82\report.txt

type C:\Windows\System32\inetsrv\config\applicationHost.config > log.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config > W1~82\log\[W-23]log.txt

type log.txt | findstr /I "webdav.dll" | find "true"
if errorlevel 1 goto W23G
if not errorlevel 1 goto W23B

:W23B
echo [W-23] WebDav가 존재함 - [취약] >> W1~82\bad\[W-23]bad.txt  
echo 인터넷 정보 서비스(IIS) 관리자 - 서버 선택 - IIS - ISAPI 및 CGI 제한 선택, WebDAV 사용여부 확인 (허용됨일 경우 취약) >> W1~82\action\[W-23]action.txt
echo 인터넷 정보 서비스(IIS) 관리자 - 서버 선택 > IIS - "ISAPI 및 CGI 제한" 선택 WebDAV 항목 선택 - 작업에서 제거하거나, 편집 - "확장 경로 실행 허용" 체크 해제  >> W1~82\action\[W-23]action.txt
echo [W-23] WebDav가 존재함 - [취약] >> W1~82\report.txt  
echo 인터넷 정보 서비스(IIS) 관리자 - 서버 선택 - IIS - ISAPI 및 CGI 제한 선택, WebDAV 사용여부 확인 (허용됨일 경우 취약) >> W1~82\report.txt
echo 인터넷 정보 서비스(IIS) 관리자 - 서버 선택 > IIS - "ISAPI 및 CGI 제한" 선택 WebDAV 항목 선택 - 작업에서 제거하거나, 편집 - "확장 경로 실행 허용" 체크 해제  >> W1~82\report.txt

goto W23

:W23G
echo [W-23] WebDav가 존재하지않음  - [양호] >> W1~82\good\[W-23]good.txt
echo [W-23] WebDav가 존재하지않음  - [양호] >> W1~82\report.txt
SET/a ServiceScore = %ServiceScore%+12
SET/a ServiceScore3 = %ServiceScore3%+1

goto W23


:W23
del log.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-24] NetBIOS 바인딩 서비스 구동 점검 >> W1~82\report.txt

wmic nicconfig where "TcpipNetbiosOptions<>null and ServiceName<>'VMnetAdapter'" get Description, TcpipNetbiosOptions > W1~82\log\[W-24]log.txt
wmic nicconfig where "TcpipNetbiosOptions<>null and ServiceName<>'VMnetAdapter'" get Description, TcpipNetbiosOptions > netb.txt

type netb.txt | findstr /I "0" > NUL
if %errorlevel% EQU 0 (
	 echo [w-24]  TCP/IP와 NetBIOS 간의 바인딩이 제거 되어 있음 [양호] > W1~82\good\[W-24]good.txt
	 echo [w-24]  TCP/IP와 NetBIOS 간의 바인딩이 제거 되어 있음 [양호] >> W1~82\report.txt
	 SET/a ServiceScore = %ServiceScore%+12
	 SET/a ServiceScore3 = %ServiceScore3%+1
) else (
	echo [W-24] TCP/IP와 NetBIOS 간의 바인딩이 제거 되어있지 않음 [취약] > W1~82\bad\[W-24]bad.txt 
	echo [W-24] 시작 - 실행 - ncpa.cpl - 로컬 영역 연결 - 속성 - TCP/IP - [일반] 탭에서 [고급] 클릭 - [WINS] 탭에서 TCP/IP에서 "NetBIOS 사용 안 함" 또는, "NetBIOS over TCP/IP 사용 안 함" 선택 >> W1~82\action\[W-24]action.txt

	echo [W-24] TCP/IP와 NetBIOS 간의 바인딩이 제거 되어있지 않음 [취약] >> W1~82\report.txt 
	echo [W-24] 시작 - 실행 - ncpa.cpl - 로컬 영역 연결 - 속성 - TCP/IP - [일반] 탭에서 [고급] 클릭 - [WINS] 탭에서 TCP/IP에서 "NetBIOS 사용 안 함" 또는, "NetBIOS over TCP/IP 사용 안 함" 선택 >> W1~82\report.txt

)

del netb.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-25] FTP 서비스 구동 점검 >> W1~82\report.txt

net start | find "Microsoft FTP Service" >  W1~82\log\[W-25]log.txt

net start | find "Microsoft FTP Service"
if %errorlevel% EQU 0 (
	echo [W-25] FTP 서비스를 사용하는 경우 - [취약] > W1~82\bad\[W-25]bad.txt
  echo FTP 서비스가 불필요할 경우 FTP서비스 사용 중지 >> W1~82\action\[W-25]action.txt
	echo 시작 - 실행 - SERVICES.MSC - FTP Publishing Service - 속성 - [일반] 탭에서 "시작 유형" 사용 안 함 으로 설정한 후, FTP 서비스 중지 >> W1~82\action\[W-25]action.txt

	echo [W-25] FTP 서비스를 사용하는 경우 - [취약] >> W1~82\report.txt
  echo FTP 서비스가 불필요할 경우 FTP서비스 사용 중지 >> W1~82\report.txt
	echo 시작 - 실행 - SERVICES.MSC - FTP Publishing Service - 속성 - [일반] 탭에서 "시작 유형" 사용 안 함 으로 설정한 후, FTP 서비스 중지 >> W1~82\report.txt

) else (
	echo [W-25] FTP 서비스를 사용하지 않는 경우 - [양호] > W1~82\good\[W-25]good.txt
	echo [W-25] FTP 서비스를 사용하지 않는 경우 - [양호] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+12
	SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-26] FTP 디렉토리 접근권한 설정 >> W1~82\report.txt
 
icacls C:\inetpub\ftproot > W1~82\log\[W-26]log.txt

icacls C:\inetpub\ftproot | findstr /i "EVERYONE"
if %errorlevel% EQU 0 (
	echo [W-26] FTP 홈 디렉토리에 Everyone 권한이 있는 경우 - [취약] >> W1~82\bad\[W-26]bad.txt
	echo [W-26] 인터넷 정보 서비스 IIS 관리 - FTP 사이트 - 해당 FTP 사이트 - 속성 - [홈 디렉토리] 탭에서 FTP 홈 디렉토리 확인 >> W1~82\action\[W-26]action.txt 
	echo [W-26] 탐색기 - 홈 디렉토리 - 속성 - [보안] 탭에서 Everyone 권한 제거 >> W1~82\action\[W-26]action.txt

	echo [W-26] FTP 홈 디렉토리에 Everyone 권한이 있는 경우 - [취약] >> W1~82\report.txt
	echo [W-26] 인터넷 정보 서비스 IIS 관리 - FTP 사이트 - 해당 FTP 사이트 - 속성 - [홈 디렉토리] 탭에서 FTP 홈 디렉토리 확인 >> W1~82\report.txt 
	echo [W-26] 탐색기 - 홈 디렉토리 - 속성 - [보안] 탭에서 Everyone 권한 제거 >> W1~82\report.txt

) else (
	echo [W-26] 양호 FTP 홈 디렉토리에 Everyone 권한이 없는 경우 - [양호] >> W1~82\good\[W-26]good.txt
	echo [W-26] 양호 FTP 홈 디렉토리에 Everyone 권한이 없는 경우 - [양호] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
)

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-27] Anonymous FTP 금지 >> W1~82\report.txt

type C:\Windows\System32\inetsrv\config\applicationHost.config | find "anonymousAuthentication enabled" > W1~82\log\[W-27]log.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config | find "anonymousAuthentication enabled" > log.txt

type log.txt | find "true" 
if %errorlevel% EQU 0 (
	echo [W-27] FTP 익명 사용 허용됨 - [취약] > W1~82\bad\[W-27]bad.txt
	echo 제어판-관리도구-인터넷 정보 서비스 IIS 관리-해당 웹사이트-마우스 우클릭-FTP 게시 추가 > W1~82\action\[W-27]action.txt
	echo 이후 진행 과정에서 인증 화면의 익명 체크 박스 해제 >> W1~82\action\[W-27]action.txt

	echo [W-27] FTP 익명 사용 허용됨 - [취약] >> W1~82\report.txt
	echo 제어판-관리도구-인터넷 정보 서비스 IIS 관리-해당 웹사이트-마우스 우클릭-FTP 게시 추가 >> W1~82\report.txt
	echo 이후 진행 과정에서 인증 화면의 익명 체크 박스 해제 >> W1~82\report.txt

) else (
	echo [W-27] FTP 익명 사용자 허용 안함 - [양호] > W1~82\good\[W-27]good.txt
	echo [W-27] FTP 익명 사용자 허용 안함 - [양호] >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
)

del log.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-28] FTP 접근 제어 설정 >> W1~82\report.txt

type C:\Windows\System32\inetsrv\config\applicationHost.config | find /I "add ipAddress" > W1~82\log\[W-28]log.txt

echo [W-28] FTP 접근 제어 설정 확인 - [취약] > W1~82\bad\[W-28S]bad.txt
echo W1~82\log\[W-28]log.txt 파일을 확인하고 담당자와 상의하여 불필요한 주소의 접근을 제거 하십시오. >> W1~82\action\[W-28]action.txt
echo 조치 방법 : 제어판-관리도구-인터넷 정보 서비스(IIS)관리-해당 웹사이트-FTP IPv4주소 및 도메인 제한 >> W1~82\action\[W-28]action.txt
echo 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 3점을 부여해 주십시오. >> W1~82\action\[W-28]action.txt

echo [W-28] FTP 접근 제어 설정 확인 - [취약] >> W1~82\report.txt
echo W1~82\log\[W-28]log.txt 파일을 확인하고 담당자와 상의하여 불필요한 주소의 접근을 제거 하십시오. >> W1~82\report.txt
echo 조치 방법 : 제어판-관리도구-인터넷 정보 서비스(IIS)관리-해당 웹사이트-FTP IPv4주소 및 도메인 제한 >> W1~82\report.txt
echo 또한, 이 점검부분에서 양호하다고 판단이 된다면, 서비스 항목에 수동으로 3점을 부여해 주십시오. >>  W1~82\report.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-29] DNS Zone Transfer 설정 >> W1~82\report.txt
SET/a W29S=0

net start > W1~82\log\[W-29]log.txt
net start > log.txt

type log.txt | find "DNS Server"
if %errorlevel% EQU 1 (
	echo [W-29] DNS서비스를 사용하지 않는 경우 - [양호] >> W1~82\good\[W-29]good.txt
	echo [W-29] DNS서비스를 사용하지 않는 경우 - [양호] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+6
	SET/a W29S=1
) else (
	echo [W-29] DNS서비스를 사용하는 경우 - [취약] >> W1~82\bad\[W-29]bad.txt
	echo [W-29] DNS서비스를 중단하세요. >> W1~82\action\[W-29]action.txt

	echo [W-29] DNS서비스를 사용하는 경우 - [취약] >> W1~82\report.txt
	echo [W-29] DNS서비스를 중단하세요. >> W1~82\report.txt

)

reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s >> W1~82\log\[W-29]log.txt
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s | find /I "SecureSecondaries" >> reg.txt

type reg.txt | findstr /I "0x1 0x2"
if %errorlevel% EQU 1 (
	echo [W-29] 영역 전송 허용을 하지 않는 경우 - [양호] >> W1~82\good\[W-29]good.txt 
	echo [W-29] 영역 전송 허용을 하지 않는 경우 - [양호] >> W1~82\report.txt
	SET/a ServiceScore = %ServiceScore%+6
	SET/a W29S=1
) else (
	echo [W-29] 영역 전송 허용을 하는 경우 - [취약] >> W1~82\bad\[W-29]bad.txt
	echo [W-29] W1~82\log\[W-29]log.txt 파일을 확인하여 'SecureSecondaries' 레지스트리값이 0x0이거나 0x3이 아닌 항목의 영역 전송 설정 변경 >> W1~82\action\[W-29]action.txt
	echo [W-29] 시작-실행-DNSMGMT.MSC-각 조회 영역-해당 영역-속성-영역 전송 >> W1~82\action\[W-29]action.txt
	echo [W-29] “다음 서버로만” 선택후 전송할 서버 IP 추가 >> W1~82\action\[W-29]action.txt

	echo [W-29] 영역 전송 허용을 하는 경우 - [취약] >> W1~82\report.txt
	echo [W-29] W1~82\log\[W-29]log.txt 파일을 확인하여 'SecureSecondaries' 레지스트리값이 0x0이거나 0x3이 아닌 항목의 영역 전송 설정 변경 >> W1~82\report.txt
	echo [W-29] 시작-실행-DNSMGMT.MSC-각 조회 영역-해당 영역-속성-영역 전송 >> W1~82\report.txt
	echo [W-29] “다음 서버로만” 선택후 전송할 서버 IP 추가 >> W1~82\report.txt
)
if %W29S% EQU 1 (
	SET/a ServiceScore3 = %ServiceScore3%+1
)


del log.txt
del reg.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt

echo [W-30] RDS (Remote Data Services)제거 >> W1~82\report.txt

reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" /s >> W1~82\log\[W-30]log.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" /s >> log.txt

type log.txt | findstr "ADCLaunch" 
if errorlevel EQU 0 (
	echo [W-30] RDS(Remote Data Services) 제거됨 (2008 이상 양호) >> W1~82\good\[W-30SS]good.txt
	echo [W-30] RDS(Remote Data Services) 제거됨 (2008 이상 양호) >> W1~82\report.txt
      SET/a ServiceScore = %ServiceScore%+12
      SET/a ServiceScore3 = %ServiceScore3%+1
	goto W30
) else (
	echo [W-30] RDS(Remote Data Services) 제거됨 (2008 미만 취약) >> W1~82\bad\[W-30SS]bad.txt
	echo 시작-실행-inetmgr-웹사이트 선택 후 오른쪽 디렉토리에서 msadc제거 >> W1~82\action\[W-30SS]action.txt
	echo 다음의 레지스트리 키/디렉토리 제거>> W1~82\action\[W-30SS]action.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\RDSServer.DataFactory >> W1~82\action\[W-30SS]action.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\AdvancedDataFactory >> W1~82\action\[W-30SS]action.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\VbBusObj.VbBusObjCls >> W1~82\action\[W-30SS]action.txt

	echo [W-30] RDS(Remote Data Services) 제거됨 (2008 미만 취약) >> W1~82\report.txt
	echo 시작-실행-inetmgr-웹사이트 선택 후 오른쪽 디렉토리에서 msadc제거 >> W1~82\report.txt
	echo 다음의 레지스트리 키/디렉토리 제거 >> W1~82\report.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\RDSServer.DataFactory >> W1~82\report.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\AdvancedDataFactory >> W1~82\report.txt
	echo HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\VbBusObj.VbBusObjCls >> W1~82\report.txt

	goto W30
)

:W30
del log.txt

echo. >> W1~82\report.txt
echo ===================================================================================================================================== >>  W1~82\report.txt
echo. >> W1~82\report.txt


echo %AccountScore%
echo %AccountScore2%
echo %AccountScore3%
echo %AccountScore% > W1~82\SOLu\AScore.txt
echo %AccountScore2% > W1~82\SOLu\AScore2.txt
echo %AccountScore3% > W1~82\SOLu\AScore3.txt
echo %ServiceScore%
echo %ServiceScore1%
echo %ServiceScore2%
echo %ServiceScore3%
echo %ServiceScore% > W1~82\SOLu\SScore.txt
echo %ServiceScore1% > W1~82\SOLu\SSCore1.txt
echo %ServiceScore2% > W1~82\SOLu\SScore2.txt
echo %ServiceScore3% > W1~82\SOLu\SScore3.txt
echo %PatchScore%
echo %PatchScore2%
echo %PatchScore3%
echo %PatchScore% > W1~82\SOLu\PScore.txt
echo %PatchScore2% > W1~82\SOLu\PScore2.txt
echo %PatchScore3% > W1~82\SOLu\PScore3.txt
echo %LogScore%
echo %LogScore1%
echo %LogScore2%
echo %LogScore3%
echo %LogScore% > W1~82\SOLu\LScore.txt
echo %LogScore1% > W1~82\SOLu\LScore1.txt
echo %LogScore2% > W1~82\SOLu\LScore2.txt
echo %LogScore3% > W1~82\SOLu\LScore3.txt
echo %SecureScore%
echo %SecureScore2%
echo %SecureScore3%
echo %SecureScore% > W1~82\SOLu\SeScore.txt
echo %SecureScore2% > W1~82\SOLu\SeScore2.txt
echo %SecureScore3% > W1~82\SOLu\SeScore3.txt
pause




