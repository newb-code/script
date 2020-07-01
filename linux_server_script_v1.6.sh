#!/bin/bash
COMPANY_NAME="upbit" # 회사명 companyName
COMPANY_CODE="upbit" # 회사 약어 company
ASSET="가" #assetClass
HOSTNAME=`hostname` # 점검 대상명(호스트명) targetName
OSTYPE="LINUX" # osType
OS_VERSION=`cat /etc/os-release | egrep -w "PRETTY_NAME" | awk -F= '{print $2}' | sed 's/\"//g'` #osVer
DATE=`date +"%Y%m%d"`

#--START(메인함수)
main(){
for i in {1..73}
do
  echo -ne "\r Linux Server 취약점 진단이 ${i}/73 진행중입니다. 잠시만 기다려주십시오..."
  U-$i > /dev/null 2>&1
done
  if [ $i -eq 73 ]
  then
    echo -ne "\r Linux Server 취약점 진단이 73/73 진행중입니다. 잠시만 기다려주십시오...Ok"
  fi
echo ""
sleep 0.5
}
#--END

function f_permit(){
location=$1
cert=$2

if [ -f $location ] ; then
re=`ls -l $location | awk '{print $1}'`


ro[1]=`expr substr $re 2 3`
ro[2]=`expr substr $re 5 3`
ro[3]=`expr substr $re 8 3`

roc[0]=0
roc[1]=0
roc[2]=0
roc[3]=0

for((ij=1;ij<4;ij++));
do
###rwx 퍼미션 확인###
if [[ ${ro[$ij]} =~ 'r' ]]; then
 roc[$ij]=`expr ${roc[$ij]} + 4`
fi
if [[ ${ro[$ij]} =~ 'w' ]]; then
 roc[$ij]=`expr ${roc[$ij]} + 2`
fi
if [[ ${ro[$ij]} =~ 'x' ]]; then
 roc[$ij]=`expr ${roc[$ij]} + 1`
fi
done

###기타 퍼미션 확인###
   if [[ ${ro[1]} =~ 's' ]]; then
     roc[0]=`expr ${roc[0]} + 4`
     roc[1]=`expr ${roc[1]} + 1`
   fi
   if [[ ${ro[1]} =~ 'S' ]]; then
     roc[0]=`expr ${roc[0]} + 4`
   fi
   if [[ ${ro[2]} =~ 's' ]]; then
     roc[0]=`expr ${roc[0]} + 2`
     roc[1]=`expr ${roc[2]} + 1`
   fi
   if [[ ${ro[2]} =~ 'S' ]]; then
     roc[0]=`expr ${roc[0]} + 2`
   fi
   if [[ ${ro[3]} =~ 't' ]]; then
     roc[0]=`expr ${roc[0]} + 1`
     roc[1]=`expr ${roc[2]} + 1`
   fi
   if [[ ${ro[3]} =~ 'T' ]]; then
     roc[0]=`expr ${roc[0]} + 1`
   fi

if [ ${roc[0]} -gt 0 ] ; then
perm=`echo "${roc[0]}${roc[1]}${roc[2]}${roc[3]}"`
else
perm=`echo "${roc[1]}${roc[2]}${roc[3]}"`
fi

if [ $perm -le $cert ] ; then
result="OK"
else
result="ERROR"
fi


echo "$result"

else
echo "$location File Not Found."
fi
}

function U-1(){
#--START(점검항목 설명)
CODE="U-01"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

usetel=`netstat -ntlp | grep -w 23 | wc -l`
sectty=`cat /etc/pam.d/login | grep -v "#" | grep pam_securetty.so | wc -l`
pts=`cat /etc/securetty | grep ^pts | wc -l`

if [ $usetel -gt 0 ]; then
        b_result11=`netstat -ntlp | grep -w 23`
        if [ $pts -eq 0 -a $sectty -eq 1 ];then
                a_result1="O"
                b_result12=`cat /etc/securetty | grep ^pts`
                b_result13=`cat /etc/pam.d/login | grep -v "#" | grep pam_securetty.so`
                c_result1="pts 설정이 없고, pam_securetty.so 모듈을 사용중이므로 양호"
        else
                a_result1="X"
                b_result12=`cat /etc/securetty | grep ^pts`
                b_result13=`cat /etc/pam.d/login | grep -v "#" | grep pam_securetty.so`
                c_result1="pts 설정과 pam_securetty.so 모듈 설정을 모두 만족하지 않으므로 취약"
        fi
else
        a_result1="O"
        b_result11=`netstat -ntlp | grep -w 23`
        c_result1="텔넷 서비스를 사용하지 않으므로 양호"
fi

usessh=`netstat -ntlp | grep ssh | wc -l`
rtlogin=`cat /etc/ssh/sshd_config | egrep ^PermitRootLogin | awk {'print $2'}`
rootlogin=`echo $rtlogin | tr ['A-Z'] ['a-z']`
authcmd=`cat /root/.ssh/authorized_keys | grep command | wc -l`

if [ $usessh -gt 0 ]; then
        b_result21=`netstat -ntlp | grep ssh`
        if [ "$rootlogin" ]; then
                if [ "$rootlogin" == "prohibit-password" ]; then
                        if [ $authcmd -eq 1 ]; then
                                a_result2="O"
                                c_result2="SSH를 사용중이며 PermitRootLogin 옵션이 $rootlogin로 설정되어있고 /root/.ssh/authorized_keys 파일의 디폴트 커맨드가 존재하므로 양호"
                                b_result22=`sed s/\'//g /root/.ssh/authorized_keys`
                        else
                                a_result2="X"
                                c_result2="SSH를 사용중이며 PermitRootLogin 옵션이 $rootlogin로 설정되어있고 /root/.ssh/authorized_keys 파일의 디폴트 커맨드가 존재하지 않으므로 취약"
                                b_result22=`sed s/\'//g /root/.ssh/authorized_keys`
                        fi
                else
                        a_result2="O"
                        c_result2="SSH를 사용중이며 PermitRootLogin 옵션이 $rootlogin로 설정되어있으므로 양호"
                fi
        else
                a_result2="X"
                c_result2="PermitRootLogin 옵션이 설정되어 있지 않으므로 취약"
        fi
else
        a_result2="X"
        b_result21=`netstat -ntlp | grep ssh`
        c_result2="SSH를 미사용 중이므로 취약"
fi

if [ $a_result1 == "O" -a $a_result2 == "O" ]; then
        a_result="O"
else
        a_result="X"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="
[SSH 원격 접속]
1.SSH 원격 접속 여부 확인
$b_result21
2./etc/ssh/sshd_config 파일 내 PermitRootLogin 설정 확인
`cat /etc/ssh/sshd_config | grep PermitRootLogin | grep "#"`
3.PermitRootLogin 옵션이 prohibit-password일 경우 /root/.ssh/authorized_keys 파일 확인
$b_result22

[Telnet 원격 접속]
1.Telnet 원격 접속 여부 확인
$b_result11
2.securetty 파일내 pts 설정 확인
$b_result12
3./etc/pam.d/login 설정 확인
$b_result13
"

chkStatus="$a_result"
chkResult="[결과값]
$c_result1
$c_result2
"
#--END

#--START(JSON 형식 출력)
json_change_start
}

function U-2(){
#--START(점검항목 설명)
CODE="U-02"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

pass1=`cat /etc/ssh/sshd_config | grep ^PasswordAuthentication`
pass2=`echo $pass1 | tr '[A-Z]' '[a-z]' | awk {'print $2'}`

# cat /etc/ssh/sshd_config 파일 내 PasswordAuthentication 설정이 yes일 경우
if [ $pass2 == "yes" ]; then

	# /etc/pam.d/system-auth 파일이 존재할 경우[RHEL 계열]
        if [ -f /etc/pam.d/system-auth ]; then
		# /etc/pam.d/system-auth 파일에 패스워드 암호화 알고리즘 점검
		b_result11=`cat /etc/pam.d/system-auth | grep -v "#" | egrep sha[0-9]`
                if [ `cat /etc/pam.d/system-auth | egrep sha[0-9] | wc -l` -eq 0 ]; then
                     	a_result="X"
			c_result="패스워드 암호화 알고리즘이 SHA256 이상으로 설정되어 있지 않아 취약"
                else
                	b_result12=`cat /etc/pam.d/system-auth | grep pam_pwquality`
	                b_result13=`cat /etc/security/pwquality.conf | grep -v "#"`
	                c_result="패스워드 암호화 알고리즘이 SHA256 이상으로 설정되어 있으므로 양호"
			# /etc/pam.d/system-auth 파일 내 enforce_for_root 설정 여부 점검
                        if [ `cat /etc/pam.d/system-auth | grep enforce_for_root | wc -l` -eq 1 ]; then

				# /etc/pam.d/system-auth 파일 내 패스워드 복잡도 설정 여부 점검
                                if [ `cat /etc/pam.d/system-auth | grep credit | wc -l` -eq 1 ]; then
					a_result="O"
                                	c_result="/etc/pam.d/system-auth 파일에 패스워드 복잡도 설정이 되어 있으므로 양호"

				# /etc/pam.d/system-auth 파일 내 패스워드 복잡도 미설정 시
                                else
					# /etc/security/pwquality.conf 패스워드 복잡도 설정 주석 처리 점검
                                        if [ `cat /etc/security/pwquality.conf | grep -v "#" | wc -l` -eq 0 ]; then
						a_result="X"
                                                c_result="/etc/pam.d/system-auth 또는 /etc/security/pwquality.conf 파일에 패스워드 복잡도 설정이 되어 있지 않으므로 취약"

					# /etc/security/pwquality.conf 패스워드 복잡도 설정 점검
                                        else
						if [ -z `cat /etc/security/pwquality.conf | grep -v "#" | grep ucredit | awk {'print $3'}` ]; then
							a_result1="X"
							c_result1="패스워드 설정 시 영대문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
						else
							if [ `cat /etc/security/pwquality.conf | grep -v "#" | grep ucredit | awk {'print $3'}` -le -1 ]; then
								a_result1="O"
	                                                        c_result1="패스워드 설정 시 영대문자 1글자 이상 필수 포함 설정되어 있으므로 양호"
							else
								a_result1="X"
								c_result1="패스워드 설정 시 영대문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
							fi
						fi

						if [ -z `cat /etc/security/pwquality.conf | grep -v "#" | grep lcredit | awk {'print $3'}` ]; then
                                                        a_result2="X"
                                                        c_result2="패스워드 설정 시 영소문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                else
                                                        if [ `cat /etc/security/pwquality.conf | grep -v "#" | grep lcredit | awk {'print $3'}` -le -1 ]; then
                                                                a_result2="O"
                                                                c_result2="패스워드 설정 시 영소문자 1글자 이상 필수 포함 설정되어 있으므로 양호"
                                                        else
                                                                a_result2="X"
                                                                c_result2="패스워드 설정 시 영소문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                        fi
                                                fi

						if [ -z `cat /etc/security/pwquality.conf | grep -v "#" | grep dcredit | awk {'print $3'}` ]; then
                                                        a_result3="X"
                                                        c_result3="패스워드 설정 시 숫자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                else
                                                        if [ `cat /etc/security/pwquality.conf | grep -v "#" | grep dcredit | awk {'print $3'}` -le -1 ]; then
                                                                a_result3="O"
                                                                c_result3="패스워드 설정 시 숫자 1글자 이상 필수 포함 설정되어 있으므로 양호"
                                                        else
                                                                a_result3="X"
                                                                c_result3="패스워드 설정 시 숫자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                        fi
                                                fi

						if [ -z `cat /etc/security/pwquality.conf | grep -v "#" | grep ocredit | awk {'print $3'}` ]; then
                                                        a_result4="X"
                                                        c_result4="패스워드 설정 시 특수문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                else
                                                        if [ `cat /etc/security/pwquality.conf | grep -v "#" | grep ocredit | awk {'print $3'}` -le -1 ]; then
                                                                a_result4="O"
                                                                c_result4="패스워드 설정 시 특수문자 1글자 이상 필수 포함 설정되어 있으므로 양호"
                                                        else
                                                                a_result4="X"
                                                                c_result4="패스워드 설정 시 특수문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                        fi
                                                fi

						if [ $a_result1 == "O" -a $a_result2 == "O" -a $a_result3 == "O" -a $a_result4 == "O" ]; then
							a_result="O"
						else
							a_result="X"
						fi
                                        fi
                                fi
                        else
				a_result="X"
                                c_result="/etc/pam.d/system-auth 파일 내 enforce_for_root 설정이 되어 있지 않으므로 취약"
                        fi
                fi

	# /etc/pam.d/common-password 파일이 존재할 경우[Ubuntu 계열]
        else

		# /etc/pam.d/common-password 파일에 패스워드 암호화 알고리즘 점검
		b_result11=`cat /etc/pam.d/common-password | grep -v "#" | egrep sha[0-9]`
                if [ `cat /etc/pam.d/common-password | grep -v "#" | egrep sha[0-9] | wc -l` -eq 0 ]; then
				a_result="X"
	                        c_result="패스워드 암호화 알고리즘이 SHA256 이상으로 설정되어 있지 않아 취약"
                else
                        b_result12=`cat /etc/pam.d/common-password | grep pam_pwquality`
                        b_result13=`cat /etc/security/pwquality.conf | grep -v "#"`

			# /etc/pam.d/common-password 파일 내 enforce_for_root 설정 여부 점검
                        if [ `cat /etc/pam.d/common-password | grep enforce_for_root | wc -l` -eq 1 ]; then

				# /etc/pam.d/common-password 파일 내 패스워드 복잡도 설정 여부 점검
                                if [ `cat /etc/pam.d/common-password | grep credit | wc -l` -eq 1 ]; then
					a_result="O"
                                        c_result="/etc/pam.d/common-password 파일에 패스워드 복잡도 설정이 되어 있으므로 양호"

				# /etc/pam.d/common-password 파일 내 패스워드 복잡도 미설정 시
                                else
					# /etc/security/pwquality.conf 패스워드 복잡도 설정 주석 처리 점검
                                        if [ `cat /etc/security/pwquality.conf | grep -v "#" | wc -l` -eq 0 ]; then
						a_result="X"
                                                c_result="/etc/pam.d/common-password 또는 /etc/security/pwquality.conf 파일에 패스워드 복잡도 설정이 되어 있지 않으므로 취약"

					# /etc/security/pwquality.conf 패스워드 복잡도 설정 점검
					else
                                                if [ -z `cat /etc/security/pwquality.conf | grep -v "#" | grep ucredit | awk {'print $3'}` ]; then
                                                        a_result1="X"
                                                        c_result1="패스워드 설정 시 영대문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                else
                                                        if [ `cat /etc/security/pwquality.conf | grep -v "#" | grep ucredit | awk {'print $3'}` -le -1 ]; then
                                                                a_result1="O"
                                                        else
                                                                a_result1="X"
                                                                c_result1="패스워드 설정 시 영대문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                        fi
                                                fi

                                                if [ -z `cat /etc/security/pwquality.conf | grep -v "#" | grep lcredit | awk {'print $3'}` ]; then
                                                        a_result2="X"
                                                        c_result2="패스워드 설정 시 영소문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                else
                                                        if [ `cat /etc/security/pwquality.conf | grep -v "#" | grep lcredit | awk {'print $3'}` -le -1 ]; then
                                                                a_result2="O"
                                                        else
                                                                a_result2="X"
                                                                c_result2="패스워드 설정 시 영소문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                        fi
                                                fi

                                                if [ -z `cat /etc/security/pwquality.conf | grep -v "#" | grep dcredit | awk {'print $3'}` ]; then
                                                        a_result3="X"
                                                        c_result3="패스워드 설정 시 숫자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                else
                                                        if [ `cat /etc/security/pwquality.conf | grep -v "#" | grep dcredit | awk {'print $3'}` -le -1 ]; then
                                                                a_result3="O"
                                                        else
                                                                a_result3="X"
                                                                c_result3="패스워드 설정 시 숫자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                        fi
                                                fi

                                                if [ -z `cat /etc/security/pwquality.conf | grep -v "#" | grep ocredit | awk {'print $3'}` ]; then
                                                        a_result4="X"
                                                        c_result4="패스워드 설정 시 특수문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                else
                                                        if [ `cat /etc/security/pwquality.conf | grep -v "#" | grep ocredit | awk {'print $3'}` -le -1 ]; then
                                                                a_result4="O"
                                                        else
                                                                a_result4="X"
                                                                c_result4="패스워드 설정 시 특수문자 1글자 이상 필수 포함 미설정되어 있으므로 취약"
                                                        fi
                                                fi

						if [ $a_result1 == "O" -a $a_result2 == "O" -a $a_result3 == "O" -a $a_result4 == "O" ]; then
                                                        a_result="O"
                                                else
                                                        a_result="X"
                                                fi
                                        fi
                                fi
                        else
				a_result="X"
                                c_result="/etc/pam.d/common-password 파일 내 enforce_for_root 설정이 되어 있지 않으므로 취약"
                        fi
                fi
        fi
else
	a_result="O"
        c_result="/etc/ssh/sshd_config 파일 내 PasswordAuthentication 설정값이 no이고 PEM key를 사용하므로 양호"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1.PasswordAuthentication 설정값 확인
PasswordAuthentication $pass2

2.패스워드 암호화 방식 확인
$b_result11

3.패스워드 복잡도 확인
$b_result12

4.패스워드 복잡도 설정 파일(pwquality.conf) 확인
$b_result13
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
$c_result1
$c_result2
$c_result3
$c_result4
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-3(){
#--START(점검항목 설명)
CODE="U-03"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

pass1=`cat /etc/ssh/sshd_config | grep ^PasswordAuthentication`
pass2=`echo $pass1 | tr '[A-Z]' '[a-z]' | awk {'print $2'}`
b_result=`cat /etc/ssh/sshd_config | grep -v "#" | grep PasswordAuthentication`

# cat /etc/ssh/sshd_config 파일 내 PasswordAuthentication 설정이 yes일 경우
if [ $pass2 == "yes" ]; then

	# /etc/pam.d/system-auth 파일이 존재할 경우[RHEL 계열]
	if [ -f /etc/pam.d/system-auth ]; then

		# /etc/pam.d/system-auth 파일에 pam_tally 모듈 사용 여부 점검
		if [ `cat /etc/pam.d/system-auth | grep ^auth | grep pam_tally | wc -l` -eq 1 -a `cat /etc/pam.d/system-auth | grep ^account | grep pam_tally | wc -l` -eq 1 ]; then
			b_result1=`cat /etc/pam.d/system-auth | grep pam_tally`
			# pam_tally 모듈이 pam_unix 모듈보다 상단에 위치하는지 확인
                        unixnum=`cat /etc/pam.d/system-auth | grep ^auth | grep -n pam_unix.so | awk -F: {'print $1'}`
                        tallynum=`cat /etc/pam.d/system-auth | grep ^auth | grep -n pam_tally | awk -F: {'print $1'}`
                        if [ $unixnum -gt $tallynum ];then

				# pam_tally 모듈 잠금 임계값 추출
                                denycnt=`cat /etc/pam.d/system-auth | sed -rn 's/.*deny=([[:digit:]]).*/\1/p'`
                                if [ $denycnt -gt 5 ]; then
					a_result="X"
                                        c_result="/etc/pam.d/system-auth 파일에 패스워드 실패 시 잠금 설정이 되어 있으나 잠금임계값이 5를 초과하므로 취약"
                                else
					a_result="O"
                                        c_result="/etc/pam.d/system-auth 파일에 패스워드 실패 시 잠금 설정이 되어 있으며 잠금임계값이 5이하이므로 양호"
                                fi
                        else
				a_result="X"
                                c_result="/etc/pam.d/system-auth 파일에 pam_tally 모듈 위치가 잘못 설정되어 잠금 임계값이 미적용되므로 취약"
                        fi

		# /etc/pam.d/system-auth 파일에 faillock  모듈 사용 여부 점검
		elif [ `cat /etc/pam.d/system-auth | grep ^auth | grep pam_faillock | wc -l` -eq 2 -a `cat /etc/pam.d/system-auth | grep ^account | grep pam_faillock | wc -l` -eq 1 ]; then
			b_result1=`cat /etc/pam.d/system-auth | grep pam_faillock`
			unixnum=`cat /etc/pam.d/system-auth | grep ^auth | grep -n pam_unix.so | awk -F: {'print $1'}`
			prefail=`cat /etc/pam.d/system-auth | grep ^auth | grep -n preauth | awk -F: {'print $1'}`
			authfail=`cat /etc/pam.d/system-auth | grep ^auth | grep -n authfail | awk -F: {'print $1'}`
			if [ $prefail -lt $unixnum -a $authfail -gt $unixnum ]; then
				denycnt=`cat /etc/pam.d/system-auth | sed -rn 's/.*deny=([[:digit:]]).*/\1/p' | uniq`
                                if [ $denycnt -gt 5 ]; then
					a_result="X"
                                        c_result="/etc/pam.d/system-auth 파일에 패스워드 실패 시 잠금 설정이 되어 있으나 잠금임계값이 5를 초과하므로 취약"
                                else
					a_result="O"
                                        c_result="/etc/pam.d/system-auth 파일에 패스워드 실패 시 잠금 설정이 되어 있으며 잠금임계값이 5이하이므로 양호"
                                fi
                        else
				a_result="X"
                                c_result="/etc/pam.d/system-auth 파일에 faillock 모듈 위치가 잘못 설정되어 잠금 임계값이 미적용되므로 취약"
                        fi
		else
			a_result="X"
			b_result=`cat /etc/pam.d/system-auth`
			c_result="/etc/pam.d/system-auth 파일에 계정 잠금 임계값이 미설정되어 있으므로 취약"
		fi

		# /etc/pam.d/password-auth 파일에 pam_tally 모듈 사용 여부 점검
                if [  `cat /etc/pam.d/password-auth | grep ^auth | grep pam_tally | wc -l` -eq 1 -a  `cat /etc/pam.d/password-auth | grep ^account | grep pam_tally | wc -l` -eq 1 ]; then
			b_result2=`cat /etc/pam.d/password-auth | grep pam_tally`
			# pam_tally 모듈이 pam_unix 모듈보다 상단에 위치하는지 확인
                        unixnum=`cat /etc/pam.d/password-auth | grep ^auth | grep -n pam_unix.so | awk -F: {'print $1'}`
                        tallynum=`cat /etc/pam.d/password-auth | grep ^auth | grep -n pam_tally | awk -F: {'print $1'}`
                        if [ $unixnum -gt $tallynum ];then

				# pam_tally 모듈 잠금 임계값 추출
                                denycnt=`cat /etc/pam.d/password-auth | sed -rn 's/.*deny=([[:digit:]]).*/\1/p'`
                                if [ $denycnt -gt 5 ]; then
					a_result="X"
                                        c_result="/etc/pam.d/password-auth 파일에 패스워드 실패 시 잠금 설정이 되어 있으나 잠금임계값이 5를 초과하므로 취약"
                                else
					a_result="O"
                                        c_result="/etc/pam.d/password-auth 파일에 패스워드 실패 시 잠금 설정이 되어 있으며 잠금임계값이 5이하이므로 양호"
                                fi
                        else
				a_result="X"
                                c_result="pam_tally 모듈 위치가 잘못 설정되어 잠금 임계값이 미적용되므로 취약"
                        fi

		# /etc/pam.d/password-auth 파일에 faillock  모듈 사용 여부 점검
                elif [  `cat /etc/pam.d/password-auth | grep ^auth | grep pam_faillock | wc -l` -eq 2 -a  `cat /etc/pam.d/password-auth | grep ^account | grep pam_faillock | wc -l` -eq 1 ]; then
			b_result2=`cat /etc/pam.d/password-auth | grep pam_faillock`
                        unixnum=`cat /etc/pam.d/password-auth | grep ^auth | grep -n pam_unix.so | awk -F: {'print $1'}`
                        prefail=`cat /etc/pam.d/password-auth | grep ^auth | grep -n preauth | awk -F: {'print $1'}`
                        authfail=`cat /etc/pam.d/password-auth | grep ^auth | grep -n authfail | awk -F: {'print $1'}`
                        if [ $prefail -lt $unixnum -a $authfail -gt $unixnum ]; then
                                denycnt=`cat /etc/pam.d/password-auth | sed -rn 's/.*deny=([[:digit:]]).*/\1/p' | uniq`
                                if [ $denycnt -gt 5 ]; then
					a_result="X"
                                        c_result="/etc/pam.d/password-auth 파일에 패스워드 실패 시 잠금 설정이 되어 있으나 잠금임계값이 5를 초과하므로 취약"
                                else
					a_result="O"
                                        c_result="/etc/pam.d/password-auth 파일에 패스워드 실패 시 잠금 설정이 되어 있으며 잠금임계값이 5이하이므로 양호"
                                fi
                        else
				a_result="X"
                                c_result="/etc/pam.d/password-auth 파일에 faillock 모듈 위치가 잘못 설정되어 잠금 임계값이 미적용되므로 취약"
                        fi
                else
			a_result="X"
                        c_result="/etc/pam.d/password-auth 파일에 계정 잠금 임계값이 미설정되어 있으므로 취약"
                fi

	# /etc/pam.d/common-auth 파일이 존재할 경우[Ubuntu 계열]
	else
		# /etc/pam.d/common-auth 파일에 pam_tally 모듈 사용 여부 점검
                autally=`cat /etc/pam.d/common-auth | grep ^auth | grep pam_tally | wc -l`
		b_result3=`cat /etc/pam.d/common-auth | grep pam_tally`
                if [ $autally -eq 1 ]; then

			# pam_tally 모듈 잠금 임계값 추출
                        denycnt=`cat /etc/pam.d/common-auth | sed -rn 's/.*deny=([[:digit:]]).*/\1/p'`
                        if [ $denycnt -gt 5 ]; then
				a_result="X"
                                c_result="패스워드 실패 시 잠금 설정이 되어 있으나 잠금임계값이 5를 초과하므로 취약"
                        else
				a_result="O"
                                c_result="패스워드 실패 시 잠금 설정이 되어 있으며 잠금임계값이 5이하이므로 양호"
                        fi
                else
			a_result="X"
                        c_result="계정 잠금 임계값이 미설정되어 있으므로 취약"
                fi
	fi
else
	a_result="O"
	c_result="PasswordAuthentication 설정이 no이고 PEM key를 사용하므로 양호"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. 패스워드 방식 사용하는지 확인
$b_result

2. 패스워드 임계값 모듈 사용 점검
/etc/pam.d/system-auth에 pam_tally, pam_faillock 모듈 사용하는지 여부 확인(콘솔 로그인, su 전환)
$b_result1

/etc/pam.d/password-auth에 pam_tally, pam_faillock 모듈 사용하는지 여부 확인(telnet, ssh, ftp 원격 접속)
$b_result2

/etc/pam.d/common-auth에 pam_tally 모듈 사용하는지 여부 확인
$b_result3
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-4(){
#--START(점검항목 설명)
CODE="U-04"
MEASURES="단기"
#--END

#--START(점검 명령어)

if [ `cat /etc/passwd | awk -F: '{print $1":" $2}' | grep x | wc -l` -eq `cat /etc/passwd | wc -l` ] ; then
	a_result="O"
	c_result="shadow 패스워드를 사용하여 /etc/passwd 파일 내 두번째 필드가 x 이므로 양호"
else
	a_result="X"
	c_result="shadow 패스워드를 사용하지 않아 /etc/passwd 파일 내 두번째 필드가 x가 아니므로 취약"
fi

b_result=`cat /etc/passwd | awk -F: '{print $1":" $2}'`
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. /etc/shadow 파일을 사용하고 있는지 확인
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-5(){
#--START(점검항목 설명)
CODE="U-05"
MEASURES="단기"
#--END

#--START(점검 명령어)

b_result=`awk -F: '{if ($3 == "0") print $1" "$3}' /etc/passwd`

if [ `cat /etc/passwd | awk -F: '{print $3}' | grep -w "0" | wc -l` -eq 1 ] ; then
	a_result="O"
        c_result="root 계정과 같은 UID를 가진 계정이 존재하지 않으므로 양호"
else
	a_result="X"
        c_result="root 계정과 같은 UID를 가진 계정이 존재하므로 취약"
fi

ruid=`cat /etc/passwd | grep ^root | awk -F: {'print $3'}`
for value in $(cat /etc/passwd | grep -v ^root | awk -F: {'print $3'}); do
	if [ $ruid == $value ]; then
		a_result="X"
		c_result="root 계정과 같은 UID를 가진 계정이 존재하므로 취약"
        else
		a_result="O"
        	c_result="root 계정과 같은 UID를 가진 계정이 존재하지 않으므로 양호"
        fi
done
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. root와 동일한 UID를 사용하는 계정이 있는지 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-6(){
#--START(점검항목 설명)
CODE="U-06"
MEASURES="단기"
#--END

#--START(점검 명령어)

usewhl=`cat /etc/pam.d/su | grep -v "#" | grep pam_wheel.so | wc -l`
nullcheck=`cat /etc/group | grep wheel | awk -F: {'print $4'} | awk -F',' {'print $2'}`
b_result=`cat /etc/pam.d/su | grep -v "#" | grep pam_wheel.so`
b_result1=`cat /etc/group | grep wheel`

if [ $usewhl -gt 0 ]; then
	if [ `cat /etc/group | grep wheel | wc -l` -eq 1 ]; then
		if [ -z "$nullcheck" ]; then
			a_result="O"
			c_result="/etc/group 파일 내 wheel 그룹에 기본 계정(ec2-user, ubuntu, admin 등) 외에 일반 계정이 존재하지 않으므로 양호"
	        else
			a_result="-"
			c_result="/etc/group 파일 내 wheel 그룹에 기본 계정(ec2-user, ubuntu, admin 등) 외에  일반 계정이 존재하므로 인터뷰 시 확인 필요"
		fi
	else
		a_result="X"
		c_result="/etc/group 파일 내 wheel 그룹이 존재하지 않으므로 취약"
	fi
else
	b_result2=`ls -l /bin/su | awk {'print $1"  "$3"  "$4'}`
	if [ `cat /etc/group | grep wheel | wc -l` -eq 1 ]; then
	        if [ "`f_permit /bin/su 4750`" == "OK" ]; then
			if [ `ls -l /bin/su | awk {'print $4'}` == "wheel" ]; then
				if [ -z "$nullcheck" ]; then
					a_result="O"
					c_result="/etc/group 파일 내 wheel 그룹에 기본 계정(ec2-user, ubuntu, admin 등) 외에 일반 계정이 존재하지 않으므로 양호"
			        else
					a_result="-"
        	        		c_result="/etc/group 파일 내 wheel 그룹에 기본 계정(ec2-user, ubuntu, admin 등) 외에  일반 계정이 존재하므로 인터뷰 시 확인 필요"
			        fi
			else
				a_result="X"
				c_result="/bin/su 파일의 권한이 4750으로 설정되어 있으나 소유그룹이 wheel이 아니므로 취약"
			fi
		else
			a_result="X"
			c_result="/bin/su 파일의 권한이 4750이 아니므로 취약"
		fi
	else
		a_result="X"
                c_result="/etc/group 파일 내 wheel 그룹이 존재하지 않으므로 취약"
	fi
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. /etc/pam.d/su 파일내의 pam_wheel.so 모듈 사용 점검
$b_result

2. su 명령어 사용권한 점검
$b_result2

3. wheel 그룹 계정 확인
$b_result1
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-7(){
#--START(점검항목 설명)
CODE="U-07"
MEASURES="Hot-Fix"
#--END


#--START(점검 명령어)

pass1=`cat /etc/ssh/sshd_config | grep ^PasswordAuthentication`
pass2=`echo $pass1 | tr '[A-Z]' '[a-z]' | awk {'print $2'}`

# cat /etc/ssh/sshd_config 파일 내 PasswordAuthentication 설정이 yes일 경우
if [ $pass2 == "yes" ]; then
	# /etc/pam.d/system-auth 파일이 존재할 경우[RHEL 계열]
	b_result1=`cat /etc/pam.d/system-auth | grep -v "#"`
	b_result2=`cat /etc/security/pwquality.conf | grep -v "#" | grep minlen`
	b_result3=`cat /etc/login.defs | grep -v "#" | grep PASS_MIN_LEN`
        if [ `ls -al /etc/pam.d/system-auth | wc -l` -eq 1 ]; then

	# /etc/pam.d/system-auth 파일 내 패스워드 최소 길이 설정 여부 점검
	        if [ `cat /etc/pam.d/system-auth | grep minlen | wc -l` -eq 1 ]; then
			if [ `cat /etc/pam.d/system-auth | sed -rn 's/.*minlen=([[:digit:]]).*/\1/p'` -ge 8 ]; then
				a_result="O"
	                	c_result="/etc/pam.d/system-auth 파일에 패스워드 최소 길이가 8자 이상으로 설정되어 있으므로 양호"
			else
				a_result="X"
				c_result="/etc/pam.d/system-auth 파일에 패스워드 최소 길이가 8자 미만으로 설정되어 있으므로 취약"
			fi

		# /etc/pam.d/system-auth 파일 내 패스워드 최소 길이  미설정 시
                else
			# /etc/security/pwquality.conf 파일 내 패스워드 최소 길이 설정  점검
                        if [ `cat /etc/security/pwquality.conf | grep -v "#" | grep minlen | wc -l` -eq 1 ]; then
				if [ `cat /etc/security/pwquality.conf | grep minlen | awk -F'=' {'print $2'}` -ge 8 ]; then
					a_result="O"
	                        	c_result="/etc/security/pwquality.conf 파일에 패스워드 최소 길이가 8자 이상으로 설정되어 있으므로 양호"
				else
					a_result="X"
					c_result="/etc/security/pwquality.conf 파일에 패스워드 최소 길이가 8자 미만으로 설정되어 있으므로 취약"
	                        fi
                        else
				# /etc/login.defs 파일 내 패스워드 최소 길이 설정 점검
				if [ `cat /etc/login.defs | grep -v "#" | grep PASS_MIN_LEN | wc -l` -eq 0 ]; then
					a_result="X"
					c_result="/etc/login.defs 파일에 패스워드 최소 길이가 설정되어 있지 않으므로 취약"
				else
					if [ `cat /etc/login.defs | grep -v "#" | grep PASS_MIN_LEN | awk {'print $2'}` -ge 8 ]; then
						a_result="O"
						c_result="/etc/login.defs 파일에 패스워드 최소 길이가 8자 이상으로 설정되어 있으므로 양호"
					else
						a_result="X"
						c_result="/etc/login.defs 파일에 패스워드 최소 길이가 8자 미만으로 설정되어 있으므로 취약"
					fi
				fi
                        fi
                fi

	# /etc/pam.d/common-password 파일이 존재할 경우[Ubuntu 계열]
        else
	b_result1=`cat /etc/pam.d/common-password | grep -v "#"`
        b_result2=`cat /etc/security/pwquality.conf | grep -v "#" | grep minlen`
        b_result3=`cat /etc/login.defs | grep -v "#" | grep PASS_MIN_LEN`
	# /etc/pam.d/common-password 파일 내 패스워드 최소 길이 설정 여부 점검
                if [ `cat /etc/pam.d/common-password | grep minlen | wc -l` -eq 1 ]; then
                        if [ `cat /etc/pam.d/common-password | sed -rn 's/.*minlen=([[:digit:]]).*/\1/p'` -ge 8 ]; then
				a_result="O"
                                c_result="/etc/pam.d/common-password 파일에 패스워드 최소 길이가 8자 이상으로 설정되어 있으므로 양호"
                        else
				a_result="X"
                                c_result="/etc/pam.d/common-password 파일에 패스워드 최소 길이가 8자 미만으로 설정되어 있으므로 취약"
                        fi
                # /etc/pam.d/common-password 파일 내 패스워드 최소 길이  미설정 시
                else
                        # /etc/security/pwquality.conf 파일 내 패스워드 최소 길이 설정  점검
                        if [ `cat /etc/security/pwquality.conf | grep -v "#" | grep minlen | wc -l` -eq 1 ]; then
                                if [ `cat /etc/security/pwquality.conf | grep minlen | awk -F'=' {'print $2'}` -ge 8 ]; then
					a_result="O"
                                        c_result="/etc/security/pwquality.conf 파일에 패스워드 최소 길이가 8자 이상으로 설정되어 있으므로 양호"
                                else
					a_result="X"
                                        c_result="/etc/security/pwquality.conf 파일에 패스워드 최소 길이가 8자 미만으로 설정되어 있으므로 취약"
                                fi
                        else
				# /etc/login.defs 파일 내 패스워드 최소 길이 설정 점검
                                if [ `cat /etc/login.defs | grep -v "#" | grep PASS_MIN_LEN | wc -l` -eq 0 ]; then
                                        a_result="X"
                                        c_result="/etc/login.defs 파일에 패스워드 최소 길이가 설정되어 있지 않으므로 취약"
                                else
                                        if [ `cat /etc/login.defs | grep -v "#" | grep PASS_MIN_LEN | awk {'print $2'}` -ge 8 ]; then
                                                a_result="O"
                                                c_result="/etc/login.defs 파일에 패스워드 최소 길이가 8자 이상으로 설정되어 있으므로 양호"
                                        else
                                                a_result="X"
                                                c_result="/etc/login.defs 파일에 패스워드 최소 길이가 8자 미만으로 설정되어 있으므로 취약"
                                        fi
                                fi
                        fi
                fi
	fi
else
	a_result="O"
	c_result="PasswordAuthentication 설정이 no이고 PEM key를 사용하므로 양호"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. 패스워드 최소 길이 설정 파일 점검
$b_result1

2. /etc/security/pwquality.conf파일의 minlen 값 확인
$b_result2

3. /etc/login.defs 파일의 PASS_MIN_LEN 값 확인
$b_result3
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-8(){
#--START(점검항목 설명)
CODE="U-08"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)
pass1=`cat /etc/ssh/sshd_config | grep ^PasswordAuthentication`
pass2=`echo $pass1 | tr '[A-Z]' '[a-z]' | awk {'print $2'}`

if [ $pass2 == "yes" ]; then
	b_result=`cat /etc/login.defs | grep -v "#" | grep PASS_MAX_DAYS`

	if [ `cat /etc/login.defs | grep -v "#" | grep PASS_MAX_DAYS | wc -l` -gt 0 ] ; then
		if [ `cat /etc/login.defs | grep -v "#" | grep PASS_MAX_DAYS | awk '{print $2}'` -le 180 ] ; then
			list=($(cat /etc/shadow | grep '\''$' | awk -F: {'print $1'}))
			b_result2=`cat /etc/shadow | grep '\''$' | awk -F: {'print $1":"$5'}`
			for((i=0;i<${#list[@]};i++))
			do
 				if [ `cat /etc/shadow | grep -w ${list[$i]} | awk -F: {'print $5'}` -gt 180 ]; then
					result[$i]="X"
				else
					result[$i]="O"
				fi
			done
			if [ `echo ${result[@]} | grep X | wc -l` -gt 0 ]; then
				a_result="X"
                                c_result="패스워드 최대 사용기간이 180일 이하로 설정되어 있지만 패스워드 최대 사용기간이 180일을 초과하도록 설정된 사용자 계정이 존재하므로 취약"
			else
				a_result="O"
                                c_result="패스워드 최대 사용기간이 180일 이하로 설정되어 있으므로 양호"
			fi
		else
			a_result="X"
			c_result="패스워드 최대 사용기간이 180일 초과로 설정되어 있으므로 취약"
		fi
	else
		a_result="X"
		c_result="패스워드 최대 사용기간이 설정되어 있지 않으므로 취약"
	fi
else
	a_result="O"
	c_result="/etc/ssh/sshd_config 파일 내 PasswordAuthentication 설정값이 no이고 PEM key를 사용하므로 양호"
fi
#--END
d_result=``
d_result2=`cat /etc/shadow | grep '\''$' | awk -F: {'print $1":"$5'}`

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. 패스워드가 설정된 계정의 최대 사용기간 확인
$b_result2

2. /etc/login.defs의 PASS_MAX_DAYS 확인
$b_result
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-9(){
#--START(점검항목 설명)
CODE="U-09"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

pass1=`cat /etc/ssh/sshd_config | grep ^PasswordAuthentication`
pass2=`echo $pass1 | tr '[A-Z]' '[a-z]' | awk {'print $2'}`
if [ $pass2 == "yes" ]; then
        minpw=`cat /etc/login.defs | grep -v "#" | grep PASS_MIN_DAYS | wc -l`
        b_result=`cat /etc/login.defs | grep -v "#" | grep PASS_MIN_DAYS`

	if [ `cat /etc/login.defs | grep -v "#" | grep PASS_MIN_DAYS | wc -l` -gt 0 ] ; then
                if [ `cat /etc/login.defs | grep -v "#" | grep PASS_MIN_DAYS | awk '{print $2}'` -gt 0 ] ; then
                        list=($(cat /etc/shadow | grep '\''$' | awk -F: {'print $1'}))
                        b_result2=`cat /etc/shadow | grep '\''$' | awk -F: {'print $1":"$4'}`
                        for((i=0;i<${#list[@]};i++))
                        do
                                if [ `cat /etc/shadow | grep -w ${list[$i]} | awk -F: {'print $4'}` -gt 0 ]; then
                                        result[$i]="X"
                                else
                                        result[$i]="O"
                                fi
                        done
                        if [ `echo ${result[@]} | grep X | wc -l` -gt 0 ]; then
                                a_result="X"
				c_result="패스워드 최소 사용기간이 1일 이상으로 설정되어 있지만 패스워드 최소 사용기간이 0일로 설정된 사용자 계정이 존재하므로 취약"
                        else
                                a_result="O"
				c_result="패스워드 최소 사용기간이 1일 이상으로 설정되어 있으므로 양호"
                        fi
                else
                        a_result="X"
                        c_esult="패스워드 최소 사용기간이 0일로 설정되어 있으므로 취약"
                fi
        else
                a_result="X"
                c_result="패스워드 최소 사용기간이 설정되어 있지 않으므로 취약"
        fi
else
        a_result="O"
        c_result="/etc/ssh/sshd_config 파일 내 PasswordAuthentication 설정값이 no이고 PEM key를 사용하므로 양호"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. 패스워드가 설정된 계정 최소 사용기간 확인
$b_result2

2. /etc/login.defs의 PASS_MIN_DAYS 확인
$b_result
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-10(){
#--START(점검항목 설명)
CODE="U-10"
MEASURES="단기"
#--END

#--START(점검 명령어)
loglist=`lastlog -t 30 | awk {'print $1'} | grep -v Username`
b_result=`awk -F: '{if ($3 >= 500) print $1"  "$3}' /etc/passwd | grep -v nobody`
b_result2=`lastlog`

for pwlist in `awk -F: '{if ($3 >= 500) print $1}' /etc/passwd | grep -v nobody`
do
        if [ `echo $loglist | grep -w "$pwlist" | wc -l` -eq 0 ]; then
                result="$result X"
		b_result3="$b_result3
`lastlog | grep -w $pwlist`"
        else
                result="$result O"
		b_result3="$b_result3
`lastlog | grep -w $pwlist`"
        fi
done

if [ `echo $result | grep X | wc -l` -gt 0 ]; then
	a_result="X"
	c_result="30일 동안 접속하지 않은 불필요한 사용자 계정이 존재하므로 취약"
else
	a_result="O"
	c_result="불필요한 계정이 존재하지 않으므로 양호"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. UID 500이상 계정 리스트
$b_result

2. 계정 접속 현황 점검
$b_result2

3. UID 500 이상 계정 접속 현황 점검
$b_result3
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-11(){
#--START(점검항목 설명)
CODE="U-11"
MEASURES="단기"
#--END

#--START(점검 명령어)

b_result=`cat /etc/group | grep root`

if [ -z `cat /etc/group | grep root | awk -F: '{print $4}'` ]; then
	a_result="O"
	c_result="root 그룹에 등록된 사용자 계정이 존재하지 않으므로 양호"
else
	a_result="-"
	c_result="root 그룹에 등록된 사용자 계정이 존재하므로 인터뷰 시 확인 필요"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. root 그룹에 등록된 사용자 정보 확인
$b_result
"

chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-12(){
#--START(점검항목 설명)
CODE="U-12"
MEASURES="단기"
#--END

#--START(점검 명령어)
for glist in `cat /etc/group | awk -F: {'print $1'} | sort`

do
        # /etc/group에 있는 그룹명과 /etc/passwd에 있는 계정명을 매칭
        if [ `cat /etc/passwd | awk -F: {'print $1'} | grep -w "$glist" | wc -l` -eq 0 ]; then

                b_result11="$b_result11
                `cat /etc/group | grep -w $glist | awk -F: {'print $1'}`"

                # /etc/group에서 각 그룹에 포함된 계정이 존재하지 않는 그룹일 경우
                if [ -z `cat /etc/group | grep -w $glist | awk -F: {'print $4'}` ]; then
                      b_result12="$b_result12
`cat /etc/group | grep -w $glist`"

                      result="$result X"
                fi
        fi
done

if [ `echo $result | grep X | wc -l` -gt 0 ]; then
	a_result1="X"
        c_result1="계정이 포함되지 않는 그룹이 존재하므로 취약"
else
	a_result1="O"
        c_result1="모든 그룹에 계정이 포함되어 있으므로 양호"
fi

#계정명과 그룹명 비교
for ulist in `cat /etc/passwd | awk -F: {'print $4'}`
do
	if [ `cat /etc/group | awk -F: {'print $3'} | grep -w "$ulist" | wc -l` -eq 0 ]; then
		b_result2="$b_result2
`cat /etc/passwd | grep -w "$ulist" | awk -F: {'print $1'}`"
		result2="$result2 X"
	else
		result2="$result2 O"
	fi
done

if [ `echo $result2 | grep X | wc -l` -gt 0 ]; then
	a_result2="X"
	c_result2="/etc/group 파일에 존재하지 않는 GID를 가진 계정이 존재하므로 취약"
else
	a_result2="O"
	c_result2="모든 계정이 /etc/group 파일에 존재하는 GID를 부여받았으므로 양호"
fi

if [ $a_result1 == "O" -a $a_result2 == "O" ]; then
	a_result="O"
else
	a_result="X"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1./etc/passwd 파일의 계정명과 일치하지 않는 그룹
$b_result11

2. 그룹에 계정이 존재하지 않는 그룹
$b_result12

3./etc/passwd 와 /etc/group의 GID를 매핑하여 불일치 점검
$b_result2
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result1
$c_result2
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-13(){
#--START(점검항목 설명)
CODE="U-13"
MEASURES="단기"
#--END

#--START(점검 명령어)

if [ `cat /etc/passwd | awk -F: '{print $3}' | sort | uniq -d | wc -l` -gt 0 ]; then
	a_result="X"
	grepopt=`cat /etc/passwd | awk -F: '{print $3}' | sort | uniq -d`
	b_result=`cat /etc/passwd | grep "x:$grepopt"`
	c_result="동일한 UID를 갖는 계정이 존재하므로 취약"
else
	a_result="O"
	c_result="동일한 UID를 갖는 계정이 존재하지 않으므로 양호"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. /etc/passwd 파일 내 동일 UID를 갖는 계정 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-14(){
#--START(점검항목 설명)
CODE="U-14"
MEASURES="단기"
#--END

#--START(점검 명령어)

if [ `cat /etc/passwd | awk -F: {'print $1" "$7'} | egrep "/bin/bash|/bin/sh" | egrep -v "root|ec2-user|ubuntu|admin" | wc -l` -gt 0 ]; then
	a_result="-"
        b_result=`cat /etc/passwd | awk -F: {'print $1" "$7'} | egrep "/bin/bash|/bin/sh" | egrep -v "root|ec2-user|ubuntu|admin"`
	c_result="기본 계정(root, ec2-user, ubuntu, admin)을 제외한 /bin/bash 또는 /bin/sh 권한을 갖는 일반 계정이 존재하므로 인터뷰 시 확인 필요"
else
	a_result="O"
        c_result="기본 계정(root, ec2-user, ubuntu, admin)만 /bin/bash 또는 /bin/sh 권한이 설정되어 있으므로 양호"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. 기본 계정을 제외한 /bin/bash 또는 /bin/sh 쉘 권한이 부여된 사용자 계정 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-15(){
#--START(점검항목 설명)
CODE="U-15"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

if [ `cat /etc/ssh/sshd_config | grep -v "#" | grep ClientAliveInterval | wc -l` -gt 0 ]; then
	palive=`cat /etc/ssh/sshd_config | grep -v "#" | grep ClientAliveInterval | awk {'print $2'}`
	b_result1=`cat /etc/ssh/sshd_config | grep -v "#" | grep ClientAliveInterval`
	if [ `cat /etc/ssh/sshd_config | grep -v "#" | grep ClientAliveInterval | awk {'print $2'}` -le 600 ]; then
		a_result1="O"
		c_result1="세션 타임아웃이 $palive초 이하로 설정되어 있으므로 양호"
	else
		a_result1="X"
                c_result1="세션 타임아웃이 $palive초로 초과 설정되어 있으므로 취약"
	fi
else
	a_result1="X"
	c_result1="세션 타임아웃이 설정되어 있지 않으므로 취약"
fi

if [ `cat /etc/profile | grep TMOUT | wc -l` -gt 0 ]; then
	ptmout=`cat /etc/profile | grep TMOUT | awk -F'=' {'print $2'}`
	b_result2=`cat /etc/profile | grep TMOUT`
	if [ `cat /etc/profile | grep TMOUT | awk -F'=' {'print $2'}` -le 600 ]; then
		a_result2="O"
		c_result2="세션 타임아웃이 $ptmout초 이하로 설정되어 있으므로 양호"
	elif [ `cat /etc/profile | grep TMOUT | awk -F'=' {'print $2'}` -gt 600 ]; then
		a_result2="X"
		c_result2="세션 타임아웃이 $ptmout초로 초과 설정되어 있으므로 취약"
	fi
else
	a_result2="X"
	c_result2="세션 타임아웃이 설정되어 있지 않으므로 취약"
fi

if [ $a_result1 == "O" -o $a_result2 == "O" ]; then
	a_result="O"
else
	a_result="X"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. /etc/ssh/sshd_config 파일 내 ClientAliveInterval 값 점검
$b_result1
2. /etc/profile 파일 내 TMOUT 설정값 점검
$b_result2
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result1
$c_result2
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-16(){
#--START(점검항목 설명)
CODE="U-16"
MEASURES="단기"
#--END

#--START(점검 명령어)

b_result=`echo ${PATH}`
if [ `echo ${PATH} | egrep '(\.\/|\:\:)' | wc -l` -eq 0 ]; then
	a_result="O"
	c_result="PATH 환경변수에 .이나 ::이 포함되어 있지 않으므로 양호"
else
	a_result="X"
	c_result="PATH 환경변수에 .이나 ::이 포함되어 있으므로 취약"
fi
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult=" PATH 환경변수 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-17(){
#--START(점검항목 설명)
CODE="U-17"
MEASURES="단기"
#--END

#--START(점검 명령어)
find /etc /home /tmp /var ! \( \( -path '/var/lib/docker' \) -prune -o \( -path '/var/lib/kublet' \) -prune \) \( -nouser -o -nogroup \) -print -exec ls -al {} \; 2> /dev/null > U-17_No_User_Group.txt

if [ `cat U-17_No_User_Group.txt | wc -l` -eq 0 ]; then
	a_result="O"
	c_result="소유자 또는 그룹이 없는 파일이나 디렉터리가 존재하지 않으므로 양호"
else
	a_result="X"
	c_result="소유자 또는 그룹이 없는 파일이나 디렉터리가 존재하므로 취약"
fi
#--END

#--START(점검 방법)
scriptResult="1. 소유자 및 소유 그룹이 없는 파일 및 디렉터리
U-17_No_User_Group.txt 파일 참고

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-18(){
#--START(점검항목 설명)
CODE="U-18"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

if [ -f /etc/passwd ]; then
	if [ "`f_permit /etc/passwd 644`" == "OK" ]; then
		if [ "`ls -l /etc/passwd | awk {'print $3'}`" == "root" ]; then
			a_result="O"
			c_result="/etc/passwd 파일의 권한이 644 이하이며, 소유자가 root이므로 양호"
		else
			a_result="X"
			c_result="/etc/passwd 파일의 권한이 644 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
		fi
	else
		a_result="X"
		c_result="/etc/passwd 파일의 권한이 644를 초과하므로 취약"
	fi
else
	a_result="N/A"
	c_result="/etc/passwd 파일이 존재하지 않으므로 해당사항 없음"
fi

b_result=`ls -al /etc/passwd 2> /dev/null`
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. /etc/passwd 파일의 소유자 및 권한 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-19(){
#--START(점검항목 설명)
CODE="U-19"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

if [ -f /etc/shadow ]; then
	if [ "`f_permit /etc/shadow 400`" == "OK" ]; then
		if [ "`ls -l /etc/shadow | awk {'print $3'}`" == "root" ]; then
			a_result="O"
			c_result="/etc/shadow 파일의 권한이 400 이하이며, 소유자가 root이므로 양호"
		else
			a_result="X"
			c_result="/etc/shadow 파일의 권한이 400 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
		fi
	else
		a_result="X"
		c_result="/etc/shadow 파일의 권한이 400 초과이므로 취약"
	fi
else
	a_result="N/A"
	c_result="/etc/shadow 파일이 존재하지 않으므로 해당사항 없음"
fi

b_result=`ls -al /etc/shadow 2> /dev/null`
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. /etc/shadow 파일의 소유자 및 권한 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-20(){
#--START(점검항목 설명)
CODE="U-20"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

if [ -f /etc/hosts ]; then
	if [ "`f_permit /etc/hosts 600`" == "OK" ]; then
		if [ "`ls -l /etc/hosts | awk {'print $3'}`" == "root" ]; then
			a_result="O"
			c_result="/etc/hosts 파일의 권한이 600 이하이며, 소유자가 root이므로 양호"
		else
			a_result="X"
			c_result="/etc/hosts 파일의 권한이 600 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
		fi
	else
		a_result="X"
		c_result="/etc/hosts 파일의 권한이 600 초과이므로 취약"
	fi
else
	a_result="N/A"
	c_result="/etc/hosts 파일이 존재하지 않으므로 해당사항 없음"
fi

b_result=`ls -al /etc/hosts 2> /dev/null`
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. /etc/hosts 파일의 소유자 및 권한 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-21(){
#--START(점검항목 설명)
CODE="U-21"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

if [ -f /etc/inetd.conf ]; then
	if [ "`f_permit /etc/inetd.conf 600`" == "OK" ]; then
		if [ "`ls -l /etc/inetd.conf | awk {'print $3'}`" == "root" ]; then
			a_result1="O"
			c_result1="/etc/inetd.conf 파일의 권한이 600 이하이며, 소유자가 root이므로 양호"
		else
			a_result1="X"
			c_result1="/etc/inetd.conf 파일의 권한이 600 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
		fi
	else
		a_result1="X"
		c_result1="/etc/inetd.conf 파일의 권한이 600 초과이므로 취약"
	fi
else
	a_result1="N/A"
	c_result1="/etc/inetd.conf 파일이 존재하지 않으므로 해당사항 없음"
fi

if [ -f /etc/xinetd.conf ]; then
        if [ "`f_permit /etc/xinetd.conf 600`" == "OK" ]; then
                if [ `ls -l /etc/xinetd.conf | awk {'print $3'}` == "root" ]; then
			a_result2="O"
                        c_result2="/etc/xinetd.conf 파일의 권한이 600 이하이며, 소유자가 root이므로 양호"
                else
			a_result2="X"
                        c_result2="/etc/xinetd.conf 파일의 권한이 600 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
                fi
        else
		a_result2="X"
                c_result2="/etc/xinetd.conf 파일의 권한이 600 초과이므로 취약"
        fi
else
	a_result2="N/A"
        c_result2="/etc/xinetd.conf 파일이 존재하지 않으므로 해당사항 없음"
fi

if [ $a_result1 == "N/A" -a $a_result2 == "N/A" ]; then
        a_result="N/A"
elif [ $a_result1 == "O" -o $a_result2 == "O" ]; then
        a_result="O"
else
        a_result="X"
fi


b_result1=`ls -al /etc/inetd.conf 2> /dev/null`
b_result2=`ls -al /etc/xinetd.conf 2> /dev/null`
#--END

# 명령 출력 #

#--START(점검 방법)
scriptResult="1. /etc/inetd.conf 파일의 소유자 및 권한 점검
$b_result1

2. /etc/xinetd.conf 파일의 소유자 및 권한 점검
$b_result2
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result1
$c_result2
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-22(){
#--START(점검항목 설명)
CODE="U-22"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

if [ -f /etc/syslog.conf ]; then
        if [ "`f_permit /etc/syslog.conf 644`" == "OK" ]; then
                if [ "`ls -l /etc/syslog.conf | awk {'print $3'}`" == "root" ]; then
			a_result1="O"
                        c_result1="/etc/syslog.conf 파일의 권한이 644 이하이며, 소유자가 root이므로 양호"
                else
			a_result1="X"
                        c_result1="/etc/syslog.conf 파일의 권한이 644 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
                fi
        else
		a_result1="X"
                c_result1="/etc/syslog.conf 파일의 권한이 644 초과이므로 취약"
        fi
else
	a_result1="N/A"
        c_result1="/etc/syslog.conf 파일이 존재하지 않으므로 해당사항 없음"
fi

b_result1=`ls -al /etc/syslog.conf 2> /dev/null`

if [ -f /etc/rsyslog.conf ]; then
	if [ "`f_permit /etc/rsyslog.conf 644`" == "OK" ]; then
		if [ `ls -l /etc/rsyslog.conf | awk {'print $3'}` == "root" ]; then
			a_result2="O"
			c_result2="/etc/rsyslog.conf 파일의 권한이 644 이하이며, 소유자가 root이므로 양호"
		else
			a_result2="X"
			c_result2="/etc/rsyslog.conf 파일의 권한이 644 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
		fi
	else
		a_result2="X"
		c_result="/etc/rsyslog.conf 파일의 권한이 644 초과이므로 취약"
	fi
else
	a_result2="N/A"
	c_result2="/etc/rsyslog.conf 파일이 존재하지 않으므로 해당사항 없음"
fi

if [ $a_result1 == "N/A" -a $a_result2 == "N/A" ]; then
	a_result="N/A"
elif [ $a_result1 == "O" -o $a_result2 == "O" ]; then
	a_result="O"
else
	a_result="X"
fi

b_result2=`ls -al /etc/rsyslog.conf 2> /dev/null`
#--END

#--START(점검 방법)
scriptResult="1. /etc/syslog.conf 파일의 소유자 및 권한 점검
$b_result1

2. /etc/rsyslog.conf 파일의 소유자 및 권한 점검
$b_result2
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result1
$c_result2
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-23(){
#--START(점검항목 설명)
CODE="U-23"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

if [ -f /etc/services ]; then
	if [ "`f_permit /etc/services 644`" == "OK" ]; then
		if [ "`ls -l /etc/services | awk {'print $3'}`" == "root" ]; then
			a_result="O"
			c_result="/etc/services 파일의 권한이 644 이하이며, 소유자가 root이므로 양호"
		else
			a_result="X"
			c_result="/etc/services 파일의 권한이 644 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
		fi
	else
		a_result="X"
		c_result="/etc/services 파일의 권한이 644 초과이므로 취약"
	fi
else
	a_result="N/A"
	c_result="/etc/services 파일이 존재하지 않으므로 해당사항 없음"
fi

b_result=`ls -al /etc/services 2> /dev/null`
#--END

#--START(점검 방법)
scriptResult="1. /etc/services 파일의 소유자 및 권한 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-24(){
#--START(점검항목 설명)
CODE="U-24"
MEASURES="단기"
#--END

#--START(점검 명령어)

stick=`find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -al 2> /dev/null {} \; | egrep '(/sbin/dump|/usr/bin/lpq-lpd|/usr/bin/newgrp|/sbin/restore|/usr/bin/lpr|/usr/sbin/lpc|/sbin/unix_chkpwd|/usr/bin/lpr-lpd|/usr/sbin/lpc-lpd|/usr/bin/at|/usr/bin/lprm|/usr/sbin/traceroute|/usr/bin/lpq|/usr/bin/lprm-lpd)' | egrep -v "snap|docker|kube|overlay" | wc -l`

b_result=`ls -al /sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd 2> /dev/null | egrep -v "snap|docker|kube|overlay"`

if [ $stick -gt 0 ]; then
	a_result="X"
	c_result="주요 파일에 Sticky bit가 설정되어 있으므로 취약"
else
	a_result="O"
	c_result="주요 파일에 Sticky bit가 설정되어 있지 않으므로 양호"
fi
#--END

#--START(점검 방법)
scriptResult="1. 불필요하게 SUID, SGID, Sticky bit 설정된 파일 점검
$b_result
"

chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-25(){
#--START(점검항목 설명)
CODE="U-25"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

b_result=`find /home \( -name .bashrc -o -name .profile -o -name .kshrc -o -name .cshrc -o -name .bash_profile -o -name .login -o -name .exrc -o -name .netrc \) -ls 2> /dev/null | egrep -v "snap|skel|docker|kube|overlay" | awk {'print $3" "$5" "$6" "$11'}`

fpermit=`find /home \( -name .bashrc -o -name .profile -o -name .kshrc -o -name .cshrc -o -name .bash_profile -o -name .login -o -name .exrc -o -name .netrc \) -ls 2> /dev/null | egrep -v "snap|skel|docker|kube|overlay" | awk {'print $3'}`

spacechk=`echo $fpermit | tr -cd " " | wc -m`
cnt=`expr $spacechk + 1`

perlist=($(echo $fpermit | sed -e "s/[[:space:]]/\n/g"))

for((i=0;i<$cnt;i++))
do
	if [ `expr substr ${perlist[$i]} 5 6 | grep w | wc -l` -gt 0 ]; then
		result="$result X"
	else
		result="$result O"
	fi
done

if [ `echo $result | grep X | wc -l` -gt 0 ]; then
	a_result1="X"
	c_result1="사용자 홈 디렉터리 환경변수 파일의 권한이 기준에 맞게 설정되어 있지 않으므로 취약"
else
	a_result1="O"
	c_result1="사용자 홈 디렉터리 환경변수 파일의 권한이 모두 기준에 맞게 설정되어 있으므로 양호"
fi

fowner1=($(find /home \( -name .bashrc -o -name .profile -o -name .kshrc -o -name .cshrc -o -name .bash_profile -o -name .login -o -name .exrc -o -name .netrc \) -ls | egrep -v "snap|skel|docker|kube|overlay" | awk {'print $5'} 2> /dev/null))
fowner2=($(find /home \( -name .bashrc -o -name .profile -o -name .kshrc -o -name .cshrc -o -name .bash_profile -o -name .login -o -name .exrc -o -name .netrc \) -ls | egrep -v "snap|skel|docker|kube|overlay" | awk {'print $6'} 2> /dev/null))

for((i=0;i<${#fowner1[@]};i++))
do
        if [ "${fowner1[$i]}" == "${fowner2[$i]}" ]; then
                result2="$result2 O"
        else
                result2="$result2 X"
        fi
done

if [ `echo $result2 | grep X | wc -l` -gt 0 ]; then
	a_result2="X"
	c_result2="환경변수 파일의 소유자 설정이 취약"
else
	a_result2="O"
	c_result2="환경변수 파일의 소유자 설정이 양호"
fi

if [ $a_result1 == "O" -a $a_result2 == "O" ]; then
	a_result="O"
else
	a_result="X"
fi
#--END

#--START(점검 방법)
scriptResult="1. 사용자 홈 디렉터리 환경변수 파일 소유자 및 권한 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result1
$c_result2
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-26(){
#--START(점검항목 설명)
CODE="U-26"
MEASURES="단기"
#--END

#--START(점검 명령어)

wwr=`find /etc /home /tmp /var -xdev -perm -2 -ls | awk '{print $3}' | egrep -v "^l|^s|^c|^p|^d|overlay|kubelet"`
find /etc /home /tmp /var -xdev -perm -2 -ls | awk '{print $3"\t"$11}' | egrep -v "^l|^s|^c|^p|^d|overlay|kubelet" > U-26_World_Writable.txt

spacechk=`echo $wwr | tr -cd " " | wc -m`
cnt=`expr $spacechk + 1`

if [ `echo $wwr | grep r | wc -l` -gt 0 ]; then
  list=($(echo $wwr | sed -e "s/[[:space:]]/\n/g"))
  for((i=0;i<$cnt;i++))
  do
        if [ `expr substr ${list[$i]} 8 3 | grep w | wc -l` -gt 0 ]; then
                result="$result X"
	else
		result="$result O"
        fi
  done
fi

if [ `echo $result | grep X | wc -l` -gt 0 ]; then
	a_result="X"
       	c_result="모든 사용자에게 쓰기 권한이 부여된 파일이 존재하므로 취약"
else
	a_result="O"
	c_result="모든 사용자에게 쓰기 권한이 부여된 파일이 존재하지 않으므로 양호"
fi
#--END

#--START(점검 방법)
scriptResult="1. 모든 사용자에게 쓰기 권한이 있는 파일 존재여부 점검
U-26_World_Writable.txt 파일 참고

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-27(){
#--START(점검항목 설명)
CODE="U-27"
MEASURES="단기"
#--END

#--START(점검 명령어)

b_result1=`ls -al /dev | egrep -v "^d|total"`
b_result2=`ls -al /dev | egrep -v "^d|total|^c|^l|^s|^b"`

if [ `ls -al /dev | egrep -v "^d|total|^c|^l|^s|^b" | wc -l` -gt 0 ]; then
	a_result="X"
	c_result="/dev 디렉터리에 major, minor number가 없는 파일이 존재하므로 취약"
else
	a_result="O"
	c_result="/dev 디렉터리의 모든 파일에 major, minor number가 존재하므로 양호"
fi
#--END

#--START(점검 방법)
scriptResult="1. /dev 디렉터리 점검
$b_result1

2. /dev에 major, minor 번호가 존재하지 않는 device 파일 점검
$b_result2
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-28(){
#--START(점검항목 설명)
CODE="U-28"
MEASURES="단기"
#--END

#--START(점검 명령어)
chekcount=0
res2=0
res2_weak=0
count_weak=0
account_list=($(cat /etc/passwd | egrep "/bin/sh|/bin/bash" | awk -F: '{print $1}'))
home_list=($(cat /etc/passwd | egrep "/bin/sh|/bin/bash" | awk -F: '{print $6}'))

if [ -f /etc/hosts.equiv ]; then
        b_result=`ls -al /etc/hosts.equiv 2> /dev/null`
        if [ `f_permit /etc/hosts.equiv 600` == "OK" ] ; then
                if [ `ls -al /etc/hosts.equiv | awk {'print $3'}` == "root" ]; then
                        res1=1 # /etc/hosts.equiv 파일의 권한이 600이하이고 소유자가 root이므로 양호
                else
                        res1=0 # /etc/hosts.equiv 파일의 권한은 600이하이지만 소유자가 root가 아니므로 취약
                fi
        else
                res1=0 # /etc/hosts.equiv 파일의 권한이 600 초과되므로 취약
        fi
else
        res1=2 # /etc/hosts.equiv 파일이 존재하지 않으므로 해당사항 없음
fi

for((i=0;i<${#account_list[@]};i++))
do
	if [ -f ${home_list[$i]}/.rhosts ] ; then
		if [ `f_permit ${home_list[$i]}/.rhosts 600` == "OK" ] ; then
			if [ `ls -al ${home_list[$i]}/.rhosts | awk {'print $3'}` == "root" ]; then
				res2=`expr $res2 + 0` # .rhosts 파일의 권한이 600이하이며 소유자가 root이므로 양호
			elif [ `ls -al ${home_list[$i]}/.rhosts | awk {'print $3'}` == "${account_list[$i]}" ]; then
				res2=`expr $res2 + 0` # .rhosts 파일의 권한이 600이하이며 소유자가 개별 사용자이므로 양호
			else
				res2_weak=1 # .rhosts 파일의 권한이 600이하이지만 소유자가 root 또는 개별 사용자가 아니므로 취약
				count_weak=1
			fi
		else
			res2_weak=1 # .rhosts 파일의 권한이 600 초과되어 취약
			count_weak=1

		fi
	else
		res2=`expr $res2 + 2` # .rhosts 파일이 존재하지 않으므로 해당사항 없음

	fi
if [ $count_weak -eq 1 ]; then
authority_list=`ls -al ${home_list[$i]}/.rhosts`
b_result1="$authority_list
$b_result1"
count_weak=0
fi

done

sum=`expr ${#account_list[@]} + ${#account_list[@]}`


if [ $res1 -eq 0 ]; then
	c_result1="/etc/hosts.equiv 파일의 권한과 소유자가 잘못 설정되어 취약"
	chekcount=1

elif [ $res1 -eq 1 ]; then

	c_result1="/etc/hosts.equiv 파일의 권한이 600이하이고 소유자가 root이므로 양호"
else
	c_result1="/etc/hosts.equiv 파일이 존재하지 않으므로 해당사항 없음"
	chekcount=2
fi


if [ $res2_weak -eq 1 ]; then
	c_result2=".rhosts 파일의 권한과 소유자가 잘못 설정되어 취약"
	chekcount=1

elif [ $res2 -eq $sum ]; then
    c_result2=".rhosts 파일이 존재하지 않으므로 해당사항 없음"
	chekcount=2

else
	c_result2=".rhosts 파일의 권한이 600이하이고 소유자가 root 또는 개별 사용자이므로 양호"

fi

if [ $chekcount -eq 1 ]; then
	a_result="X"
elif [ $chekcount -eq 2 ]; then
	a_result="N/A"
else
	a_result="O"
fi
#--END

#--START(점검 방법)
scriptResult="1. /etc/hosts.equiv 파일 소유자 및 권한 점검
$b_result

2. .rhosts 파일 소유자 및 권한 점검
$b_result1
"
chkStatus="$a_result"
chkResult="[결과값]1
$c_result1
$c_result2
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-29(){
#--START(점검항목 설명)
CODE="U-29"
MEASURES="단기"
#--END

#--START(점검 명령어)
# RHEL
if [ -f /etc/pam.d/system-auth ]; then
	if [ -f /usr/bin/cloud-init ]; then
		rescloud=1 # 클라우드 환경
		a_result="O"
		c_result1="클라우드 환경이며 Security Group을 사용하므로 양호"
	else
		rescloud=0 # 온프레미스 환경
		# TCPWrapper 사용 유무
		if [ -f /etc/hosts.deny ]; then
			denyf=1 # deny 파일 유무
			if [ `cat /etc/hosts.deny | grep -v "#" | grep "ALL" | wc -l` -gt 0 ]; then
				denyall=1 # deny all 유무
				if [ -f /etc/hosts.allow ]; then
					allowf=1 # allow 파일 유무
					if [ `cat /etc/hosts.allow | grep -v "#" | wc -l` -gt 0 ]; then
						allowip=1 # allow ip 설정 유무
						a_result2="O"
						b_result21=`cat /etc/hosts.deny | grep -v "#"`
						b_result22=`cat /etc/hosts.allow | grep -v "#"`
						c_result2="TCPWrapper를 사용하여 접근제어가 설정되어 있으므로 양호"
					else
						allowip=0 # allow ip 설정 유무
						a_result2="X"
                                                b_result21=`cat /etc/hosts.deny | grep -v "#"`
                                                b_result22=`cat /etc/hosts.allow | grep -v "#"`
                                                c_result2="TCPWrapper를 사용하여 deny all 설정이 되어 있으나 /etc/hosts.allow에 허용된 접근 제어가 설정되어 있지 않으므로 모든 IP 접속 불가"
					fi
				else
					allowf=0 # allow 파일 유무
					a_result2="X"
                        	        b_result21=`cat /etc/hosts.deny | grep -v "#"`
                                	c_result2="TCPWrapper를 사용하여 deny all 설정이 되어 있으나 /etc/hosts.allow 파일이 없으므로 모든 IP 접속 불가"
				fi
			else
				denyall=0 # deny all 유무
				a_result2="X"
				b_result2=`cat /etc/hosts.deny | grep -v "#"`
				c_result2="/etc/hosts.deny 파일이 존재하지만 deny all 설정이 없으므로 취약"
			fi
		else
			denyf=0 # deny 파일 유무
			a_result2="X"
			c_result2="/etc/hosts.deny 파일이 존재하지 않으므로 취약"
		fi

		# iptables 사용 유무
		if [ `service iptables status 2> /dev/null | egrep "not|inactive" | wc -l` -eq 1 ]; then
			iptab=0 # iptables 서비스 활성 유무
			a_result3="X"
			c_result3="iptables 서비스를 사용하지 않으므로 취약"
		else
			iptab=1 # iptables 서비스 활성 유무
			if [ `iptables -L | egrep -v "Chain|reject" | egrep "ACCEPT|anywhere|0.0.0.0" | wc -l` -gt 0 ]; then
				resany=1
				a_result3="-"
				b_result3=`iptables -L`
				c_result3="iptables 서비스를 사용하여 접근제어를 하지만 모든 IP에 허용된 룰이 있으므로 인터뷰 시 확인 필요"
			else
				resany=0
				a_result3="O"
				b_result3=`iptables -L`
                                c_result3="iptables 서비스를 사용하여 접근제어를 하며 모든 IP에 허용된 룰이 존재하지 않으므로 양호"
			fi
		fi

		if [ "$a_result2" == "O" -o "$a_result3" == "O" ]; then
                        a_result="O"
                else
                        a_result="X"
                fi
	fi
# UBUNTU
else
	if [ -f /usr/bin/cloud-init ]; then
                rescloud=1 # 클라우드 환경
                a_result="O"
                c_result1="클라우드 환경이며 Security Group을 사용하므로 양호"
        else
                rescloud=0 # 온프레미스 환경
                # TCPWrapper 사용 유무
                if [ -f /etc/hosts.deny ]; then
                        denyf=1 # deny 파일 유무
                        if [ `cat /etc/hosts.deny | grep -v "#" | grep "ALL" | wc -l` -gt 0 ]; then
                                denyall=1 # deny all 유무
                                if [ -f /etc/hosts.allow ]; then
                                        allowf=1 # allow 파일 유무
                                        if [ `cat /etc/hosts.allow | grep -v "#" | wc -l` -gt 0 ]; then
                                                allowip=1 # allow ip 설정 유무
                                                a_result2="O"
                                                b_result21=`cat /etc/hosts.deny | grep -v "#"`
                                                b_result22=`cat /etc/hosts.allow | grep -v "#"`
                                                c_result2="TCPWrapper를 사용하여 접근제어가 설정되어 있으므로 양호"
                                        else
                                                allowip=0 # allow ip 설정 유무
                                                a_result2="X"
                                                b_result21=`cat /etc/hosts.deny | grep -v "#"`
                                                b_result22=`cat /etc/hosts.allow | grep -v "#"`
                                                c_result2="TCPWrapper를 사용하여 deny all 설정이 되어 있으나 /etc/hosts.allow에 허용된 접근 제어가 설정되어 있지 않으므로 모든 IP 접속 불가"
                                        fi
                                else
                                        allowf=0 # allow 파일 유무
                                        a_result2="X"
                                        b_result21=`cat /etc/hosts.deny | grep -v "#"`
                                        c_result2="TCPWrapper를 사용하여 deny all 설정이 되어 있으나 /etc/hosts.allow 파일이 없으므로 모든 IP 접속 불가"
                                fi
                        else
                                denyall=0 # deny all 유무
                                a_result2="X"
                                b_result2=`cat /etc/hosts.deny | grep -v "#"`
                                c_result2="/etc/hosts.deny 파일이 존재하지만 deny all 설정이 없으므로 취약"
                        fi
                else
                        denyf=0 # deny 파일 유무
                        a_result2="X"
                        c_result2="/etc/hosts.deny 파일이 존재하지 않으므로 취약"
                fi

                # iptables 사용 유무
                if [ `service iptables status 2> /dev/null | egrep "not|inactive" | wc -l` -eq 1 ]; then
                        iptab=0 # iptables 서비스 활성 유무
                        a_result3="X"
                        c_result3="iptables 서비스를 사용하지 않으므로 취약"
                else
                        iptab=1 # iptables 서비스 활성 유무
                        if [ `iptables -L | egrep -v "Chain|reject" | egrep "ACCEPT|anywhere|0.0.0.0" | wc -l` -gt 0 ]; then
                                resany=1
                                a_result3="-"
                                b_result3=`iptables -L`
                                c_result3="iptables 서비스를 사용하여 접근제어를 하지만 모든 IP에 허용된 룰이 있으므로 인터뷰 시 확인 필요"
                        else
                                resany=0
                                a_result3="O"
                                b_result3=`iptables -L`
                                c_result3="iptables 서비스를 사용하여 접근제어를 하며 모든 IP에 허용된 룰이 존재하지 않으므로 양호"
                        fi
                fi

		if [ "$a_result2" == "O" -o "$a_result3" == "O" ]; then
			a_result="O"
		else
	        	a_result="X"
		fi
        fi
fi
#--END

#--START(점검 방법)
scriptResult="1. /etc/hosts.deny 파일 점검
$b_result21

2. /etc/hosts.allow 파일 점검
$b_result22

2. iptables 사용 점검
$b_result3
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result1
$c_result2
$c_result3
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-30(){
#--START(점검항목 설명)
CODE="U-30"
MEASURES="단기"
#--END

#--START(점검 명령어)
if [ -f /etc/hosts.lpd ]; then
        if [ "`f_permit /etc/hosts.lpd 600`" == "OK" ] ; then
                if [ "`ls -al /etc/hosts.lpd | awk {'print $3'}`" == "root" ]; then
                        res1=1 # /etc/hosts.lpd 파일의 권한이 600이하이고 소유자가 root이므로 양호
                else
                        res1=0 # /etc/hosts.lpd 파일의 권한은 600이하이지만 소유자가 root가 아니므로 취약
                fi
        else
                res1=0 # /etc/hosts.lpd 파일의 권한이 600 초과되므로 취약
        fi
else
        res1=2 # /etc/hosts.lpd 파일이 존재하지 않으므로 해당사항 없음
fi

if [ $res1 -eq 0 ]; then
	a_result="O"
	b_result=`ls -al /etc/hosts.lpd 2> /dev/null`
	c_result="/etc/hosts.lpd 파일의 권한이 600이하이고 소유자가 root이므로 양호"
elif [ $res1 -eq 1 ]; then
	a_result="X"
	b_result=`ls -al /etc/hosts.lpd 2> /dev/null`
	c_result="/etc/hosts.lpd 파일의 권한과 소유자가 잘못 설정되어 있으므로 취약"
else
	a_result="N/A"
	c_result="/etc/hosts.lpd 파일이 존재하지 않으므로 해당사항 없음"
fi
#--END

#--START(점검 방법)
scriptResult="1. hosts.lpd 파일 점검
$b_result
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END


#--START(JSON 형식 출력)
json_change_m
}


function U-31(){
#--START(점검항목 설명)
CODE="U-31"
MEASURES="단기"
#--END


#--START(점검 명령어)

if [ `ps -ef | egrep "ypserv|yppasswdd|ypxfrd" | grep -v grep | wc -l` -gt 0 ]; then
	a_result="X"
	b_result=`ps -ef | egrep "ypserv|yppasswdd|ypxfrd" | grep -v grep`
	c_result="NIS 서비스가 활성화 되어 있으므로 취약"
else
	a_result="O"
        b_result=`ps -ef | egrep "ypserv|yppasswdd|ypxfrd" | grep -v grep`
        c_result="NIS 서비스가 비활성화 되어 있으므로 양호"
fi
#--END

#--START(점검 방법)
scriptResult="1. NIS 서비스 사용현황 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END


#--START(JSON 형식 출력)
json_change_m
}


function U-32(){
#--START(점검항목 설명)
CODE="U-32"
MEASURES="Hot-Fix"
#--END


#--START(점검 명령어)

maskcfg=`umask`
if [ $maskcfg == "0022" ]; then
	a_result="O"
	b_result=`umask`
	c_result="UMASK 값이 0022로 설정되어 있으므로 양호"
else
	a_result="X"
        b_result=`umask`
        c_result="UMASK 값이 0022로 설정되어 있지 않으므로 취약"
fi
#--END

#--START(점검 방법)
scriptResult="1. UMASK 설정 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END


#--START(JSON 형식 출력)
json_change_m
}


function U-33(){
#--START(점검항목 설명)
CODE="U-33"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)
user_id=($(cat /etc/passwd | egrep "/bin/sh|/bin/bash" | awk -F: '{print $1}'))
homedir=($(cat /etc/passwd | egrep "/bin/sh|/bin/bash" | awk -F: '{print $6}'))

a_result1="O"
a_result2="O"

for((i=0;i<${#user_id[@]};i++))
do
	if [ -d ${homedir[$i]} ]; then
		if [ ${homedir[$i]} ]; then
			b_result11="계정: ${user_id[$i]} `ls -ald ${homedir[$i]} | awk '{print "권한:"$1" 소유자:"$3" 홈디렉터리:"$9}'`"
			b_result12="$b_result12
$b_result11"
			dirpmt=`ls -ald ${homedir[$i]} | awk '{print $1}'`
			if [ `expr substr $dirpmt 5 6 | grep w | wc -l` -gt 0 ]; then
				a_result1="$a_result X"
				c_result1="타사용자에게 쓰기 권한이 부여되어 있는 홈 디렉터리가 존재하므로 취약"
			fi
		else
			a_result1="$a_result1 X"
               		b_result11="계정: ${user_id[$i]}"
		 	b_result12="$b_result12
$b_result11"
			c_result1="홈 디렉터리가 존재하지 않는 계정이 존재하므로 취약"
		fi
	else
		a_result1="$a_result1 X"
		b_result11="계정: ${user_id[$i]}"
                b_result12="$b_result12
$b_result11"
		c_result1="홈 디렉터리가 존재하지 않는 계정이 존재하므로 취약"
	fi


	if [ -d ${homedir[$i]} ]; then
		if [ ${homedir[$i]} ]; then
			if [ "`ls -ald ${homedir[$i]} | awk '{print $3}'`" != "${user_id[$i]}" ] ; then
				a_result2="$a_result2 X"
				c_result2="홈 디렉터리의 사용자 계정과 소유자가 다르므로 취약"
			fi
		else
		a_result2="$a_result1 X"
		c_result2="홈 디렉터리가 존재하지 않는 계정이 존재하므로 취약"
		fi
	else
		a_result2="$a_result2 X"
		c_result2="홈 디렉터리가 존재하지 않는 계정이 존재하므로 취약"
	fi
done

if [ "$a_result1" == "O" -a "$a_result2" == "O" ]; then
	a_result="O"
	c_result="사용자별 홈디렉터리 소유자와 권한이 적절하므로 양호"
else
	a_result="X"
fi
b_result=`cat /etc/passwd | egrep "/bin/sh|/bin/bash"`
#--END

#--START(점검 방법)
scriptResult="1. 사용자별 홈 디렉터리의 소유자 및 권한 점검
$b_result
$b_result12

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
$c_result1
$c_result2
"
#--END


#--START(JSON 형식 출력)
json_change_m
}


function U-34(){
#--START(점검항목 설명)
CODE="U-34"
MEASURES="단기"
#--END

#--START(점검 명령어)
user_id=($(cat /etc/passwd | egrep "/bin/sh|/bin/bash" | awk -F: '{print $1}'))
homedir=($(cat /etc/passwd | egrep "/bin/sh|/bin/bash" | awk -F: '{print $6}'))

for((i=0;i<${#user_id[@]};i++))
do
	if [ -d ${homedir[$i]} ]; then
		if [ ${homedir[$i]} ]; then
			a_result1="$a_result1 O"
		else
			a_result1="$a_result1 X"
		fi
	else
       	        a_result1="$a_result1 X"
	fi
done

if [ `echo $a_result1 | grep X | wc -l` -gt 0 ]; then
	a_result="X"
	c_result="홈디렉터리가 존재하지 않는 계정이 존재하므로 취약"
else
	a_result="O"
	c_result="모든 계정에 존재하는 홈디렉터리가 설정되어 있으므로 양호"
fi

b_result=`cat /etc/passwd | egrep "/bin/sh|/bin/bash" | awk -F: '{print $1" "$6}'`
#--END

#--START(점검 방법)
scriptResult="1. /etc/passwd 파일 내 설정된 사용자 계정별 홈 디렉터리 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END


#--START(JSON 형식 출력)
json_change_m
}


function U-35(){
#--START(점검항목 설명)
CODE="U-35"
MEASURES="단기"
#--END


#--START(점검 명령어)

if [ `find /etc /home /tmp /var -xdev -name ".*" | egrep -v "overlay|kubelet|docker|bash|ssh|shrc" | wc -l` -gt 0 ]; then
	a_result="X"
	find /etc /home /tmp /var -xdev -name ".*" | egrep -v "overlay|kubelet|docker|bash|ssh|shrc" > U-35_Hide_File_Check.txt
	c_result="숨겨진 디렉터리 및 파일이 존재하므로 확인 필요"
else
	a_result="O"
	c_result="숨겨진 디렉터리 및 파일이 존재하지 않으므로 양호"
fi
#--END

#--START(점검 방법)
scriptResult="1. 숨겨진 파일 점검
U-35_Hide_File_Check.txt 파일 참고

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END


#--START(JSON 형식 출력)
json_change_m
}


function U-36(){
#--START(점검항목 설명)
CODE="U-36"
MEASURES="Hot-Fix"
#--END


#--START(점검 명령어)

b_result=`netstat -nlpt | grep -w 79`
if [ `netstat -nlpt | grep -w 79 | wc -l` -eq 1 ]; then
	a_result="X"
	c_result="finger 서비스가 활성화 되어 있으므로 취약"
else
	a_result="O"
        c_result="finger 서비스가 비활성화 되어 있으므로 양호"
fi
#--END

#--START(점검 방법)
scriptResult="finger 서비스 활성 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END


#--START(JSON 형식 출력)
json_change_m
}


function U-37(){
#--START(점검항목 설명)
CODE="U-37"
MEASURES="단기"
#--END

#--START(점검 명령어)

if [ -f /etc/pam.d/system-auth ]; then
	if [ `netstat -nlpt | grep -w 21 | wc -l` -eq 1 ]; then
		if [ `cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable | awk -F= {'print $2'}` == "YES" ]; then
			a_result="X"
                        b_result1=`netstat -nlpt | grep -w 21`
                        b_result2=`cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable`
                        c_result="Anonymous FTP가 활성화되어 있으므로 취약"

		elif [ `cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable | awk -F= {'print $2'}` == "yes" ]; then
			a_result="X"
                        b_result1=`netstat -nlpt | grep -w 21`
                        b_result2=`cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable`
                        c_result="Anonymous FTP가 활성화되어 있으므로 취약"
		else
			a_result="O"
			b_result1=`netstat -nlpt | grep -w 21`
			b_result2=`cat /etc/vsftpd/vsftpd.conf | grep anonymous_enable`
			c_result="Anonymous FTP가 비활성화되어 있으므로 양호"
		fi
	else
		a_result="O"
	        b_result=`netstat -nlpt | grep -w 21`
	        c_result="ftp 서비스가 비활성화 되어 있으므로 양호"
	fi
else
	if [ `netstat -nlpt | grep -w 21 | wc -l` -eq 1 ]; then
                if [ `cat /etc/vsftpd.conf | grep anonymous_enable | awk -F= {'print $2'}` == "YES" ]; then
                        a_result="X"
                        b_result1=`netstat -nlpt | grep -w 21`
                        b_result2=`cat /etc/vsftpd.conf | grep anonymous_enable`
                        c_result="Anonymous FTP가 활성화되어 있으므로 취약"

                elif [ `cat /etc/vsftpd.conf | grep anonymous_enable | awk -F= {'print $2'}` == "yes" ]; then
                        a_result="X"
                        b_result1=`netstat -nlpt | grep -w 21`
                        b_result2=`cat /etc/vsftpd.conf | grep anonymous_enable`
                        c_result="Anonymous FTP가 활성화되어 있으므로 취약"
                else
                        a_result="O"
                        b_result1=`netstat -nlpt | grep -w 21`
                        b_result2=`cat /etc/vsftpd.conf | grep anonymous_enable`
                        c_result="Anonymous FTP가 비활성화되어 있으므로 양호"
                fi
        else
                a_result="O"
                b_result=`netstat -nlpt | grep -w 21`
                c_result="ftp 서비스가 비활성화 되어 있으므로 양호"
        fi
fi
#--END

#--START(점검 방법)
scriptResult="1. FTP 서비스 사용 점검
$b_result1

2. 익명 ftp 접속 허용 여부 점검
$b_result2
"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END


#--START(JSON 형식 출력)
json_change_m
}


function U-38(){
#--START(점검항목 설명)
CODE="U-38"
MEASURES="단기"
#--END


#--START(점검 명령어)

if [ `netstat -nlpt | egrep -w "512" | wc -l` -gt 0 ]; then
	a_result1="X"
	c_result1="rexec 서비스가 활성화 되어 있으므로 취약"
else
	a_result1="O"
        c_result1="rexec 서비스가 비활성화 되어 있으므로 양호"
fi
if [ `netstat -nlpt | egrep -w "513" | wc -l` -gt 0 ]; then
        a_result2="X"
        c_result2="rlogin 서비스가 활성화 되어 있으므로 취약"
else
        a_result2="O"
        c_result2="rlogin 서비스가 비활성화 되어 있으므로 양호"
fi
if [ `netstat -nlpt | egrep -w "514" | wc -l` -gt 0 ]; then
        a_result3="X"
        c_result3="rsh 서비스가 활성화 되어 있으므로 취약"
else
        a_result3="O"
        c_result3="rsh 서비스가 비활성화 되어 있으므로 양호"
fi

if [ $a_result1 == "O" -a $a_result2 == "O" -a $a_result3 == "O" ]; then
	a_result="O"
	b_result=`netstat -nlpt | egrep -w "512|513|514"`
	c_result="rsh, rlogin, rexec 서비스가 모두 비활성화되어 있으므로 양호"
else
	a_result="X"
	b_result=`netstat -nlpt | egrep -w "512|513|514"`
        c_result="$c_result1
$c_result2
$c_result3"
fi
#--END

#--START(점검 방법)
scriptResult="1. rexec(512), rlogin(513), rsh(514) 서비스 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END


#--START(JSON 형식 출력)
json_change_m
}


function U-39(){
#--START(점검항목 설명)
CODE="U-39"
MEASURES="Hot-Fix"
#--END


#--START(점검 명령어)

if [ -f /etc/pam.d/system-auth ]; then
	a_result1="O"
	a_result2="O"

	if [ -f /etc/cron.deny ]; then
		fdeny=1
		if [ "`f_permit /etc/cron.deny 640`" == "OK" -a "`ls -al /etc/cron.deny | awk {'print $3'}`" == "root" ]; then
			a_result1="O"
		else
			a_result1="X"
		fi
	else
		fdeny=0
	fi

	if [ -f /etc/cron.allow ]; then
		fallow=1
             	if [ "`f_permit /etc/cron.allow 640`" == "OK" -a "`ls -al /etc/cron.allow | awk {'print $3'}`" == "root" ]; then
	              	a_result2="O"
                else
	                a_result2="X"
               	fi
        else
		fallow=0
        fi

	if [ $fdeny -eq 1 -a $fallow -eq 0 ]; then
		a_result="X"
		b_result=`ls -al /etc/cron.allow /etc/cron.deny 2> /dev/null`
		c_result="/etc/cron.deny 파일만 존재하므로 취약"
	elif [ $fdeny -eq 0 -a $fallow -eq 0 ]; then
		a_result="O"
                b_result=`ls -al /etc/cron.allow /etc/cron.deny 2> /dev/null`
                c_result="/etc/cron.allow, /etc/cron.deny 파일이 존재하지 않고, crontab 명령을 root만 사용가능하므로 양호"
	else
		if [ $a_result1 == "O" -a $a_result2 == "O" ]; then
			a_result="O"
			b_result=`ls -al /etc/cron.allow /etc/cron.deny 2> /dev/null`
			c_result="/etc/cron.allow, /etc/cron.deny 파일의 소유자 root, 권한 640이하이므로 양호"
		else
			a_result="X"
                        b_result=`ls -al /etc/cron.allow /etc/cron.deny 2> /dev/null`
                        c_result="/etc/cron.allow, /etc/cron.deny 파일의 소유자 또는 권한이 잘못 설정되어 취약"
		fi
	fi

else
	a_result1="O"
        a_result2="O"

	if [ -f /etc/cron.deny ]; then
                fdeny=1
                if [ "`f_permit /etc/cron.deny 640`" == "OK" -a "`ls -al /etc/cron.deny | awk {'print $3'}`" == "root" ]; then
                        a_result1="O"
                else
                        a_result1="X"
		fi
        else
                fdeny=0
        fi

        if [ -f /etc/cron.allow ]; then
                fallow=1
                if [ "`f_permit /etc/cron.allow 640`" == "OK" -a "`ls -al /etc/cron.allow | awk {'print $3'}`" == "root" ]; then
                        a_result2="O"
                else
                        a_result2="X"
                fi
        else
                fallow=0
        fi

        if [ $fdeny -eq 1 -a $fallow -eq 0 ]; then
                a_result="X"
                b_result=`ls -al /etc/cron.allow /etc/cron.deny 2> /dev/null`
                c_result="/etc/cron.deny 파일만 존재하므로 취약"
	elif [ $fdeny -eq 0 -a $fallow -eq 0 ]; then
                a_result="X"
                b_result=`ls -al /etc/cron.allow /etc/cron.deny 2> /dev/null`
                c_result="/etc/cron.allow, /etc/cron.deny 파일 모두 존재하지 않으므로 취약"
        else
                if [ $a_result1 == "O" -a $a_result2 == "O" ]; then
                        a_result="O"
                        b_result=`ls -al /etc/cron.allow /etc/cron.deny 2> /dev/null`
                        c_result="/etc/cron.allow, /etc/cron.deny 파일의 소유자 root, 권한 640이하이므로 양호"
                else
                        a_result="X"
                        b_result=`ls -al /etc/cron.allow /etc/cron.deny 2> /dev/null`
                        c_result="/etc/cron.allow, /etc/cron.deny 파일의 소유자 또는 권한이 잘못 설정되어 취약"
                fi
        fi
fi
#--END

#--START(점검 방법)
scriptResult="1. /etc/cron.deny, /etc/cron.allow 파일 점검
$b_result

"
chkStatus="$a_result"
chkResult="[결과값]
$c_result
"
#--END


#--START(JSON 형식 출력)
json_change_m
}
function U-40(){
#--START(점검항목 설명)
CODE="U-40"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)

if [ `netstat -na | egrep -w "7|9|13|19" | grep LISTEN | grep tcp | wc -l` -eq 0 ]; then
	b_result1=""
	a_result1="O"
	c_result1="DoS 공격에 취약한 서비스를 사용하고 있지 않으므로 양호"

else
	b_result1=`netstat -na | egrep -w "7|9|13|19"`
	a_result1="X"
	c_result1="7:9:13:19 의 서비스 포트는 DoS 공격에 취약함으로 취약"

fi

#--END

#--START(점검 방법)
scriptResult="1. 7:9:13:19 의 서비스 포트 사용 여부
$b_result1
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1
"
#--END

#--START(JSON 형식 출력)
json_change_m
}
function U-41(){
#--START(점검항목 설명)
CODE="U-41"
MEASURES="단기"
#--END

#--START(점검 명령어)
if [ `ps -ef | grep "nfs"|grep -v grep |wc -l` -eq 0 ]; then
	b_result1=""
	a_result1="O"
    c_result1="NFS 서비스가 비활성화되어 있으므로 양호"
	else
	b_result1=`ps -ef | grep "nfs"|grep -v grep`
	a_result1="X"
	c_result1="NFS 서비스가 활성화되어 있으므로 취약"
fi

#--END


#--START(점검 방법)
scriptResult="1. nfs 서비스 사용 여부
$b_result1
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1
"
#--END

#--START(JSON 형식 출력)
json_change_m
}
function U-42(){
#--START(점검항목 설명)
CODE="U-42"
MEASURES="단기"
#--END

#--START(점검 명령어)
if [ `ps -ef | grep -i "nfs" | grep -v "grep"|wc -l ` -eq 0 ]; then
	a_result1="O"
	c_result1="NFS 서비스가 비활성화되어 있으므로 양호"

else

	b_result1=`ps -ef | grep -i "nfs" | grep -v grep`
	b_result2=`cat /etc/exports`
	a_result1="-"
	c_result1="NFS 서비스가 활성성화되어 있으므로 취약 NFS 서비스 사용 시 설정 파일 결과에 따라 인터뷰 시 확인"

fi
#--END

#--START(점검 방법)
scriptResult="$b_result1
1. NFS 공유 설정 파일(/etc/exports) 점검
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1
"
#--END

#--START(JSON 형식 출력)
json_change_m
}
function U-43(){
#--START(점검항목 설명)
CODE="U-43"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)
if [ `ps -ef | grep automount |grep -v grep| wc -l` -eq 0 ]; then
	b_result1=`ps -ef | grep automount`
	a_result1="O"
	c_result1="automountd 서비스가 비활성화되어 있으므로 양호"
	else
	b_result1=`ps -ef | grep automount`
	a_result1="X"
	c_result1="automount 서비스가 활성화되어 있으므로 취약"
fi

#--END

#--START(점검 방법)
scriptResult="1. automount 서비스 사용 여부
$b_result1
"

chkStatus="$a_result1"
chkResult="[결과값]
$c_result1
"
#--END

#--START(JSON 형식 출력)
json_change_m
}
function U-44(){
#--START(점검항목 설명)
CODE="U-44"
MEASURES="단기"
#--END

#--START(점검 명령어)
chek_count=0
file_list=("rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms.server" "cachefsd")

for((i=0;i<${#file_list[@]};i++))
do
	if [ `netstat -nptl | grep "${file_list[$i]}" |wc -l` -ge 1 ]; then

		b_result1="${file_list[$i]}
		$b_result1"
		chek_count=1

	fi

done

if [ $chek_count -eq 0 ]; then

	b_result1=""
	a_result1="O"
	c_result1="불필요한 RPC 서비스가 비활성화되어 있으므로 양호"
else

	a_result1="X"
	c_result1="불필요한 RPC 서비스가 활성화되어 있으므로 취약"

fi

#--END

#--START(점검 방법)
scriptResult="1. 불필요한 RPC 서비스 목록
$b_result1
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1
"
#--END

#--START(JSON 형식 출력)
json_change_m
}
function U-45(){
#--START(점검항목 설명)
CODE="U-45"
MEASURES="단기"
#--END

#--START(점검 명령어)
if [ `ps -ef | grep -w yp | grep -v grep | wc -l` -eq 0 ]; then
	b_result1=""
	a_result1="O"
	c_result1="NIS 서비스가 비활성화되어 있으므로 양호"

else
	b_result1=`ps -ef | grep -w yp | grep -v grep `
	a_result1="X"
	c_result1="NIS 서비스가 활성화되어 있으므로 취약"
fi
#--END

#--START(점검 방법)
scriptResult="1. NIS 서비스 사용 여부
$b_result1
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1
"

#--END

#--START(JSON 형식 출력)
json_change_m
}
function U-46(){
#--START(점검항목 설명)
CODE="U-46"
MEASURES="Hot-Fix"
#--END

#--START(점검 명령어)
if [ `ps -ef | egrep "tftp|talk" | grep -v grep| wc -l` -eq 0 ]; then
	a_result1="O"
	c_result1="tftp, talk 서비스가 비활성화되어 있으므로 양호"
	b_result1=""

else
	b_result1=`ps -ef | egrep "tftp|talk"`
	a_result1="X"
	c_result1="tftp,talk 서비스가 활성화되어 있으므로 취약"

fi

#--END

#--START(점검 방법)
scriptResult="1. tftp,talk 서비스 사용 여부
$b_result1
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1
"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-47(){
#--START(점검항목 설명)
CODE="U-47"
MEASURES="중기"
#--END

#--START(점검 명령어)
if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -ge 1 ]; then
	if [ `ls -al /etc/pam.d/system-auth| wc -l` -eq 0 ]; then
		a_result1="X"
		b_result1=`dpkg -l | egrep "sendmail" | awk '{print $3}'| sed -n '1p'`
		c_result1="수동 점검  sendmail 8.15.2-3 이상 필요함(2019-12-02 기준)"
	else
		a_result1="X"
		b_result1=`rpm -qa sendmail`
		c_result1="수동 점검  sendmail 8.14.4-9 이상 필요함(2019-12-02 기준)"
	fi
else

	b_result1="sendmail 서비스 비활성화"
	a_result1="O"
	c_result1="sendmail 서비스가 비활성화되어 있으므로 양호"
fi


if [ `ps -ef | grep postfix | grep -v grep | wc -l` -ge 1 ]; then
	if [ `ls -al /etc/pam.d/system-auth| wc -l` -eq 0 ]; then
		a_result2="X"
		b_result2=`dpkg -l | egrep "postfix" | awk '{print $3}'| sed -n '1p'`
		c_result2="수동 점검 필요 sendmail 3.1.0-3 이상 양호(2019-12-02 기준)"
	else
		a_result2="X"
		b_result2=`rpm -qa postfix`
		c_result2="수동 점검 필요 sendmail 2.10.1-6 이상 양호(2019-12-02 기준)"
	fi
else

	b_result2="postfix 서비스 비활성화"
	a_result2="O"
	c_result2="postfix 서비스가 비활성화되어 있으므로 양호"

fi

if [ $a_result1 == "O" -a $a_result2 == "O" ] ;
	then
		a_result3="O"
	else
		a_result3="X"
fi

#--END

#--START(점검 방법)
scriptResult="
1. sendmail 버전 점검 결과
$b_result1

2. postfix 버전 점검 결과
$b_result2
"
chkStatus="$a_result3"
chkResult="[결과값]
$c_result1
$c_result2
"
#--END
#--START(JSON 형식 출력)
json_change_m
}

function U-48(){
#--START(점검항목 설명)
CODE="U-48"
MEASURES="단기"
#--END

#--START(점검 명령어)
sum=0
if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -eq 1 ]; then


	#c_result1=`cat /etc/mail/sendmail.cf  |grep '$#error $@ 5.7.1 $: "550 Relaying denied"'`

	if [ `cat /etc/mail/sendmail.cf  |grep '$#error $@ 5.7.1 $: "550 Relaying denied"' | awk '{print $1}' |grep  "#" |wc -l
` -eq 1 ]; then

		b_result1=`cat /etc/mail/sendmail.cf  |grep '$#error $@ 5.7.1 $: "550 Relaying denied"'`
		a_result1="X"
		c_result1="Sendmail의 스펨 릴레이 제한 설정이 비활성화되어 있으므로 취약"

	else

		b_result1=`cat /etc/mail/sendmail.cf  |grep '$#error $@ 5.7.1 $: "550 Relaying denied"'`
		a_result1="O"
		c_result1="Sendmail의 스펨 릴레이 제한 설정이 활성화되어 있으므로 양호"

	fi



else
	b_result1="sendmail 서비스 비활성화"
	a_result1="O"
	c_result1="Sendmail 서비스가 비활성화되어 있으므로 양호"


fi



if [ `ps -ef | grep postfix | grep -v grep | wc -l` -eq 1 ]; then


	if [ `cat /etc/postfix/main.cf |grep "mynetworks =" |grep "0.0.0.0"|wc -l` -eq 1 ]; then
		b_result2=`cat  /etc/postfix/main.cf |grep "mynetworks =" |grep "0.0.0.0"`
		a_result2="X"
		c_result2="postfix의 스펨 릴레이 제한 설정이 비활성화되어 있으므로 취약 "
	else
		b_result2=`cat /etc/postfix/main.cf |grep "mynetworks ="`
		a_result2="O"
		c_result2="postfix의 스펨 릴레이 제한 설정이 활성화되어 있으므로 양호"
	fi
else
	b_result2="postfix 서비스 비활성화"
	a_result2="O"
	c_result2="postfix의 서비스가 비활성화되어 있으므로 양호"


fi

if [ $a_result1 == "O" -a $a_result2 == "O" ] ;
	then
		a_result3="O"
	else
		a_result3="X"
fi

#--END

#--START(점검 방법)
scriptResult="
1. sendmail 주석 처리 점검 결과
$b_result1

2. postfix 주석 처리 점검 결과
$b_result2
"
chkStatus="$a_result3"
chkResult="[결과값]
$c_result1
$c_result2
"
#--END
#--START(JSON 형식 출력)
json_change_m
}

function U-49(){
#--START(점검항목 설명)
CODE="U-49"
MEASURES="Hot-Fix"
#--END
#일반사용자의 Sendmail 실행 방지


#--START(점검 명령어)
if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ] ;
then
        if [ `cat /etc/mail/sendmail.cf | grep -v "#" | grep PrivacyOptions| grep restrictqrun | wc -l` -gt 0 ] ;
        then
        a_result1="O"
        b_result1=`ps -ef | grep sendmail | grep -v grep`
        b_result2=`cat /etc/mail/sendmail.cf | grep -v "#" | grep PrivacyOptions| grep restrictqrun`
        c_result1="restrictqrun 설정이 되어 일반 사용자의 Sendmail 실행 방지 되므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep sendmail | grep -v grep`
        b_result2=`cat /etc/mail/sendmail.cf | grep -v "#" | grep PrivacyOptions| grep restrictqrun`
        c_result1="restrictqrun 설정이 되지 않아 일반 사용자의 Sendmail 실행 방지가 되지 않으므로 취약"
        fi
else
a_result1="O"
b_result1=`ps -ef | grep sendmail | grep -v grep`
c_result1="Sendmail 서비스를 사용하지 않으므로 양호"
fi
#--END

#--START(점검 방법)
scriptResult="1. Sendmail 서비스 사용 여부
$b_result1
2. restrictqrun 설정 여부
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-50(){
#--START(점검항목 설명)
CODE="U-50"
MEASURES="중기"
#--END

#DNS 보안 버전 패치
if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ] ;
then
a_result1="수동 점검 필요"
b_result1=`ps -ef | grep named | grep -v grep`
b_result2=`named -v | awk {'print $2'} | awk -F- {'print $1'}`
c_result1="BIND9 보안 취약점 매트릭스를 확인해야 함"
else
a_result1="O"
b_result1=`ps -ef | grep named | grep -v grep`
c_result1="DNS 서비스를 사용하지 않으므로 양호"
fi
#--END

#--START(점검 방법)
scriptResult="1. named 서버 활성화 여부
$b_result1
2. DNS 서비스 보안 패치 여부
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-51(){
#--START(점검항목 설명)
CODE="U-51"
MEASURES="단기"
#--END
#DNS Zone Transfer 설정

#--START(점검 명령어)
if [ -f /etc/pam.d/system-auth ];
#RHEL 계열
then
    if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ] ;
    then
        if [ `cat /etc/named.conf | grep 'allow-transfer' | wc -l` -eq 1 ] ;
        then
        a_result1="O"
        b_result1=`ps -ef | grep named | grep -v grep`
        b_result2=`cat /etc/named.conf | grep 'allow-transfer'`
        c_result1="Zone Transfer 설정이 되어 있으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep named | grep -v grep`
        b_result2=`cat /etc/named.conf | grep 'allow-transfer'`
        c_result1="Zone Transfer 설정이 되어 있지 않으므로 취약"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep named | grep -v grep`
    c_result1="DNS 서비스를 사용하지 않으므로 양호"
    fi
#ubuntu
else
  if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ] ;
  then
      if [ `cat /etc/bind/named.conf | grep 'allow-transfer' | wc -l` -eq 1 ] ;
      then
      a_result1="O"
      b_result1=`ps -ef | grep named | grep -v grep`
      b_result2=`cat /etc/bind/named.conf | grep 'allow-transfer'`
      c_result1="Zone Transfer 설정이 되어 있으므로 양호"
      else
      a_result1="X"
      b_result1=`ps -ef | grep named | grep -v grep`
      b_result2=`cat /etc/bind/named.conf | grep 'allow-transfer'`
      c_result1="Zone Transfer 설정이 되어 있지 않으므로 취약"
      fi
  else
  a_result1="O"
  b_result1=`ps -ef | grep named | grep -v grep`
  c_result1="DNS 서비스를 사용하지 않으므로 양호"
  fi
fi
#--END

#--START(점검 방법)
scriptResult="1. named 서버 활성화 여부
$b_result1
2. Zone Transfer 설정 여부
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-52(){
#--START(점검항목 설명)
CODE="U-52"
MEASURES="Hot-Fix"
#--END
#Apache 디렉토리 리스팅 제거

#--START(점검 명령어)
if [ -f /etc/pam.d/system-auth ];
#RHEL 계열
then
    if [ `ps -ef | grep httpd | grep -v grep | wc -l` -gt 0 ] ;
    then
        if [ `cat /etc/httpd/conf/httpd.conf | grep -v "#" | grep -i indexes | wc -l` -eq 0 ] ;
        then
        a_result1="O"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v "#" | grep -i indexes`
        c_result1="Options 지시자에 Indexes 포함되어 디렉토리 리스팅 비활성화 되어 있으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v "#" | grep -i indexes`
        c_result1="Options 지시자에 Indexes 포함되어 디렉토리 리스팅 활성화 되어 있으므로 취약"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep httpd | grep -v grep`
    c_result1="httpd Service가 실행중이 아니므로 양호"
    fi
#ubuntu
else
  if [ `ps -ef | grep apache | grep -v grep | wc -l` -gt 0 ] ;
  then
      if [ `cat /etc/apache2/apache2.conf | grep -v "#" | grep -i indexes | wc -l` -eq 0 ] ;
      then
      a_result1="O"
      b_result1=`ps -ef | grep apache | grep -v grep`
      b_result2=`cat /etc/apache2/apache2.conf | grep -v "#" | grep -i indexes`
      c_result1="Options 지시자에 Indexes 포함되어 디렉토리 리스팅 비활성화 되어 있으므로 양호"
      else
    a_result1="X"
    b_result1=`ps -ef | grep apache | grep -v grep`
    b_result2=`cat /etc/apache2/apache2.conf | grep -v "#" | grep -i indexes`
    c_result1="Options 지시자에 Indexes 포함되어 디렉토리 리스팅 활성화 되어 있으므로 취약"
    fi
  else
    a_result1="O"
    b_result1=`ps -ef | grep apache | grep -v grep`
    c_result1="apache 서비스 실행 중이 아니므로 양호"
  fi
fi
#--END

#--START(점검 방법)
scriptResult="1. Apache 서버 활성화 여부
$b_result1
2. Apache 디렉토리 리스팅 제거
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-53(){
#--START(점검항목 설명)
CODE="U-53"
MEASURES="단기"
#--END
#Apache 웹 프로세스 권한 제한


#--START(점검 명령어)
if [ -f /etc/pam.d/system-auth ];
#RHEL 계열
then
    if [ `ps -ef | grep httpd | grep -v grep | wc -l` -gt 0 ] ;
    then
        if [ ` ps -ef | grep httpd | grep root | wc -l` -eq 2 ] ;
        then
        a_result1="O"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`ps -ef | grep httpd | grep root`
        c_result1="Apache 웹 프로세스 권한이 제한 되어 있으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`ps -ef | grep httpd | grep root`
        c_result1="Apache 웹 프로세스 권한이 제한 되어 있지 않으므로 취약"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep httpd | grep -v grep`
    c_result1="httpd Service가 실행중이 아니므로 양호"
    fi
#ubuntu
else
  if [ `ps -ef | grep apache | grep -v grep | wc -l` -gt 0 ] ;
  then
      if [ `ps -ef | grep apache | grep root | wc -l` -eq 2 ] ;
      then
      a_result1="O"
      b_result1=`ps -ef | grep apache | grep -v grep`
      b_result2=`ps -ef | grep apache | grep root | wc -l`
      c_result1="Apache 웹 프로세스 권한이 제한 되어 있으므로 양호"
      else
      a_result1="X"
      b_result1=`ps -ef | grep apache | grep -v grep`
      b_result2=`ps -ef | grep apache | grep root | wc -l`
      c_result1="Apache 웹 프로세스 권한이 제한 되어 있지 않으므로 취약"
      fi
  else
  a_result1="O"
  b_result1=`ps -ef | grep apache | grep -v grep`
  c_result1="apache 서비스가 실행 중이 아니므로 양호"
  fi
fi
#--END

#--START(점검 방법)
scriptResult="1. Apache 서버 활성화 여부
$b_result1
2. Apache 웹 프로세스 권한이 제한 설정 여부
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-54(){
#--START(점검항목 설명)
CODE="U-54"
MEASURES="단기"
#--END
#Apache 상위 디렉토리 접근 금지


#--START(점검 명령어)
if [ -f /etc/pam.d/system-auth ];
#RHEL 계열
then
    if [ `ps -ef | grep httpd | grep -v grep | wc -l` -gt 0 ] ;
    then
        if [ `cat /etc/httpd/conf/httpd.conf | grep -v "#" | grep -i allowoverride | grep -vi none | wc -l` -eq 0 ] ;
        then
        a_result1="O"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v "#" | grep -i allowoverride`
        c_result1="설정 파일에 모든 AllowOverride 지시자가 none으로 설정되어 있으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v "#" | grep -i allowoverride`
        c_result1="설정 파일에 AllowOverride 지시자가 none으로 설정되어 있지 않으므로 취약"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep httpd | grep -v grep`
    c_result1="httpd Service 실행중이 아니므로 양호"
    fi
#ubuntu
else
  if [ `ps -ef | grep apache | grep -v grep | wc -l` -gt 0 ] ;
  then
      if [ `cat /etc/apache2/apache2.conf | grep -v "#" | grep -i allowoverride | grep -vi none | wc -l` -eq 0 ] ;
      then
      a_result1="O"
      b_result1=`ps -ef | grep apache | grep -v grep`
      b_result2=`cat /etc/apache2/apache2.conf | grep -v "#" | grep -i allowoverride`
      c_result1="설정 파일에 모든 AllowOverride 지시자가 none으로 설정되어 있으므로 양호"
      else
    a_result1="X"
    b_result1=`ps -ef | grep apache | grep -v grep`
    b_result2=`cat /etc/apache2/apache2.conf | grep -v "#" | grep -i allowoverride`
    c_result1="설정 파일에 AllowOverride 지시자가 none으로 설정되어 있지 않으므로 취약"
    fi
  else
    a_result1="O"
    b_result1=`ps -ef | grep apache | grep -v grep`
    c_result1="apache 서비스 실행 중이 아니므로 양호"
  fi
fi
#--END

#--START(점검 방법)
scriptResult="1. Apache 서버 활성화 여부
$b_result1
2. Apache DocumentRoot 경로에 불필요한 파일 존재 여부
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-55(){
#--START(점검항목 설명)
CODE="U-55"
MEASURES="Hot-Fix"
#--END
#Apache 불필요한 파일 제거


#--START(점검 명령어)
if [ -f /etc/pam.d/system-auth ];
#RHEL 계열
then
    if [ `ps -ef | grep httpd | grep -v grep | wc -l` -gt 0 ] ;
    then
        DocuRoot=`cat /etc/httpd/conf/httpd.conf | grep -v "#" | grep -i documentroot | awk -F[\"] {'print $2'}`
        if [ `ls -al $DocuRoot | egrep "manual|*.bak" | wc -l` -gt 0 ] ;
        then
        a_result1="X"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`ls -al $DocuRoot | egrep "manual|*.bak"`
        c_result1="DocumentRoot에 불필요한 파일(매뉴얼, 테스트, 임시, 백업, 샘플)이 존재하므로 취약"
        else
        a_result1="O"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`ls -al $DocuRoot | egrep "manual|*.bak"`
        c_result1="DocumentRoot에 불필요한 파일(매뉴얼, 테스트, 임시, 백업, 샘플)이 존재하지 않으므로 양호"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep httpd | grep -v grep`
    c_result1="httpd Service 실행중이 아니므로 양호"
    fi
#ubuntu
else
  if [ `ps -ef | grep apache | grep -v grep | wc -l` -gt 0 ] ;
  then
      DocuRoot=`cat /etc/apache2/sites-available/000-default.conf | grep -i documentroot | awk -F' ' {'print $2'}`
      if [ `ls -al $DocuRoot | egrep "manual|*.bak" | wc -l ` -gt 0 ] ;
      then
      a_result1="X"
      b_result1=`ps -ef | grep apache | grep -v grep`
      b_result2=`ls -al $DocuRoot | egrep "manual|*.bak"`
      c_result1="DocumentRoot에 불필요한 파일(매뉴얼, 테스트, 임시, 백업, 샘플)이 존재하므로 취약"
      else
    a_result1="O"
    b_result1=`ps -ef | grep apache | grep -v grep`
    b_result2=`ls -al $DocuRoot | egrep "manual|*.bak"`
    c_result1="DocumentRoot에 불필요한 파일(매뉴얼, 테스트, 임시, 백업, 샘플)이 존재하지 않으므로 양호"
    fi
  else
    a_result1="O"
    b_result1=`ps -ef | grep apache | grep -v grep`
    c_result1="apache 서비스 실행 중이 아니므로 양호"
  fi
fi
#--END

#--START(점검 방법)
scriptResult="1. Apache 서버 활성화 여부
$b_result1
2. Apache DocumentRoot 경로에 불필요한 파일 존재 여부
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-56(){
#--START(점검항목 설명)
CODE="U-56"
MEASURES="단기"
#--END
#Apache 링크 사용 금지


#--START(점검 명령어)
if [ -f /etc/pam.d/system-auth ];
#RHEL 계열
then
    if [ `ps -ef | grep httpd | grep -v grep | wc -l` -gt 0 ] ;
    then
        if [ `cat /etc/httpd/conf/httpd.conf | grep -v '#' | grep Options | grep FollowSymLinks | wc -l` -gt 0 ] ;
        then
        a_result1="X"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v '#' | grep Options | grep FollowSymLinks`
        c_result1="Options 지시자에 아파치 링크 사용 활성화되어 있으므로 취약"
        else
        a_result1="O"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v '#' | grep Options | grep FollowSymLinks`
        c_result1="Options 지시자에 아파치 링크 사용 비활성화되어 있으므로 양호"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep httpd | grep -v grep`
    c_result1="httpd Service가 실행중이 아니므로 양호"
    fi
#ubuntu
else
  if [ `ps -ef | grep apache | grep -v grep | wc -l` -gt 0 ] ;
  then
    if [ `cat /etc/apache2/apache2.conf | grep -v '#' | grep Options | grep FollowSymLinks | wc -l` -gt 0 ] ;
    then
    a_result1="X"
    b_result1=`ps -ef | grep apache | grep -v grep`
    b_result2=`cat /etc/apache2/apache2.conf | grep -v '#' | grep Options | grep FollowSymLinks`
    c_result1="Options 지시자에 아파치 링크 사용 활성화되어 있으므로 취약"
    else
    a_result1="O"
    b_result1=`ps -ef | grep apache | grep -v grep`
    b_result2=`cat /etc/apache2/apache2.conf | grep -v '#' | grep FollowSymLinks`
    c_result1="Options 지시자에 아파치 링크 사용 비활성화되어 있으므로 양호"
    fi
  else
    a_result1="O"
    b_result1=`ps -ef | grep apache | grep -v grep`
    b_result2=`cat /etc/apache2/apache2.conf | grep -v '#' | grep Options | grep FollowSymLinks`
    c_result1="apache 서비스가 실행 중이 아니므로 양호"
  fi
fi
#--END

#--START(점검 방법)
scriptResult="1. Apache 서버 활성화 여부
$b_result1
2. Apache Options 지시자에 FollowSymLinks 설정 여부
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-57(){
#--START(점검항목 설명)
CODE="U-57"
MEASURES="단기"
#--END
#Apache 파일 업로드 및 다운로드 제한


#--START(점검 명령어)
if [ -f /etc/pam.d/system-auth ];
then
    if [ `ps -ef | grep httpd | grep -v grep | wc -l` -gt 0 ] ;
    then
        if [ `cat /etc/httpd/conf/httpd.conf | grep -v '#' | grep LimitRequestBody | wc -l` -gt 0 ] ;
        then
        a_result1="O"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v '#' | grep LimitRequestBody`
        c_result1="LimitRequestBody가 포함되어 Apache 파일 업로드 및 다운로드를 제한하고 있으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v '#' | grep LimitRequestBody`
        c_result1="LimitRequestBody가 설정되지 않아 Apache 파일 업로드 및 다운로드가 제한되지 않으므로 취약"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep httpd | grep -v grep`
    c_result1="httpd Service가 실행중이 아니므로 양호"
    fi
#ubuntu
else
  if [ `ps -ef | grep apache | grep -v grep | wc -l` -gt 0 ] ;
  then
        if [ `cat /etc/apache2/apache2.conf | grep -v '#' | grep LimitRequestBody | wc -l` -gt 0 ] ;
        then
        a_result1="O"
        b_result1=`ps -ef | grep apache | grep -v grep`
        b_result2=`cat /etc/apache2/apache2.conf | grep -v '#' | grep LimitRequestBody`
        c_result1="LimitRequestBody가 포함되어 Apache 파일 업로드 및 다운로드를 제한하고 있으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep apache | grep -v grep`
        b_result2=`cat /etc/apache2/apache2.conf | grep -v '#' | grep LimitRequestBody`
        c_result1="LimitRequestBody가 설정되지 않아 Apache 파일 업로드 및 다운로드가 제한되지 않으므로 취약"
        fi
  else
  a_result1="O"
  b_result1=`ps -ef | grep apache | grep -v grep`
  b_result2=`cat /etc/apache2/apache2.conf | grep -v '#' | grep LimitRequestBody`
  c_result1="apache 서비스가 실행 중이 아니므로 양호"
  fi
fi
#--END

#--START(점검 방법)
scriptResult="1. Apache 서버 활성화 여부
$b_result1
2. Apache LimitRequestBody 설정 여부
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-58(){
#--START(점검항목 설명)
CODE="U-58"
MEASURES="중기"
#--END
#Apache 아파치 웹 디렉터리 별도 분리현황 점검


#--START(점검 명령어)

if [ -f /etc/pam.d/system-auth ];
then
    if [ `ps -ef | grep httpd | grep -v grep | wc -l` -gt 0 ] ;
    then
        if [ `cat /etc/httpd/conf/httpd.conf | grep DocumentRoot | egrep -i '(/usr/local/apache/htdocs|/usr/local/apache2/htdocs|/var/www/html)' | wc -l` -eq 0 ] ;
        then
        a_result1="O"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v "#" | grep DocumentRoot`
        c_result1="DocumentRoot를 별도의 디렉토리로 지정하였으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v "#" | grep DocumentRoot`
        c_result1="DocumentRoot를 별도의 디렉토리로 지정하지 않았으므로 취약"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep httpd | grep -v grep`
    c_result1="httpd Service가 실행중이 아니므로 양호"
    fi
#ubuntu
else
  if [ `ps -ef | grep apache | grep -v grep | wc -l` -gt 0 ] ;
  then
        if [ `cat /etc/apache2/sites-enabled/000-default.conf | grep -v "#" | grep DocumentRoot | egrep -i '(/usr/local/apache/htdocs|/usr/local/apache2/htdocs|/var/www/html)' | wc -l` -eq 0 ] ;
        then
        a_result1="O"
        b_result1=`ps -ef | grep apache | grep -v grep`
        b_result2=`cat /etc/apache2/sites-enabled/000-default.conf | grep -v "#" | grep DocumentRoot`
        c_result1="DocumentRoot를 별도의 디렉토리로 지정하였으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep apache | grep -v grep`
        b_result2=`cat /etc/apache2/sites-enabled/000-default.conf | grep -v "#" | grep DocumentRoot`
        c_result1="DocumentRoot를 별도의 디렉토리로 지정하지 않았으므로 취약"
        fi
  else
        a_result1="O"
        b_result1=`ps -ef | grep apache | grep -v grep`
        c_result1="apache 서비스가 실행 중이 아니므로 양호"
        fi
  fi
#--END

#--START(점검 방법)
scriptResult="1. Apache 서버 활성화 여부
$b_result1
2. Apache 웹 서비스 영역의 분리
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-59(){
#--START(점검항목 설명)
CODE="U-59"
MEASURES="Hot-Fix"
#--END
#원격 접속 프로토콜을 암호화 전송이 되는 프로토콜로 사용하는 여부 확인


#--START(점검 명령어)

if [ `netstat -anp | grep :23 | grep tcp | grep LISTEN |wc -l` -eq 0 ] ;
then
  a_result1="O"
  b_result1=`netstat -anp | grep :23 | grep tcp | grep LISTEN`
  c_result1="Telnet 서비스 비활성화되어 있으므로 양호"
else
   a_result1="X"
   b_result1=`netstat -anp | grep :23 | grep tcp | grep LISTEN`
   c_result1="Telnet 서비스 활성화되어 있으므로 취약"
fi

if [ `ps -ef | grep sshd | grep -v grep |wc -l` -gt 0 ] ;
then
   a_result2="O"
   b_result2=`ps -ef | grep sshd | grep -v grep`
   c_result2=", SSH 프로토콜 사용하므로 양호"
else
   a_result2="X"
   b_result2=`ps -ef | grep sshd | grep -v grep`
   c_result2=", SSH 프로토콜 사용하지 않으므로 취약"
fi


if [ $a_result1 == "O" -a $a_result2 == "O" ] ;
then
    a_result3="O"
else
    a_result3="X"
fi
#--END

#--START(점검 방법)
scriptResult="1. Telnet 서비스 활성화 여부
$b_result1
2. SSH 프로토콜 사용 여부
$b_result2
"
chkStatus="$a_result3"
chkResult="[결과값]
$c_result1 $c_result2"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-60(){
#--START(점검항목 설명)
CODE="U-60"
MEASURES="단기"
#--END
#FTP 서비스 확인


#--START(점검 명령어)

if [ `netstat -an | grep tcp | grep :21 | grep LISTEN | wc -l` -gt 0 ] ;
then
a_result1="X"
b_result1=`netstat -an | grep tcp | grep :21 | grep LISTEN`
c_result1="FTP 서비스가 활성화 되어 있으므로 취약"
else
a_result1="O"
b_result1=`netstat -an | grep tcp | grep :21 | grep LISTEN`
c_result1="FTP 서비스가 비활성화 되어 있으므로 양호"
fi
#--END

#--START(점검 방법)
scriptResult="1. ftp 활성화 여부
$b_result1
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-61(){
#--START(점검항목 설명)
CODE="U-61"
MEASURES="Hot-Fix"
#--END
#ftp 계정 shell 제한


#--START(점검 명령어)
      if [ `cat /etc/passwd | grep ^ftp | wc -l` -gt 0 ];
      then
           if [ `cat /etc/passwd | grep ^ftp | egrep '(/bin/false|/sbin/nologin)' | wc -l` -gt 0 ];
           then
            a_result1="O"
            b_result1=`cat /etc/passwd | grep ^ftp`
            c_result1="쉘 권한 제한이 설정되어 있으므로 양호"
            else
            a_result1="X"
            b_result1=`cat /etc/passwd | grep ^ftp`
            c_result1="쉘 권한 제한이 설정되어 있지 않으므로 취약"
            fi
      else
      a_result1="O"
      b_result1=`cat /etc/passwd | grep ^ftp`
      c_result1="ftp user가 존재하지 않음"
      fi
#--END

#--START(점검 방법)
scriptResult="1. ftp 계정 쉘 권한 점검
$b_result1
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-62(){
#--START(점검항목 설명)
CODE="U-62"
MEASURES="Hot-Fix"
#--END
#Ftpusers 파일 소유자 및 권한 설정


#--START(점검 명령어)
#RHEL
if [ -f /etc/pam.d/system-auth ];
then
    if [ `ps -ef | grep vsftpd | grep -v grep | wc -l` -gt 0 ];
    then
        if [ -f /etc/ftpusers ];
        then
            if [ "`f_permit /etc/vsftpd/ftpusers 640`" == "OK" ];
            then
                    if [ `ls -l /etc/vsftpd/ftpusers 2> /dev/null | awk {'print $3'}` == "root" ];
                    then
                    a_result1="O"
                    b_result1=`ls -l /etc/vsftpd/ftpusers 2> /dev/null`
                    c_result1="/etc/vsftpd/ftpusers 파일의 권한이 640 이하이며, 소유자가 root이므로 양호"
                    else
                    a_result1="X"
                    b_result1=`ls -l /etc/vsftpd/ftpusers 2> /dev/null`
                    c_result1="/etc/vsftpd/ftpusers 파일의 권한이 640 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
                    fi
            else
            a_result1="X"
            b_result1=`ls -l /etc/vsftpd/ftpusers 2> /dev/null`
            c_result1="/etc/vsftpd/ftpusers 파일의 권한이 640 초과이므로 취약"
            fi
        else
        a_result1="N"
        c_result1="/etc/vsftpd/ftpusers 파일이 존재하지 않아 접근 제어 할 수 없으므로 취약"
        fi

        if [ `ls -al /etc/vsftpd/user_list 2> /dev/null | wc -l` -eq 1 ];
        then
             if [ "`f_permit /etc/vsftpd/user_list 640`" == "OK" ];
             then
                   if [ `ls -l /etc/vsftpd/user_list 2> /dev/null | awk {'print $3'}` == "root" ];
                   then
                   a_result2="O"
                   b_result2=`ls -l /etc/vsftpd/user_list 2> /dev/null`
                   c_result2="/etc/vsftpd/user_list 파일의 권한이 640 이하이며, 소유자가 root이므로 양호"
                   else
                   a_result2="X"
                   b_result2=`ls -l /etc/vsftpd/user_list 2> /dev/null`
                   c_result2="/etc/vsftpd/user_list 파일의 권한이 640 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
                   fi
             else
             a_result2="X"
             b_result2=`ls -l /etc/vsftpd/user_list 2> /dev/null`
             c_result2="/etc/vsftpd/user_list 파일의 권한이 640 초과이므로 취약"
             fi
        else
        a_result2="N"
        b_result2=`ls -l /etc/vsftpd/user_list 2> /dev/null`
        c_result2="/etc/vsftpd/user_list 파일이 존재하지 않아 접근 제어 할 수 없으므로 취약"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep vsftpd | grep -v grep`
    c_result1="FTP 서비스가 동작하지 않으므로 양호"
    fi
#Ubuntu
else
    if [ `ps -ef | grep vsftpd | grep -v grep | wc -l` -gt 0 ];
    then
        if [ -f /etc/ftpusers ];
        then
            if [ "`f_permit /etc/ftpusers 640`" == "OK" ];
            then
                  if [ `ls -l /etc/ftpusers 2> /dev/null | awk {'print $3'}` == "root" ];
                  then
                  a_result3="O"
                  b_result1=`ls -l /etc/ftpusers 2> /dev/null`
                  c_result1="/etc/ftpusers 파일의 권한이 640 이하이며, 소유자가 root이므로 양호"
                  else
                  a_result3="X"
                  b_result1=`ls -l /etc/ftpusers 2> /dev/null`
                  c_result1="/etc/ftpusers 파일의 권한이 640 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
                  fi
            else
            a_result3="X"
            b_result1=`ls -l /etc/ftpusers 2> /dev/null`
            c_result1="/etc/ftpusers 파일의 권한이 640 초과이므로 취약"
            fi
        else
        a_result3="X"
        c_result1="ftp 서비스를 사용하나 /etc/ftpusers 파일이 존재하지 않아 접근 제어를 할 수 없으므로 취약"
        fi
    else
    a_result3="O"
    b_result1=`ps -ef | grep vsftpd | grep -v grep`
    c_result1="FTP 서비스가 동작하지 않으므로 양호"
    fi
fi

if [ "$a_result1" == "X" ] ;
then
  a_result3="X"
elif [ "$a_result2" == "X" ] ;
then
  a_result3="X"
else
  a_result3="O"
fi

if [ "$a_result1" == "N" -a "$a_result2" == "N" ] ;
then

    a_result3="X"
    c_result1="FTP 서비스를 사용하나 ftpusers 파일 및 user_list 파일이 존재하지 않아 접근 제어가 불가능하므로 취약"
    c_result2=""
fi
#--END

#--START(점검 방법)
scriptResult="1. ftpusers 또는 user_list 파일 접근 권한
$b_result1
$b_result2
"
chkStatus="$a_result3"
chkResult="[결과값]
$c_result1
$c_result2"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-63(){
#--START(점검항목 설명)
CODE="U-63"
MEASURES="Hot-Fix"
#--END
#FTP 사용자 설정에 root 직접 접속 차단 설정


#--START(점검 명령어)

#RHEL 계열
if [ -f /etc/pam.d/system-auth ];
then
    if [ `ps -ef | grep vsftpd | grep -v grep | wc -l` -gt 0 ];
    then
        if [ `cat /etc/vsftpd/vsftpd.conf | grep -v '#'| grep -i userlist_enable=YES | wc -l` -eq 1 ];
        then
            if [ `cat /etc/vsftpd/vsftpd.conf | grep -v '#'| grep -i userlist_deny=NO | wc -l` -eq 1 ];
            then
                  if [ `cat /etc/vsftpd/user_list | grep -v '#'| grep -i root | wc -l` -eq 1 ];
                  then
                  a_result1="O"
                  b_result1=`ps -ef | grep vsftpd | grep -v grep`
                  b_result2=`cat /etc/vsftpd/user_list | grep -v "#"`
                  c_result1="userlist_enable=YES, userlist_deny=NO 설정으로 user_list 내 포함 된 계정은 접속 불가함. 해당 파일에 root가 존재하므로 접속 차단 되어 양호"
                  else
                  a_result1="X"
                  b_result1=`ps -ef | grep vsftpd | grep -v grep`
                  b_result2=`cat /etc/vsftpd/user_list | grep -v "#"`
                  c_result1="userlist_enable=YES, userlist_deny=NO 설정으로 user_list 내 포함된 계정만 접속 불가함. 해당 파일에 root가 존재하지 않으므로 root 접속 차단 안되어 취약"
                  fi
            else
                  if [ `cat /etc/vsftpd/user_list | grep -v "#" | grep root | wc -l` -eq 0 -o `cat /etc/vsftpd/user_list | grep "#root" | wc -l` -eq 1 ];
                  then
                  a_result1="O"
                  b_result1=`ps -ef | grep vsftpd | grep -v grep`
                  b_result2=`cat /etc/vsftpd/user_list | grep -v "#"`
                  c_result1="uselist_enable=YES이고 userlist_deny=YES 또는 userlist_deny 미설정 되어 user_list 내 포함된 계정은 접속 됨. 해당 파일에 root가 존재하지 않으므로 양호"
                  else
                  a_result1="X"
                  b_result1=`ps -ef | grep vsftpd | grep -v grep`
                  b_result2=`cat /etc/vsftpd/user_list | grep -v "#"`
                  c_result1="uselist_enable=YES이고 userlist_deny=YES 또는 userlist_deny 미설정 되어 user_list 내 포함된 계정은 접속 됨. 해당 파일에 root가 존재하므로 취약"
                  fi
            fi
        else
            if [ `cat /etc/vsftpd/ftpusers | grep -v '#'| grep root | wc -l` -eq 1 ];
            then
            a_result1="O"
            b_result1=`ps -ef | grep vsftpd | grep -v grep`
            b_result2=`cat /etc/vsftpd/ftpusers | grep -v '#'`
            c_result1="userlist_enable=NO일 경우 ftpusers 내 설정된 계정만 접속 불가함. 해당 파일에 root가 존재하므로 root 접속 차단 되어 양호"
            else
            a_result1="X"
            b_result1=`ps -ef | grep vsftpd | grep -v grep`
            b_result2=`cat /etc/vsftpd/ftpusers | grep -v '#'`
            c_result1="userlist_enable=NO, userlist_deny=NO 설정으로 ftpusers 내 설정된 계정만 접속 불가함. 해당 파일에 root가 존재하지 않으므로 root 접속 차단 안되어 취약"
            fi
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep vsftpd | grep -v grep`
    c_result1="FTP 서비스가 동작하지 않으므로 양호"
    fi
# ubuntu
else
    if [ `ps -ef | grep vsftpd | grep -v grep | wc -l` -gt 0 ];
    then
        if [ -f /etc/ftpusers ];
        then
              if [ `cat /etc/ftpusers| grep -v "#" | grep root | wc -l ` -eq 0 ];
              then
              a_result1="O"
              b_result1=`ps -ef | grep vsftpd | grep -v grep`
              b_result2=`cat /etc/ftpusers| grep -v "#"`
              c_result1="ftpusers 파일 내 root 계정이 존재하지 않아 root 접속이 차단 되어 양호"
              else
              a_result1="X"
              b_result1=`ps -ef | grep vsftpd | grep -v grep`
              b_result2=`cat /etc/ftpusers| grep -v "#"`
              c_result1="ftpusers 파일 내 root 계정이 존재하여 root 접속이 차단 되지 않아 취약"
              fi
        else
        a_result1="X"
        b_result1=`ps -ef | grep vsftpd | grep -v grep`
        c_result1="FTP 서비스를 사용하나 ftpusers 파일이 존재하지 않아 root 접속이 차단 되지 않으므로 취약"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep vsftpd | grep -v grep`
    c_result1="FTP 서비스가 동작하지 않으므로 양호"
    fi
fi
#--END

#--START(점검 방법)
scriptResult="1. FTP 서비스 활성화 여부
$b_result1
2. FTP 사용자 설정에 root 직접 접속 차단 설정 되었는지 확인
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-64(){
#--START(점검항목 설명)
CODE="U-64"
MEASURES="Hot-Fix"
#--END
#at 파일 소유자 및 권한 설정


#--START(점검 명령어)
if [ `ls -al /etc/at.allow 2> /dev/null | wc -l` -eq 1 ];
then
        if [ `ls -al /etc/at.deny 2> /dev/null | wc -l` -eq 1 ];
        then
                  if [[ "`f_permit /etc/at.allow 640`" == "OK" && "`f_permit /etc/at.deny 640`" == "OK" ]];
                  then
                           if [[ `ls -l /etc/at.allow 2> /dev/null | awk {'print $3'}` == "root" && `ls -l /etc/at.deny 2> /dev/null | awk {'print $3'}` == "root" ]];
                           then
                                a_result1="O"
                                b_result1=`ls -al /etc/at.allow 2> /dev/null`
                                b_result2=`ls -al /etc/at.deny 2> /dev/null`
                                c_result1="at.allow, at.deny 파일이 모두 존재하고 파일 소유자가 root이고 권한이 640이하이므로 양호"
                            else
                                a_result1="X"
                                b_result1=`ls -al /etc/at.allow 2> /dev/null`
                                b_result2=`ls -al /etc/at.deny 2> /dev/null`
                                c_result1="at.allow, at.deny 파일이 모두 존재하나 파일 소유자가 root가 아니므로 취약"
                            fi
                  else
                  a_result1="X"
                  b_result1=`ls -al /etc/at.allow 2> /dev/null`
                  b_result2=`ls -al /etc/at.deny 2> /dev/null`
                  c_result1="at.allow, at.deny 파일이 모두 존재하나 파일 권한이 640 초과이므로 취약"
                  fi
        else
            if [ "`f_permit /etc/at.allow 640`" == "OK" ];
            then
                if [ `ls -l /etc/at.allow 2> /dev/null | awk {'print $3'}` == "root" ];
                then
                a_result1="O"
                b_result1=`ls -al /etc/at.allow 2> /dev/null`
                c_result1="at.allow 파일만 존재하고 파일 소유자가 root이고 권한이 640이하이므로 양호"
                else
                a_result1="X"
                b_result1=`ls -al /etc/at.allow 2> /dev/null`
                c_result1="at.allow 파일만 존재하나 파일 소유자가 root로 설정되어 있지 않으므로 취약"
                fi
            else
            a_result1="X"
            b_result1=`ls -al /etc/at.allow 2> /dev/null`
            c_result1="at.allow 파일만 존재하나 권한이 640 초과이므로 취약"
            fi
      fi


elif [ `ls -al /etc/at.deny 2> /dev/null | wc -l` -eq 1 ];
then
    a_result1="X"
    b_result2=`ls -al /etc/at.deny 2> /dev/null`
    c_result1="at.deny 파일만 존재하므로 취약"

else
    a_result1="O"
    c_result1="at.allow, at.deny 파일 모두 존재하지 않으므로 양호"
fi

#--END

#--START(점검 방법)
scriptResult="1. at.allow 파일 소유자 및 권한
$b_result1
2. at.deny 파일 소유자 및 권한
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-65(){
#--START(점검항목 설명)
CODE="U-65"
MEASURES="단기"
#--END
#SNMP 서비스 활성화 여부


#--START(점검 명령어)

if [ `ps -ef | grep snmp | grep -v grep | wc -l` -ge 1 ];
then
      a_result1="X"
      b_result1=`ps -ef | grep snmp | grep -v grep`
      c_result1="SNMP 서비스가 동작하므로 취약"
else
      a_result1="O"
      b_result1=`ps -ef | grep snmp | grep -v grep`
      c_result1="SNMP 서비스가 동작하지 않으므로 양호"
fi
#--END

#--START(점검 방법)
scriptResult="1. SNMP 서비스 활성화 여부
$b_result1
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-66(){
#--START(점검항목 설명)
CODE="U-66"
MEASURES="Hot-Fix"
#--END
#SNMP 서비스 사용시 커뮤니티 스트링 복잡도 설정


#--START(점검 명령어)

#RHEL 계열
if [ -f /etc/pam.d/system-auth ];
then
    if [ `ps -ef | grep snmp | grep -v grep | wc -l` -gt 0 ];
    then
        if [ `cat /etc/snmp/snmpd.conf | grep -v "#"| grep -i com2sec |egrep -i '(private|public)' | wc -l` -eq 0 ];
        then
        a_result1="O"
        b_result1=`ps -ef | grep snmp | grep -v grep`
        b_result2=`cat /etc/snmp/snmpd.conf | grep -v "#"| grep -i com2sec`
        c_result1="SNMP Community String 값이 'private' 또는 'public'으로 설정되어 있지 않으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep snmp | grep -v grep`
        b_result2=`cat /etc/snmp/snmpd.conf | grep -v "#"| grep -i com2sec`
        c_result1="SNMP Community String 값이 'private' 또는 'public'으로 설정되어 있으므로 취약"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep snmp | grep -v grep`
    c_result1="SNMP 서비스가 동작하지 않으므로 양호"
    fi
#ubuntu
else
    if [ `ps -ef | grep snmp | grep -v grep | wc -l` -gt 0 ];
    then
        if [ `cat /etc/snmp/snmpd.conf | grep -v "#"| grep -i rocommunity |egrep -i '(private|public)' | wc -l` -eq 0 ];
        then
        a_result1="O"
        b_result1=`ps -ef | grep snmp | grep -v grep`
        b_result2=`cat /etc/snmp/snmpd.conf | grep -v "#"| grep -i rocommunity`
        c_result1="SNMP Community String 값이 'private' 또는 'public'으로 설정되어 있지 않으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep snmp | grep -v grep`
        b_result2=`cat /etc/snmp/snmpd.conf | grep -v "#"| grep -i rocommunity`
        c_result1="SNMP Community String 값이 'private' 또는 'public'으로 설정되어 있으므로 취약"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep snmp | grep -v grep`
    c_result1="SNMP 서비스가 동작하지 않으므로 양호"
    fi
fi
#--END

#--START(점검 방법)
scriptResult="1. SNMP 서비스 활성화 여부
$b_result1
2. SNMP Comunity String 설정 값
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-67(){
#--START(점검항목 설명)
CODE="U-67"
MEASURES="Hot-Fix"
#--END
#로그온 시 경고 메시지 제공

#--START(점검 명령어)
unset a_result a_result1 a_result2 a_result3 a_result4 b_result b_result1 b_result2 b_result3 b_result11 b_result12 b_result13 b_result21 b_result22 c_result1 c_result2 c_result3 c_result4
#RHEL 계열
if [ -f /etc/pam.d/system-auth ];
then
    #/etc/issue.net
    if [ -f /etc/issue.net ];
    then
        a_result1="(수동)"
        b_result1=`cat /etc/issue.net`
    else
    a_result1="X"
    c_result1="/etc/issue.net 파일이 없으므로 취약"
    fi

    #sshd_config
    if [ `ps -ef | grep sshd | grep -v grep |wc -l` -gt 0 ] ;
    then
          if [ -f /etc/ssh/sshd_config ];
          then
              if [ `cat /etc/ssh/sshd_config | grep -v "#" | grep -i Banner | wc -l` -gt 0 ] ;
              then
              Banner=`cat /etc/ssh/sshd_config | grep -v "#" | grep -i Banner | awk {'print $2'}`
              a_result2="(수동)"
              b_result2=`cat $Banner`
              else
              a_result2="X"
              c_result2="ssh 접속 시 로그온 메세지 설정이 되어 있지 않으므로 취약"
              fi
          else
          a_result2="X"
          c_result2="/etc/ssh/sshd_config 파일이 없으므로 취약"
          fi
    fi

    #/etc/motd
    if [ -f /etc/motd ];
    then
        a_result3="(수동)"
        b_result3=`cat /etc/motd`
    else
    a_result3="X"
    c_result3="/etc/motd 파일이 없으므로 취약"
    fi

#Ubuntu
else
  #/etc/issue.net
  if [ -f /etc/issue.net ];
  then
      a_result1="(수동)"
      b_result1=`cat /etc/issue.net`
  else
  a_result1="X"
  c_result1="/etc/issue.net 파일이 없으므로 취약"
  fi

  #sshd_config
  if [ `ps -ef | grep sshd | grep -v grep |wc -l` -gt 0 ] ;
  then
        if [ -f /etc/ssh/sshd_config ];
        then
            if [ `cat /etc/ssh/sshd_config | grep -v "#" | grep -i Banner | wc -l` -gt 0 ] ;
            then
            Banner=`cat /etc/ssh/sshd_config | grep -v "#" | grep -i Banner | awk {'print $2'}`
            a_result2="(수동)"
            b_result2=`cat $Banner`
            else
            a_result2="X"
            c_result2="ssh 접속 시 로그온 메세지 설정이 되어 있지 않으므로 취약"
            fi
        else
        a_result2="X"
        c_result2="/etc/ssh/sshd_config 파일이 없으므로 취약"
        fi
  fi


  if [ -f /etc/update-motd.d/00-header ];
  then
    a_result3="(수동)"
    b_result3=`/bin/bash /etc/update-motd.d/00-header`
  else
    a_result3="X"
    c_result3="/etc/update-motd.d/00-header 파일이 없으므로 취약"
  fi
fi


if [ "$a_result1" == "(수동)" -o "$a_result2" == "(수동)" -o "$a_result3" == "(수동)" ] ;
then
a_result5="(수동 점검 필요)"
else
a_result5="X"
fi
#--END

#--START(점검 방법)
scriptResult="1./etc/issue.net 점검
$b_result1
2.sshd_config 점검
$b_result2
3.motd 점검
$b_result3
"
chkStatus="$a_result5"
chkResult="[결과값]
$c_result1
$c_result2
$c_result3"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-68(){
#--START(점검항목 설명)
CODE="U-68"
MEASURES="Hot-Fix"
#--END
#NFS 설정 파일 접근 권한


#--START(점검 명령어)

if [ `ls -al /etc/exports 2> /dev/null | wc -l` -gt 0 ];
then
    if [ "`f_permit /etc/exports 644`" == "OK" ];
    then
         if [ `ls -l /etc/exports 2> /dev/null | awk {'print $3'}` == "root" ];
         then
         a_result1="O"
         b_result1=`ls -l /etc/exports 2> /dev/null`
         c_result1="/etc/exports 파일의 권한이 644 이하이며, 소유자가 root이므로 양호"
         else
         a_result1="X"
         b_result1=`ls -l /etc/exports 2> /dev/null`
         c_result1="/etc/exports 파일의 권한이 644 이하로 설정되어 있으나 소유자가 root가 아니므로 취약"
        fi
    else
    a_result1="X"
    b_result1=`ls -l /etc/exports 2> /dev/null`
    c_result1="/etc/exports 파일의 권한이 644 초과이므로 취약"
    fi
else
a_result1="N/A"
b_result1=`ls -l /etc/exports 2> /dev/null`
c_result1="/etc/exports 파일이 존재하지 않으므로 해당사항 없음"
fi
#--END

#--START(점검 방법)
scriptResult="1. NFS 설정파일 접근 권한
$b_result1
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-69(){
#--START(점검항목 설명)
CODE="U-69"
MEASURES="Hot-Fix"
#--END
#expn, vrfy 명령어 제한


#--START(점검 명령어)
#Sendmail 사용 시
    if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ] ;
    then
        if [ `cat /etc/mail/sendmail.cf | grep -i PrivacyOptions | grep authwarnings | grep novrfy| grep noexpn |grep -v "#" | wc -l` -gt 0 ];
        then
        a_result1="O"
        b_result1=`ps -ef | grep sendmail | grep -v grep`
        b_result2=`cat /etc/mail/sendmail.cf | grep -i PrivacyOptions | grep authwarnings | grep novrfy| grep noexpn | grep -v "#"`
        c_result1="sendmail 서비스 사용 시 expn, vrfy 명령어 제한이 설정되어 있으므로 양호"
        elif [ `cat /etc/mail/sendmail.cf | grep -i PrivacyOptions | grep authwarnings | grep goaway | grep -v "#" | wc -l` -gt 0 ];
        then
        a_result1="O"
        b_result1=`ps -ef | grep sendmail | grep -v grep`
        b_result2=`cat /etc/mail/sendmail.cf | grep -i PrivacyOptions | grep authwarnings`
        c_result1="sendmail 서비스 사용 시 expn, vrfy 명령어 제한이 설정되어 있으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep sendmail | grep -v grep`
        b_result2=`cat /etc/mail/sendmail.cf | grep -i PrivacyOptions | grep authwarnings`
        c_result1="sendmail 서비스 사용 시 expn, vrfy 명령어 제한이 설정되어 있지 않으므로 취약"
        fi
    else
    a_result1="O"
    b_result1=`ps -ef | grep sendmail | grep -v grep`
    c_result1="Sendmail 서비스를 사용하지 않으므로 양호"
    fi

#Postfix 사용 시
    if [ `ps -ef | grep postfix | grep -v grep | wc -l` -gt 0 ] ;
    then
        if [ `cat /etc/postfix/main.cf | grep -i disable_vrfy_command | grep -i yes | grep -v "#" | wc -l` -gt 0 ];
        then
        a_result2="O"
        b_result3=`ps -ef | grep postfix | grep -v grep`
        b_result4=`cat /etc/postfix/main.cf | grep -i disable_vrfy_command`
        c_result2="postfix 서비스 사용 시 expn, vrfy 명령어 제한이 설정되어 있으므로 양호"
        else
        a_result2="X"
        b_result3=`ps -ef | grep postfix | grep -v grep`
        b_result4=`cat /etc/postfix/main.cf | grep -i disable_vrfy_command`
        c_result2="postfix 서비스 사용 시 expn, vrfy 명령어 제한이 설정되어 있지 않으므로 취약"
        fi
    else
    a_result2="O"
    b_result3=`ps -ef | grep postfix | grep -v grep`
    c_result2="Postfix 서비스를 사용하지 않으므로 양호"
    fi

    if [ $a_result1 == "O" -a $a_result2 == "O" ] ;
    then
        a_result3="O"
    else
        a_result3="X"
    fi
#--END

#--START(점검 방법)
scriptResult="1.Sendmail 서비스 사용 여부
$b_result1
2. Sendmail 사용 시, expn, vrfy 명령어 제한 설정
$b_result2
3.Postfix 서비스 사용 여부
$b_result3
4.Postfix 사용 시, expn, vrfy 명령어 제한 설정
$b_result4
"
chkStatus="$a_result3"
chkResult="[결과값]
$c_result1
$c_result2"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-70(){
#--START(점검항목 설명)
CODE="U-70"
MEASURES="Hot-Fix"
#--END
#운영 중인 웹서버의 버전 정보 노출 금지 설정 점검


#--START(점검 명령어)

if [ -f /etc/pam.d/system-auth ];
#RHEL 계열
then
    if [ `ps -ef | grep httpd | grep -v grep | wc -l` -gt 0 ] ;
    then
        if [ `cat /etc/httpd/conf/httpd.conf | grep -v "#" |egrep -i '(ServerTokens Prod|ServerSignature off)' | wc -l` -eq 2 ] ;
        then
        a_result1="O"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v "#" |egrep -i '(ServerTokens|ServerSignature)'`
        c_result1="웹 서버 버전 정보 노출 방지를 위한 설정이 되어 있으므로 양호"
        else
        a_result1="X"
        b_result1=`ps -ef | grep httpd | grep -v grep`
        b_result2=`cat /etc/httpd/conf/httpd.conf | grep -v "#" |egrep -i '(ServerTokens|ServerSignature)'`
        c_result1="웹 서버 버전 정보 노출 방지를 위한 설정이 되어 있지 않으므로 취약"
        fi
    else
      a_result1="O"
      b_result1=`ps -ef | grep apache | grep -v grep`
      c_result1="apache 서비스가 실행 중이 아님"
    fi
#Ubuntu
else
    if [ `ps -ef | grep apache | grep -v grep | wc -l` -gt 0 ] ;
    then
      if [ `cat /etc/apache2/conf-enabled/security.conf | grep -v "#" |egrep -i '(ServerTokens Prod|ServerSignature off)' | wc -l` -eq 2 ] ;
      then
      a_result1="O"
      b_result1=`ps -ef | grep apache | grep -v grep`
      b_result2=`cat /etc/apache2/conf-enabled/security.conf | grep -v "#" |egrep -i '(ServerTokens|ServerSignature)'`
      c_result1="웹 서버 버전 정보 노출 방지를 위한 설정이 되어 있으므로 양호"
      else
      a_result1="X"
      b_result1=`ps -ef | grep apache | grep -v grep`
      b_result2=`cat /etc/apache2/conf-enabled/security.conf | grep -v "#" |egrep -i '(ServerTokens|ServerSignature)'`
      c_result1="웹 서버 버전 정보 노출 방지를 위한 설정이 되어 있지 않으므로 취약"
      fi
  else
    a_result1="O"
    b_result1=`ps -ef | grep apache | grep -v grep`
    c_result1="apache 서비스가 실행 중이 아님"
  fi
fi
#--END

#--START(점검 방법)
scriptResult="1. Apache 서버 활성화 여부
$b_result1
2. Apache 버전 정보 노출 방지 설정 여부
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-71(){
#--START(점검항목 설명)
CODE="U-71"
MEASURES="중기"
#--END
#최신 보안패치 및 벤더 권고사항 적용
#--START(점검 명령어)
a_result1="-"
b_result1=`uname -r`
b_result2=`rpm -qa openssl`
b_result3=`apt list --installed | grep ^openssl`
b_result4=`rpm -qa openssh`
b_result5=`apt list --installed | grep openssh-server`
#--END

#--START(점검 방법)
scriptResult="1. OS 버전 점검
$OS_VERSION
2. Kernel 버전 점검
$b_result1
3. OpenSSL 버전 점검
$b_result2
$b_result3
4. OpenSSH 버전 점검
$b_result4
$b_result5
"
chkStatus="$a_result1"
chkResult="[결과값]
인터뷰 시 확인
"

#--END

#--START(JSON 형식 출력)
json_change_m
}


function U-72(){
#--START(점검항목 설명)
CODE="U-72"
MEASURES="단기"
#--END
#로그의 정기적 검토 및 보고
a_result1="-"
#--START(점검 방법)
scriptResult="인터뷰 시 확인"
chkStatus="$a_result1"
chkResult="[결과값]
인터뷰 시 확인"
#--END

#--START(JSON 형식 출력)
json_change_m
}

function U-73(){
#--START(점검항목 설명)
CODE="U-73"
MEASURES="단기"
#--END
#정책에 따른 시스템 로깅 설정


#--START(점검 명령어)

if [ -f /etc/pam.d/system-auth ];
#[RHEL 계열]
then
  if [ `ps -ef|grep rsyslog|grep -v grep|grep -v vi|wc -l` -gt 0 ] ;
  then
      if [ `cat /etc/rsyslog.conf | grep -v "#" | grep "authpriv.*" | wc -l` -eq 2 ] ;
      then
      a_result1="O"
      b_result1=`ps -ef|grep rsyslog|grep -v grep|grep -v vi`
      b_result2=`cat /etc/rsyslog.conf | grep -v "#" | grep "authpriv.*"`
      c_result1="설정 파일 내 시스템 로깅 설정이 되어 있으므로 양호"
      else
      a_result1="X"
      b_result1=`ps -ef|grep rsyslog|grep -v grep|grep -v vi`
      b_result2=`cat /etc/rsyslog.conf | grep -v "#" | grep "authpriv.*"`
      c_result1="설정 파일 내 시스템 로깅 설정이 되어 있지 않으므로 취약"
      fi
  else
      a_result1="X"
      b_result1=`ps -ef|grep rsyslog|grep -v grep|grep -v vi`
      c_result1="rsyslog 서비스를 사용하지 않으므로 취약"
  fi
#Ubuntu
else
  if [ `ps -ef|grep rsyslog|grep -v grep|grep -v vi|wc -l` -gt 0 ] ;
  then
      if [ `cat /etc/rsyslog.d/50-default.conf | grep -v "#" | grep "authpriv" | wc -l` -eq 2 ]
      then
      a_result1="O"
      b_result1=`ps -ef|grep rsyslog|grep -v grep|grep -v vi`
      b_result2=`cat /etc/rsyslog.d/50-default.conf | grep -v "#" | grep "authpriv"`
      c_result1="설정 파일 내 시스템 로깅 설정이 되어 있으므로 양호"
      else
      a_result1="O"
      b_result1=`ps -ef|grep rsyslog|grep -v grep|grep -v vi`
      b_result2=`cat /etc/rsyslog.d/50-default.conf | grep -v "#" | grep "authpriv"`
      c_result1="설정 파일 내 시스템 로깅 설정이 되어 있지 않으므로 취약"
    fi
  else
    a_result1="X"
    b_result1=`ps -ef|grep rsyslog|grep -v grep|grep -v vi`
    c_result1="rsyslog 서비스를 사용하지 않으므로 취약"
  fi
fi
#--END

#--START(점검 방법)
scriptResult="1. rsyslog 서비스 사용 여부
$b_result1
2. 시스템 로깅 설정 여부
$b_result2
"
chkStatus="$a_result1"
chkResult="[결과값]
$c_result1"
#--END

echo "호스트명" >> total_result.txt
hostname -i >> total_result.txt

echo -e "\n[네트워크 연결 상태]" >> total_result.txt
netstat -anp >> total_result.txt

echo -e "\n[pts 설정 확인]" >> total_result.txt
cat /etc/securetty | grep -v "#"| grep pts >> total_result.txt

echo -e "\n[pam_securetty.so 설정 확인]" >> total_result.txt
cat /etc/pam.d/login | grep -v "#" | grep pam_securetty.so >> total_result.txt

echo -e "\n[/etc/ssh/sshd_config]" >> total_result.txt
echo "- PermitRootLogin 설정 확인" >> total_result.txt
cat /etc/ssh/sshd_config | grep -v "#" | grep -i PermitRootLogin >> total_result.txt

echo -e "\n- PasswordAuthentication 설정 확인" >> total_result.txt
cat /etc/ssh/sshd_config | grep -v "#" | grep -i PasswordAuthentication >> total_result.txt

echo -e "\n[PEM KEY]" >> total_result.txt
cat /root/.ssh/authorized_keys >> total_result.txt

echo -e "\n[패스워드 관련 설정]" >> total_result.txt
echo "- RHEL, CentOS, Amazon Linux" >> total_result.txt
echo "system-auth 설정" >> total_result.txt
cat /etc/pam.d/system-auth | grep -v "#" >> total_result.txt

echo -e "\npassword-auth 설정" >> total_result.txt
cat /etc/pam.d/password-auth | grep -v "#" >> total_result.txt

echo -e "\n- Debian, Ubuntu" >> total_result.txt
echo "common-password 설정" >> total_result.txt
cat /etc/pam.d/common-password | grep -v "#" | sed '/^$/d' >> total_result.txt

echo -e "\ncommon-auth 설정" >> total_result.txt
cat /etc/pam.d/common-auth | grep -v "#" | sed '/^$/d' >> total_result.txt

echo -e "\n- 공통" >> total_result.txt
echo "pam_pwquality.conf 설정" >> total_result.txt
cat /etc/security/pwquality.conf | grep -v "#" >> total_result.txt

echo -e "\n패스워드 최대/최소 사용기간, 최소 길이 설정" >> total_result.txt
cat /etc/login.defs | grep -v "#" | grep PASS >> total_result.txt

echo -e "\n[계정 관련 설정]" >> total_result.txt
echo "/etc/passwd 파일 확인" >> total_result.txt
cat /etc/passwd >> total_result.txt

echo -e "\n/etc/shadow 파일 확인" >> total_result.txt
cat /etc/shadow >> total_result.txt

echo -e "\n/etc/group 파일" >> total_result.txt
cat /etc/group >> total_result.txt

echo -e "\nsu 제한 설정" >> total_result.txt
cat /etc/pam.d/su | grep -v "#" | sed '/^$/d' >> total_result.txt

echo -e "\n계정 접속 현황" >> total_result.txt
lastlog >> total_result.txt

echo -e "\n[Session Timeout]" >> total_result.txt
cat /etc/ssh/sshd_config | grep -v "#" | grep ClientAliveInterval >> total_result.txt
echo -e "\n"
cat /etc/profile | grep TMOUT >> total_result.txt

echo -e "\n[권한 확인]" >> total_result.txt
echo "su 명령 권한 확인" >> total_result.txt
ls -al /bin/su >> total_result.txt
echo -e "\npasswd 권한 확인" >> total_result.txt
ls -al /etc/passwd >> total_result.txt
echo -e "\nshadow 권한 확인" >> total_result.txt
ls -al /etc/shadow >> total_result.txt
echo -e "\nhosts 권한 확인" >> total_result.txt
ls -al /etc/hosts >> total_result.txt
echo -e "\ninetd.conf 권한 확인" >> total_result.txt
ls -al /etc/inetd.conf >> total_result.txt
echo -e "\nxinetd.conf 권한 확인" >> total_result.txt
ls -al /etc/xinetd.conf >> total_result.txt
echo -e "\nsyslog.conf 권한 확인" >> total_result.txt
ls -al /etc/syslog.conf >> total_result.txt
echo -e "\nrsyslog.conf 권한 확인" >> total_result.txt
ls -al /etc/rsyslog.conf >> total_result.txt
echo -e "\nservices 권한 확인" >> total_result.txt
ls -al /etc/services >> total_result.txt
echo -e "\nSUID, SGID, Sticky bit 확인" >> total_result.txt
ls -al /sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd >> total_result.txt
echo -e "\n사용자 환경변수 파일 확인" >> total_result.txt
ls -aRl /home | egrep -w '.bashrc|.profile|.kshrc|.cshrc|.bash_profile|.login|.exrc|.netrc' >> total_result.txt
echo -e "\nhosts.equiv 권한 확인" >> total_result.txt
ls -al /etc/hosts.equiv >> total_result.txt
echo -e "\n.rhosts 권한 확인" >> total_result.txt
ls -aRl /home | egrep -w '.rhosts'
echo -e "\n.hosts.lpd 권한 확인" >> total_result.txt
ls -al /etc/hosts.lpd >> total_result.txt
echo -e "\numask 권한 확인" >> total_result.txt
umask >> total_result.txt
echo -e "\n사용자 홈 디렉터리 권한 확인" >> total_result.txt
ls -al /home >> total_result.txt
echo -e "\nexports 파일 권한 확인" >> total_result.txt
ls -al /etc/exports >> total_result.txt

echo -e "\n[crontab 관련 설정]" >> total_result.txt
echo "cron.deny 권한 및 설정 확인" >> total_result.txt
ls -al /etc/cron.deny >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/cron.deny >> total_result.txt
echo -e "\ncron.allow 권한 및 설정 확인" >> total_result.txt
ls -al /etc/cron.allow >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/cron.allow >> total_result.txt

echo -e "\n[서버 접근 제어 설정]" >> total_result.txt
ls -al /etc/hosts.deny >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/hosts.deny | grep -v "#" >> total_result.txt
echo -e "\n" >> total_result.txt
ls -al /etc/hosts.allow >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/hosts.allow | grep -v "#" >> total_result.txt
echo -e "\n" >> total_result.txt
iptables -L >> total_result.txt

echo -e "\n[프로세스 확인]" >> total_result.txt
ps -ef >> total_result.txt

echo -e "\n[SMTP 서비스 확인]" >> total_result.txt
echo "- SENDMAIL" >> total_result.txt
rpm -qa sendmail >> total_result.txt
echo -e "\n" >> total_result.txt
dpkg -l | grep "sendmail" >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/mail/sendmail.cf  | grep '$#error $@ 5.7.1 $: "550 Relaying denied"' >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/mail/sendmail.cf | grep -v "#" | grep PrivacyOptions >> total_result.txt

echo -e "\n- POSTFIX" >> total_result.txt
rpm -qa postfix >> total_result.txt
echo -e "\n" >> total_result.txt
dpkg -l | grep "postfix" >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/postfix/main.cf | grep "mynetworks =" >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/postfix/main.cf | grep -i disable_vrfy_command >> total_result.txt

echo -e "\n[DNS 서비스 확인]" >> total_result.txt
cat /etc/bind/named.conf >> total_result.txt

echo -e "\n[Apache 서비스 확인]" >> total_result.txt
echo "- RHEL, CentOS, Amazon Linux" >> total_result.txt
cat /etc/httpd/conf/httpd.conf | grep -v "#" | sed '/^$/d' >> total_result.txt

echo -e "\n- Debian, Ubuntu" >> total_result.txt
cat /etc/apache2/apache2.conf | grep -v "#" | sed '/^$/d' >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/apache2/sites-available/000-default.conf | grep -v "#" | sed '/^$/d'>> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/apache2/conf-enabled/security.conf | grep -v "#" >> total_result.txt

echo -e "\n[FTP 서비스 설정]" >> total_result.txt
echo "- RHEL, CentOS, Amazon Linux" >> total_result.txt
cat /etc/vsftpd/vsftpd.conf | grep -v "#" | sed '/^$/d' >> total_result.txt
echo -e "\n" >> total_result.txt
ls -al /etc/vsftpd/ftpusers >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/vsftpd/ftpusers >> total_result.txt
echo -e "\n" >> total_result.txt
ls -al /etc/vsftpd/user_list >> total_result.txt
cat /etc/vsftpd/user_list >> total_result.txt

echo -e "\n- Debian, Ubuntu" >> total_result.txt
cat /etc/vsftpd.conf | grep -v "#" | sed '/^$/d' >> total_result.txt
echo -e "\n" >> total_result.txt
ls -al /etc/ftpusers >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/ftpusers >> total_result.txt

echo -e "\n[at 관련 설정]" >> total_result.txt
echo "at.deny 권한 및 설정 확인" >> total_result.txt
ls -al /etc/at.deny >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/at.deny >> total_result.txt
echo -e "\nat.allow 권한 및 설정 확인" >> total_result.txt
ls -al /etc/at.allow >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/at.allow >> total_result.txt

echo -e "\n[SNMP 관련 설정]" >> total_result.txt
cat /etc/snmp/snmpd.conf | grep -v "#" >> total_result.txt

echo -e "\n[배너 관련 설정]" >> total_result.txt
cat /etc/issue.net >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/motd >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/update-motd.d/00-header >> total_result.txt

echo -e "\n[보안패치 정보]" >> total_result.txt
cat /etc/*release* >> total_result.txt
echo -e "\n" >> total_result.txt
uname -r >> total_result.txt
echo -e "\n" >> total_result.txt
rpm -qa openssl >> total_result.txt
echo -e "\n" >> total_result.txt
rpm -qa openssh >> total_result.txt
echo -e "\n" >> total_result.txt
apt list --installed | grep ^openssl >> total_result.txt
echo -e "\n" >> total_result.txt
apt list --installed | grep openssh-server >> total_result.txt

echo -e "\n[로그 설정 정보]" >> total_result.txt
cat /etc/rsyslog.conf | grep -v "#" >> total_result.txt
echo -e "\n" >> total_result.txt
cat /etc/rsyslog.d/50-default.conf | grep -v "#" >> total_result.txt

#--START(JSON 형식 출력)
json_change_finish
}

#--START(JSON 형식 출력)
function json_change_start(){
unset result a_result a_result1 a_result2 a_result3 a_result4 b_result b_result1 b_result2 b_result3 b_result11 b_result12 b_result13 b_result21 b_result22 c_result1 c_result2 c_result3 c_result4

chkResult=$(echo "$chkResult" |
sed -E ':a;N;$!ba;s/\r{0,1}\\/\\\\/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\"/\\"/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\t/\\t/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\n/\\n/g')

scriptResult=$(echo "$scriptResult" |
sed -E ':a;N;$!ba;s/\r{0,1}\\/\\\\/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\"/\\"/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\t/\\t/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\n/\\n/g')

echo "{	\"company\":\"$COMPANY_CODE\",\"companyName\":\"$COMPANY_NAME\",\"assetClass\":\"$ASSET\",\"targetName\":\"$HOSTNAME\",\"osType\":\"$OSTYPE\",\"osVer\":\"$OS_VERSION\",\"report\":[{\"itemCode\":\"$CODE\",\"actTime\":\"$MEASURES\",\"chkResult\":\"$chkResult\",\"scriptResult\":\"$scriptResult\",\"chkStatus\":\"$chkStatus\"}," > ${COMPANY_CODE}_Linux_Report_${HOSTNAME}_${DATE}.json
}

function json_change_m(){
unset result a_result a_result1 a_result2 a_result3 a_result4 b_result b_result1 b_result2 b_result3 b_result11 b_result12 b_result13 b_result21 b_result22 c_result1 c_result2 c_result3 c_result4

chkResult=$(echo "$chkResult" |
sed -E ':a;N;$!ba;s/\r{0,1}\\/\\\\/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\"/\\"/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\t/\\t/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\n/\\n/g')

scriptResult=$(echo "$scriptResult" |
sed -E ':a;N;$!ba;s/\r{0,1}\\/\\\\/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\"/\\"/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\t/\\t/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\n/\\n/g')

echo "{\"itemCode\":\"$CODE\",\"actTime\":\"$MEASURES\",\"chkResult\":\"$chkResult\",\"scriptResult\":\"$scriptResult\",\"chkStatus\":\"$chkStatus\"}," >> ${COMPANY_CODE}_Linux_Report_${HOSTNAME}_${DATE}.json
}

function json_change_finish(){
unset result a_result a_result1 a_result2 a_result3 a_result4 b_result b_result1 b_result2 b_result3 b_result11 b_result12 b_result13 b_result21 b_result22 c_result1 c_result2 c_result3 c_result4

chkResult=$(echo "$chkResult" |
sed -E ':a;N;$!ba;s/\r{0,1}\\/\\\\/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\"/\\"/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\t/\\t/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\n/\\n/g')

scriptResult=$(echo "$scriptResult" |
sed -E ':a;N;$!ba;s/\r{0,1}\\/\\\\/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\"/\\"/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\t/\\t/g'|
sed -E ':a;N;$!ba;s/\r{0,1}\n/\\n/g')

echo "{\"itemCode\":\"$CODE\",\"actTime\":\"$MEASURES\",\"chkResult\":\"$chkResult\",\"scriptResult\":\"$scriptResult\",\"chkStatus\":\"$chkStatus\"}]}" >> ${COMPANY_CODE}_Linux_Report_${HOSTNAME}_${DATE}.json
}

#--START(메인함수 실행)
main
tar zcf ${COMPANY_CODE}_Linux_Report_${HOSTNAME}_${DATE}.tar.gz *.json *.txt
