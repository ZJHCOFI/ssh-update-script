#!/bin/bash
#===============================
# 适配系统：Centos 7
# 功能：升级OpenSSH和OpenSSL版本
# System Request:Centos 7
# Function：Upgrade OpenSSH and OpenSSL versions
#===============================
# 脚本更新时间（Script update time）：2024.02.19 19:00
# 脚本作者：ZJHCOFI
# Edit by ZJHCOFI
# 博客（Blog）：http://zjhcofi.com
# Github：https://github.com/zjhcofi
# 开源协议（License）：BSD 3-Clause “New” or “Revised” License
# 后续更新或漏洞修补通告页面（Subsequent updates and bug fixes notification page）：https://github.com/ZJHCOFI/ssh_update_script
# 参考文献（References）：https://github.com/wulabing
#=====更新日志（Changelog）=====
# 2023.09.03 13:49
# 第一个版本发布 First Edition Release
# 2024.02.19 19:00
# 1、修改了OpenSSL的下载机制
#===============================

# 字体颜色配置
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
# RedBG="\033[41;37m"
OK="${Green}[OK]${Font}"
CHOOSE="${Yellow}[CHOOSE]${Font}"
INFO="${Yellow}[INFO]${Font}"
ERROR="${Red}[ERROR]${Font}"

# 全局变量
openssh_version=""
openssl_version=""
update_choose_num=""
system_version=""
date_time=$(date "+%Y%m%d%H%M")
input_string=$1


function print_ok() {
	echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
	echo -e "${ERROR} ${Red} $1 ${Font}"
}

judge() {
	if [[ 0 -eq $? ]]; then
		print_ok "$1\n完成Done"
		sleep 1
	else
		print_error "$1\n失败Failed"
		exit 1
	fi
}

judge_download_ssh() {
	if [[ 0 -eq $? ]]; then
		print_ok "$1\n完成Done"
		sleep 1
		openssh_check
	else
		print_error "$1\n失败Failed"
		rm -f ${path_way}/${openssh_version}
		exit 1
	fi
}

judge_download_ssl() {
	if [[ 0 -eq $? ]]; then
		print_ok "$1\n完成Done"
		sleep 1
		openssl_check
	else
		print_error "$1\n失败Failed"
		rm -f ${path_way}/${openssl_version}
		exit 1
	fi
}

# 获取脚本当前路径
function path_way_check() {
	path_way=$(readlink -f "$(dirname "$0")")
	if [ "$path_way" != "${path_way//[\' ]/}" ]; then 
		print_error "当前的绝对路径有空格，请将脚本移至无空格的绝对路径下。The current absolute path has spaces. Please move the script to an absolute path without spaces."
		exit 1
	fi
}

# 检测是否root权限
function is_root() {
	if [[ 0 == "$UID" ]]; then
		print_ok "当前用户是 root 用户，开始安装流程。The current user is root, starting the installation process."
	else
		print_error "当前用户不是 root 用户，请切换到 root 用户后重新执行脚本。The current user is not root. Please switch to root and execute the script again."
		exit 1
	fi
}

# 选择升级内容
function update_choose() {
	echo -e "
${CHOOSE}${Blue}选择升级类型(Select Upgrade Type)：${Font}
=====升级操作 Upgrade operation=====
${Yellow}1.${Font} 升级OpenSSH和OpenSSL(Upgrade OpenSSH and OpenSSL)
${Yellow}2.${Font} 升级OpenSSH(Upgrade OpenSSH)
${Yellow}3.${Font} 升级OpenSSL(Upgrade OpenSSL)
=====其他操作 Other operations=====
${Yellow}4.${Font} 升级后清理(不包含备份文件)(Cleanup after upgrade, but does not include backup files.)
${Yellow}5.${Font} 执行修改ssh配置文件后的升级步骤(Perform the upgrade steps after modifying the SSH profile.)
${Yellow}6.${Font} 回退至以前的版本(Fallback to previous version.)
${Blue}请输入您的选择(Please enter your selection)：${Font}"
	read -r update_choose_num
	case ${update_choose_num} in
	1)
		update_choose_num="1"
		;;
	2)
		echo -e "\n${CHOOSE}${Blue}单独升级OpenSSH很有可能会出错，是否继续？(y/n)\nUpgrading OpenSSH separately is highly likely to result in errors. Do you want to continue? (y/n)：${Font}"
		read -r second_check
		case ${second_check} in
		[yY][eE][sS] | [yY])
			update_choose_num="2"
			;;
		*)
			update_choose
			;;
		esac
		;;
	3)
		update_choose_num="3"
		;;
	4)
		clear
		exit 1
		;;
	5)
		openssh_restart
		exit 1
		;;
	6)
		print_error "该功能未完成-.-  This function is not completed-.-"
		exit 1
		;;
	*) 
		print_error "输入有误！Input error!"
		update_choose
		;;
	esac
}

# 检测系统版本
function system_check() {

	source '/etc/os-release'

	if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
		print_ok "当前系统为 Centos ${VERSION_ID} ${VERSION}。The current system is Centos ${VERSION_ID} ${VERSION}"
		system_version="centos7"
		INS="yum install -y"
		RMS="yum remove -y"
		${INS} curl
		judge "安装 curl。Install curl"
		${INS} wget
		judge "安装 wget。Install wget"
		
		case ${update_choose_num} in
		1)
			openssh_check
			;;
		2)
			openssh_check
			;;
		3)
			openssl_check
			;;
		esac
	else
		print_error "当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内。The current system is ${ID} ${VERSION_ID} ,not in the list of supported systems."
		exit 1
	fi
}

# openssh版本包检测
function openssh_check() {
	
	openssh_file_num=$(ls ${path_way} | grep openssh-*p*.tar.gz | wc -l)

	if [[ ${openssh_file_num} == "0" ]];then
		print_error "脚本目录下没有OpenSSH版本包。There is no OpenSSH package in the script directory."
		openssh_version=""
		openssh_download
	elif [[ ${openssh_file_num} != "1" ]];then 
		print_error "脚本目录下只能存在一个OpenSSH版本包。Only one OpenSSH package can exist in the script directory."
		openssh_version=""
		openssh_download
	else
		openssh_version=$(ls ${path_way} | grep openssh-*p*.tar.gz)
		print_ok "检测到脚本目录下的OpenSSH版本包为 ${Font}${Red}${openssh_version}${Blue}，继续执行安装程序。Detected that the OpenSSH package in the script directory is ${Font}${Red}${openssh_version}${Blue},continue installation."
		
		case ${update_choose_num} in
		1)
			openssl_check
			;;
		2)
			telnet_install
			dependent_install
			openssh_update
			;;
		*)
			print_error "有Bug！Something wrong!"
			exit 1
			;;
		esac
	fi
}

# openssl版本包检测
function openssl_check() {

	openssl_file_num=$(ls ${path_way} | grep openssl-*.tar.gz | wc -l)

	if [[ ${openssl_file_num} == "0" ]];then
		print_error "脚本目录下没有OpenSSL版本包。There is no OpenSSL package in the script directory."
		openssl_version=""
		openssl_download
	elif [[ ${openssl_file_num} != "1" ]];then
		print_error "脚本目录下只能存在一个OpenSSL版本包。Only one OpenSSL package can exist in the script directory."
		openssl_version=""
		openssl_download
	else
		openssl_version=$(ls ${path_way} | grep openssl-*.tar.gz)
		if [[ ${system_version} == "centos7" && $(echo ${openssl_version} | grep openssl-1.*.*tar.gz) == "" ]]; then
			echo -e "\n${ERROR}检测到脚本目录下的OpenSSL版本包为 ${Font}${Red}${openssl_version}${Blue}，可能不适用于当前系统，建议更换为openssl-1.x.xx的版本，下载地址：${Font}${Yellow}https://www.openssl.org/source/old/1.1.1/index.html ${Font}。Detected that the OpenSSL package in the script directory is ${Font}${Red}${openssl_version}${Blue},may not be applicable to the current system,it is recommended to replace it with the version of openssl-1.x.xx,download url:${Font}${Yellow}https://www.openssl.org/source/old/1.1.1/index.html ${Font}\n"
			exit 1
		fi
		print_ok "检测到脚本目录下的OpenSSL版本包为 ${Font}${Red}${openssl_version}${Blue}，继续执行安装程序。Detected that the OpenSSL package in the script directory is ${Font}${Red}${openssl_version}${Blue},continue installation."
		
		case ${update_choose_num} in
		1)
			telnet_install
			dependent_install
			openssl_update
			openssh_update
			;;
		3)
			telnet_install
			dependent_install
			openssl_update
			;;
		*)
			print_error "有Bug！Something wrong!"
			exit 1
			;;
		esac
	fi
}

# 网络检测openssh版本包
function openssh_download() {

	if [[ ${openssh_version} == "" ]];then
	
		openssh_version=$(curl https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/ | grep "tar.gz" | grep -v "asc" | grep -v "md5" | grep -v "sig" | cut -d ">" -f 2 | cut -d "<" -f 1 | tail -n 1)
		
		if [[ ${openssh_version} == "" ]];then
			print_error "获取OpenSSH版本包列表失败。Fail to obtain the list of OpenSSH packages."
			echo -e "\n${INFO}${Blue}请自行前往 ${Font}${Yellow}https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/ ${Font}${Blue}下载您需要升级的OpenSSH版本包，放在脚本同目录下(注意：只能是${Font}${Yellow}p1.tar.gz${Font}${Blue}或${Font}${Yellow}p2.tar.gz${Font}${Blue}结尾的版本包)。Please download the OpenSSH version you need to upgrade from the ${Font}${Yellow}https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${Font}${Blue},place it in the same directory as the script.Attention: Only versions ending in ${Font}${Yellow}p1.tar.gz${Font}${Blue} or ${Font}${Yellow}p2.tar.gz${Font}${Blue} can be used.${Font}\n"
			exit 1
		else
			print_ok "获取OpenSSH版本包列表成功。Obtain the list of OpenSSH packages success."
		fi
		
		echo -e "\n${CHOOSE}${Blue}最新的OpenSSH版本包为 ${Font}${Red}${openssh_version}${Font}${Blue}，是否升级到此版本？(y/n)\nThe latest OpenSSH version is ${Font}${Red}${openssh_version}${Font}${Blue},do you want to upgrade to this version? (y/n)：${Font}"
		read -r download_openssh
		case ${download_openssh} in
		[yY][eE][sS] | [yY])
			wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${openssh_version}
			judge_download_ssh "下载OpenSSH版本包。Download OpenSSH package."
			;;
		[nN][oO] | [nN])
			echo -e "\n${INFO}${Blue}请自行前往 ${Font}${Yellow}https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/ ${Font}${Blue}下载您需要升级的OpenSSH版本包，放在脚本同目录下(注意：只能是${Font}${Yellow}p1.tar.gz${Font}${Blue}或${Font}${Yellow}p2.tar.gz${Font}${Blue}结尾的版本包)。Please download the OpenSSH version you need to upgrade from the ${Font}${Yellow}https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${Font}${Blue},place it in the same directory as the script。Attention: Only versions ending in ${Font}${Yellow}p1.tar.gz${Font}${Blue} or ${Font}${Yellow}p2.tar.gz${Font}${Blue} can be used.${Font}\n"
			exit 1
			;;
		*)
			print_error "输入有误！Input error!"
			main
			;;
		esac
	fi
}

# 网络检测openssl版本包
function openssl_download() {

	if [[ ${openssl_version} == "" ]];then

		if [[ ${system_version} == "centos7" ]]; then
			echo -e "\n${Blue}请自行前往 ${Font}${Yellow}https://www.openssl.org/source/old/1.1.1/index.html ${Font}${Blue}下载您需要升级的OpenSSL版本包，建议下载openssl-1.x.xx的版本，放在脚本同目录下。Please download the OpenSSL version you need to upgrade from the ${Font}${Yellow}https://www.openssl.org/source/old/1.1.1/index.html ${Font}${Blue},suggest downloading the version of openssl-1.x.xx,place it in the same directory as the script.${Font}\n"
			exit 1
		fi

		openssl_version=($(curl https://www.openssl.org/source/ | grep openssl-*.*.tar.gz | cut -d '"' -f 2 | cut -d '"' -f 1))
		
		if [[ -z "${openssl_version[*]}" ]]; then
			print_error "获取OpenSSL版本包列表失败。Fail to obtain the list of OpenSSL packages."
			echo -e "\n${INFO}${Blue}请自行前往 ${Font}${Yellow}https://www.openssl.org/source/ ${Font}${Blue}下载您需要升级的OpenSSL版本包，放在脚本同目录下。Please download the OpenSSL version you need to upgrade from the ${Font}${Yellow}https://www.openssl.org/source/${Font}${Blue},place it in the same directory as the script.${Font}\n"
			exit 1
		else
			print_ok "获取OpenSSL版本包列表成功。Obtain the list of OpenSSL packages success."
		fi
		
		echo -e "\n${Blue}最新的OpenSSL版本包如下：${Font}\n${Blue}The latest OpenSSL version is as follows：${Font}" 
		# 遍历并输出版本包
		openssl_version_num=1
		openssl_version_num_list=()
		for var in "${openssl_version[@]}"
		do	
			echo -e "${Yellow}${openssl_version_num}.${Font} $var"
			openssl_version_num_list+=(${openssl_version_num})
			openssl_version_num=$(expr ${openssl_version_num} + 1)
		done
		# 下载版本包
		echo -e "\n${CHOOSE}${Blue}请选择需要升级的OpenSSL版本，或者输入\"N\"自行下载：${Font}\n${Blue}Please select the OpenSSL version that needs to be upgraded,or enter \"N\" to download it by yourself：${Font}"
		read -r download_openssl
		if echo "${openssl_version_num_list[@]}" | grep -w "${download_openssl}" &>/dev/null; then
			a=$(expr ${download_openssl} - 1)
			openssl_version=${openssl_version[${a}]}
			wget https://www.openssl.org/source/${openssl_version} --no-check-certificate
			judge_download_ssl "下载OpenSSL版本包。Download OpenSSL package."
		elif [[ ${download_openssl} == "N" || ${download_openssl} == "n" ]]; then
			echo -e "\n${INFO}${Blue}请自行前往 ${Font}${Yellow}https://www.openssl.org/source/ ${Font}${Blue}下载您需要升级的OpenSSL版本包，放在脚本同目录下。Please download the OpenSSL version you need to upgrade from the ${Font}${Yellow}https://www.openssl.org/source/${Font}${Blue},place it in the same directory as the script.${Font}\n"
			exit 1
		else
			print_error "输入有误！Input error!"
			main
		fi
	fi
}

# ssh升级依赖安装
function dependent_install() {

	${INS} tar
	judge "安装 tar。Install tar"

	${INS} pam* zlib*
	judge "安装依赖：pam* zlib*。Install pam* zlib*"

	${INS} gcc gcc-c++ glibc make autoconf openssl openssl-devel pcre-devel
	judge "安装依赖：gcc gcc-c++ glibc make autoconf openssl openssl-devel pcre-devel。Install gcc gcc-c++ glibc make autoconf openssl openssl-devel pcre-devel"
}

# 安装telnet服务端/客户端并启用
function telnet_install() {

	${INS} net-tools
	judge "安装 net-tools。Install net-tools"
	
	${INS} xinetd telnet-server telnet
	judge "安装telnet相关组件：xinetd telnet-server telnet。Install telnet: xinetd telnet-server telnet"

	cp /etc/securetty /etc/securetty_bak
	sed -i '/pts/d' /etc/securetty
	echo -e "pts/0\npts/1\npts/2\npts/3" >> /etc/securetty
	telnet_config=$(grep "pts" /etc/securetty | wc -l)
	if [[ ${telnet_config} != "4" ]];then
		print_error "Telnet权限配置失败。Telnet permission configuration failed."
		exit 1
	fi

	systemctl enable xinetd
	systemctl enable telnet.socket
	systemctl restart telnet.socket
	systemctl restart xinetd

	sleep 3

	telnet_port=$(netstat -lntp | grep 23 | grep systemd | awk '{print $4}' | sed 's/://g')
	if [[ ${telnet_port} == "23" ]];then
		print_ok "Telnet启动成功。Telnet started successfully."
	else
		print_error "Telnet启动失败。Telnet startup failed."
		exit 1
	fi
}

# OpenSSL升级操作
function openssl_update() {

	# 解压openssl
	openssl_version=$(echo ${openssl_version} | sed "s/.tar.gz//g")
	cd ${path_way}
	rm -rf ${openssl_version}
	tar xfz ${openssl_version}.tar.gz
	judge "解压OpenSSL版本包。Unzip OpenSSL package."
	cd ${openssl_version}

	# 备份旧版本openssl
	ls -all /usr/bin/openssl
	mv /usr/bin/openssl /usr/bin/openssl_bak_${date_time}
	judge "备份/usr/bin/openssl到/usr/bin/openssl_bak_${date_time}。Backup /usr/bin/openssl to /usr/bin/openssl_bak_${date_time}"
	ls -all /usr/include/openssl
	mv /usr/include/openssl /usr/include/openssl_bak_${date_time}
	judge "备份/usr/include/openssl到/usr/include/openssl_bak_${date_time}。Backup /usr/include/openssl to /usr/include/openssl_bak_${date_time}"

	# 编译安装openssl
	cd ${path_way}/${openssl_version} && ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared && make && make install
	judge "编译安装OpenSSL。make && make install OpenSSL"

	# 制作软链接
	ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl
	judge "生成软连接：/usr/bin/openssl -> /usr/local/ssl/bin/openssl。Making soft link：/usr/bin/openssl -> /usr/local/ssl/bin/openssl"
	ln -s /usr/local/ssl/include/openssl /usr/include/openssl
	judge "生成软连接：/usr/include/openssl -> /usr/local/ssl/include/openssl。Making soft link：/usr/include/openssl -> /usr/local/ssl/include/openssl"
	ls -all /usr/bin/openssl
	ls -all /usr/include/openssl -ld

	# 加载新配置
	rm -rf /usr/lib64/libssl.so.1.1
	rm -rf /usr/lib64/libcrypto.so.1.1
	sed -i '/\/usr\/local\/ssl\/lib/d' /etc/ld.so.conf
	judge "加载新配置1：sed -i '/\/usr\/local\/ssl\/lib/d' /etc/ld.so.conf。Load new config 1:sed -i '/\/usr\/local\/ssl\/lib/d' /etc/ld.so.conf"
	echo "/usr/local/ssl/lib" >> /etc/ld.so.conf
	judge "加载新配置2：echo \"/usr/local/ssl/lib\" >> /etc/ld.so.conf。Load new config 2:echo \"/usr/local/ssl/lib\" >> /etc/ld.so.conf"
	ln -s /usr/local/ssl/lib/libssl.so.1.1 /usr/lib64/libssl.so.1.1
	judge "加载新配置3：ln -s /usr/local/ssl/lib/libssl.so.1.1 /usr/lib64/libssl.so.1.1。Load new config 3:ln -s /usr/local/ssl/lib/libssl.so.1.1 /usr/lib64/libssl.so.1.1"
	ln -s /usr/local/ssl/lib/libcrypto.so.1.1 /usr/lib64/libcrypto.so.1.1
	judge "加载新配置4：ln -s /usr/local/ssl/lib/libcrypto.so.1.1 /usr/lib64/libcrypto.so.1.1。Load new config 4:ln -s /usr/local/ssl/lib/libcrypto.so.1.1 /usr/lib64/libcrypto.so.1.1"
	export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin
	judge "加载新配置5：export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin。Load new config 5:export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin"
	/sbin/ldconfig
	judge "加载新配置6：/sbin/ldconfig。Load new config 6:/sbin/ldconfig"
	ldconfig
	judge "加载新配置7：ldconfig。Load new config 7:ldconfig"

	# 查看版本
	openssl version
	sleep 10
}

# OpenSSH升级操作
function openssh_update() {

	# 解压openssh
	openssh_version=$(echo ${openssh_version} | sed "s/.tar.gz//g")
	cd ${path_way}
	rm -rf ${openssh_version}
	tar xfz ${openssh_version}.tar.gz
	judge "解压OpenSSH版本包。Unzip OpenSSH package."
	cd ${openssh_version}
	echo ${openssh_version} > ${path_way}/.ssh_version.tmp

	# 备份openssh
	cp -rp /etc/ssh/ /etc/ssh_bak_${date_time}/
	judge "备份/etc/ssh/到/etc/ssh_bak_${date_time}/。Backup /etc/ssh/ to /etc/ssh_bak_${date_time}/"
	ls -all /etc/ssh_bak_${date_time}/
	rm -rf /etc/ssh/*
	judge "删除/etc/ssh/*。Delete /etc/ssh/*"

	# 编译安装openssh
	cd ${path_way}/${openssh_version} && ./configure --prefix=/usr/ --sysconfdir=/etc/ssh --with-openssl-includes=/usr/local/ssl/lib --with-ssl-dir=/usr/local/ssl/lib --with-zlib --with-md5-passwords --with-pam && make && make install
	judge "编译安装OpenSSH。make && make install OpenSSH"

	# 恢复配置文件
	print_ok "=========请确认OpenSSH配置文件参数===========\n=========Please confirm the OpenSSH profile parameters==========="
	cat /etc/ssh/sshd_config
	print_ok "=========请确认上方OpenSSH配置文件参数===========\n=========Please confirm the OpenSSH profile parameters above==========="
	echo -e "\n${CHOOSE}${Red}【重要】${Font}${Blue}上方OpenSSH的${Font}${Red}新的${Font}${Blue}配置文件的参数是否正确？(y/n) 

★如不正确，请手动完成选择以下任一事项：${Font}${Yellow}
1、修改OpenSSH配置文件 ${Font}${Red}/etc/ssh/sshd_config${Font}${Yellow}
2、将旧的OpenSSH配置文件 ${Font}${Red}/etc/ssh_bak_${date_time}/sshd_config${Font}${Yellow} 和新的配置文件 ${Font}${Red}/etc/ssh/sshd_config${Font}${Yellow} 进行对比，再做相对应的修改${Font}${Blue}

★常见问题解决：${Font}${Yellow}
1、ssh重启后报错\"could not get shadow information for root\"：修改 /etc/ssh/sshd_config 中的 #UsePAM no 为 UsePAM yes
2、需要root登录：修改 /etc/ssh/sshd_config 中的 #PermitRootLogin prohibit-password 为 PermitRootLogin yes${Font}${Blue}

★修改完成后，请用此命令再执行此脚本： ${Font}${Red}bash ssh_update_onekey.sh ssh${Font}

${Red}[Attention]${Font}${Blue}Are the parameters of the ${Font}${Red}new profile${Font}${Blue} for OpenSSH above correct? (y/n)：

☆If not correct,please manually complete the selection of any of the following:${Font}${Yellow}
1.Modifying OpenSSH profile ${Font}${Red}/etc/ssh/sshd_config${Font}${Yellow}
2.Compare the old OpenSSH profile ${Font}${Red}/etc/ssh_bak_${date_time}/sshd_config${Font}${Yellow} with the new one ${Font}${Red}/etc/ssh/sshd_config${Font}${Yellow},and make corresponding modifications again.${Font}${Blue}

☆Common problem-solving methods:${Font}${Yellow}
1.Login error after SSH restart \"could not get shadow information for root\": Modify \"#UsePAM no\" in the /etc/ssh/sshd_config to \"UsePAM yes\"
2.Require root login:Modify \"#PermitRootLogin prohibit-password\" in the /etc/ssh/sshd_config to \"PermitRootLogin yes\"${Font}${Blue}

☆After completing the modifications, please use this command to execute this script again: ${Font}${Red}bash ssh_update_onekey.sh ssh${Font}"
	read -r change_check
	case ${change_check} in
	[yY][eE][sS] | [yY])
		openssh_restart
		;;
	*)
		exit 1
		;;
	esac
}

# openssh配置更新及重启
function openssh_restart() {

	openssh_version=$(cat ${path_way}/.ssh_version.tmp)
	cd ${path_way}/${openssh_version}
	cp -a contrib/redhat/sshd.init /etc/init.d/sshd
	judge "加载新配置1：cp -a contrib/redhat/sshd.init /etc/init.d/sshd。Load new config 1:cp -a contrib/redhat/sshd.init /etc/init.d/sshd"
	cp -a contrib/redhat/sshd.pam /etc/pam.d/sshd.pam
	judge "加载新配置2：cp -a contrib/redhat/sshd.pam /etc/pam.d/sshd.pam。Load new config 2:cp -a contrib/redhat/sshd.pam /etc/pam.d/sshd.pam"
	chmod +x /etc/init.d/sshd
	judge "加载新配置3：chmod +x /etc/init.d/sshd。Load new config 3:chmod +x /etc/init.d/sshd"

	if [ -f "/usr/lib/systemd/system/sshd.service" ];then
		mv /usr/lib/systemd/system/sshd.service ${path_way}
	fi
	chkconfig --add sshd
	chkconfig sshd on
	systemctl enable sshd
	systemctl daemon-reload
	judge "设置ssh开启自启。Set SSH startup and self start."
	
	ssh -V

	echo -e "\n${CHOOSE}${Blue}升级完成，请检查版本号是否正确，正确则重启OpenSSH！(y/n)\nUpgrade completed, please check if the version number is correct. If it is correct, restart OpenSSH! (y/n)：${Font}"
	read -r vesion_check
	case ${vesion_check} in
	[yY][eE][sS] | [yY])
		echo -e "
${INFO}${Yellow}升级后注意事项：
1、如果重启后无法正常登录ssh，可使用此命令进行登录：${Font}${Red}telnet ip${Font}${Yellow} 
2、确认功能正常后，请使用本命令进行清理(不包含备份文件)：${Font}${Red}bash ssh_update_onekey.sh clear${Font}${Yellow}
Precautions after upgrading
1、If you cannot log in to SSH normally after restarting, you can use this command to log in: ${Font}${Red}telnet ip${Font}${Yellow}
2、After confirming that the function is normal, please use this command to cleanup after upgrade, but does not include backup files: ${Font}${Red}bash ssh_update_onekey.sh clear${Font}"
		systemctl restart sshd
		judge "重启ssh。restart ssh."
		systemctl status sshd
		;;
	*)
		print_error "升级已停止，请进行相关检查。Upgrade stopped, please perform relevant checks."
		exit 1
		;;
	esac
}

# 升级后清理
function clear() {

	cd ${path_way}/
	rm -rf openssl-1.*.*
	rm -rf openssh-*p*
	rm -f sshd.service
	echo -e "
${CHOOSE}${Blue}Telnet选项(Telnet Options)：${Font}
${Yellow}1.${Font} 还原权限并卸载Telnet(Restore permissions from Telnet and uninstall Telnet)
${Yellow}2.${Font} 还原权限并关闭Telnet(Restore permissions from Telnet and close Telnet)
${Yellow}3.${Font} 只还原权限(Only restore permissions from Telnet)
${Yellow}4.${Font} 不做任何操作(Do nothing)
${Blue}请输入您的选择(Please enter your selection)：${Font}"
	read -r telnet_choose_num
	case ${telnet_choose_num} in
	1)
		cp /etc/securetty_bak /etc/securetty_bak${date_time}
		mv /etc/securetty_bak /etc/securetty
		${RMS} xinetd telnet-server
		judge "卸载telnet相关组件：xinetd telnet-server。Remove telnet: xinetd telnet-server"
		;;
	2)
		cp /etc/securetty_bak /etc/securetty_bak${date_time}
		mv /etc/securetty_bak /etc/securetty
		systemctl stop telnet.socket
		systemctl stop xinetd
		judge "关闭telnet相关组件：xinetd telnet-server。Shutdown telnet: xinetd telnet-server"
		;;
	3)
		cp /etc/securetty_bak /etc/securetty_bak${date_time}
		mv /etc/securetty_bak /etc/securetty
		systemctl restart telnet.socket
		systemctl restart xinetd
		judge "重启telnet相关组件：xinetd telnet-server。Shutdown telnet: xinetd telnet-server"
		;;
	4)
		exit 1
		;;
	*) 
		clear
		;;
	esac
}

# 主程序运行
function main() {
	if [[ ${input_string} == "ssh" ]];then
		path_way_check
		is_root
		openssh_restart
	elif [[ ${input_string} == "clear" ]];then
		path_way_check
		is_root
		clear
	else
		path_way_check
		is_root
		update_choose
		system_check
	fi
}

main
