#!/bin/bash

# Globals Declarations
VERSION=1.60
PATH=/sbin:/usr/sbin:$PATH
HOST=$(hostname)
XDATE=$(date +%Y%m%d-%H%M)
OFILE=sysinfo-snapshot-${VERSION}-$HOST-$XDATE.html
ZOFILE=SIS-results-$HOST-$XDATE.tar.gz
########################################################
########################################################
########################################################
# Datasets used by this script
########################################################
########################################################
########################################################
declare -a NativeCommands=(\
	'hostname'\
	'uptime'\
	'date'\
	'df -h'\
	'fdisk -l'\
	'free'\
	'mount'\
	'ifconfig -a'\
	'ip a s'\
	'ip m s'\
	'ip n s'\
	'arp -an'\
	'netstat -anp'\
	'sdpnetstat -anp'\
	'netstat -nlp'\
	'netstat -nr'\
	'netstat -i'\
	'route -n'\
	'sysctl -a'\
	'ulimit -a'\
	'uname -a'\
	'biosdecode'\
	'dmidecode'\
	'cat /boot/config-$(uname -r)'\
	'cat /etc/redhat-release'\
	'cat /etc/SuSE-release'\
	'cat /etc/issue'\
	'chkconfig --list | sort'\
	'lslk'\
	'lsmod'\
	'rpm -qa'\
	'modprobe sg'\
	'numactl --hardware'\
	'lspci'\
	'lspci -tv'\
	'lspci -s'\
	'lscpu'\
	'setpci -s 05.0 858.w'\
	'setpci -s 05.0 85c.w'\
	'service irqbalance status'\
	'env'\
	'dmidecode'\
	'dpkg -l'\
	'ls -la /etc/init.d/'\
	'ls -la /etc/rc1.d/'\
	'ls -la /etc/rc2.d/'\
	'ls -la /etc/rc3.d/'\
	'ls -la /etc/rc4.d/'\
	'ls -la /etc/rc5.d/'\
	'ls -la /home/'


)	
	#'lsof'\
	#'ps xfalw'\

declare -a SensitiveCommands=(\
	'iptables -t filter -nvL'\
	'iptables-save -t filter'\
	'iptables -t nat -nvL'\
	'iptables-save -t nat'\
	'iptables -t mangle -nvL'\
	'iptables-save -t mangles'\
)

declare -a InfiniBandHostCommands=(\
	'ibstat'\
	'ibstatus'\
	'ibv_devinfo'\
	'ibv_devinfo -v'\
	'sminfo'\
)

declare -a FabricScalingCommands=(
	'ibnetdiscover'\
	'ibnetdiscover -p'\
	'ibcheckerrors -nocolor'\
	'ibdiagnet'\
	'ibhosts'\
	'ibswitches'\
	'ibnodes'\
	'iblinkinfo'\
)

declare -a DriverCommands=(
	'ofed_info'\
	'ompi_info'\
)

declare -a FilesToGet=(
	'/boot/grub/grub.conf'
	'/boot/grub/grub.cfg'
	'/proc/version'\
	'/proc/modules'\
	'/proc/cpuinfo'\
	'/proc/mounts'\
	'/proc/buddyinfo'\
	'/proc/cmdline'\
	'/proc/crypto'\
	'/proc/devices'\
	'/proc/diskstats'\
	'/proc/dma'\
	'/proc/execdomains'\
	'/proc/filesystems'\
	'/proc/interrupts'\
	'/proc/interrupt'\
	'/sys/class/net/eth*/device/numa_node'\
	'/proc/iomem'\
	'/proc/ioports'\
	'/proc/loadavg'\
	'/proc/locks'\
	'/proc/mdstat'\
	'/proc/meminfo'\
	'/proc/misc'\
	'/proc/mtrr'\
	'/proc/partitions'\
	'/proc/stat'\
	'/proc/swaps'\
	'/proc/uptime'\
	'/proc/vmstat'\
	'/proc/zoneinfo'\
	'/proc/slabinfo'\
	'/proc/scsi/scsi'\
	'/etc/resolv.conf'\
	'/etc/hosts'\
	'/etc/hostname'\
	'/etc/hosts.allow'\
	'/etc/hosts.deny'\
	'/etc/network/interfaces'\
	'/sys/class/infiniband/*/board_id'\
	'/sys/class/infiniband/*/fw_ver'\
	'/sys/class/infiniband/*/hca_type'\
	'/sys/class/infiniband/*/hw_rev'\
	'/sys/class/infiniband/*/node_desc'\
	'/sys/class/infiniband/*/node_guid'\
	'/sys/class/infiniband/*/node_type'\
	'/sys/class/infiniband/*/sys_image_guid'\
	'/sys/class/infiniband/*/uevent'\
	'/proc/net/sdp'\
	'/proc/net/dev_mcast'\
	'/etc/modprobe.conf'\
	'/etc/modprobe.d/*'\
	#'/var/log/messages'\
)

########################################################
########################################################
########################################################
# Functions having to do with managing the script itself
########################################################
########################################################
########################################################
function usage {
    echo "sysinfo-snapshot version: $VERSION usage: The sysinfo-snapshot command gathers system information
          for a linux host. The gathered information is placed
          into a gziped file named $ZOFILE. It is required to run this as super 
          user (root) in order to gather all needed information. 
		  
		  Parameters:
		  -v (Verbose) Include commands that scale with fabric size and commonly produce large outputs 
		  
		  Send your feedback to: Luis De Siqueira <luis@mellanox.com>"
    exit 0
}

# Uses whoami to check if the script is being run as root and exits if it is not.
function check_root {
	if [[ -f /usr/bin/whoami ]] ; then
		if [[ `/usr/bin/whoami` != "root" ]] ; then
			echo "Runing as a none root user"
			echo "Please switch to root user (super user) and run again."
			exit 1
		fi
	fi
}

# Prevent script from running with any parameters
function noopts {
	while [[ ! -z "$1" ]]; do
		# echo "$1"
      	case "$1" in
			-h|--help|\?)
	    	usage
			;;
			*)  echo "error: unknown option $1"
	    	usage
			;;
		esac
	shift
	done
}
########################################################
########################################################
########################################################
# Functions serving as utilities for the script
########################################################
########################################################
########################################################
#checks master SM is alive by sampling its activity count:
function sm-status {
	SmActivity_1=0
	NoSM=0
	for ((lo=0;lo<=3;lo++)) ; do
		sleep 3
		SmActivity=`sminfo |awk '{ print $10 }'`
		echo "SM activity on `date +%T` is $SmActivity"
		if [[ $SmActivity == $SmActivity_1 ]] ; then
			NoSM=1	
		else
			NoSM=0
		fi
		SmActivity_1=$SmActivity
	done
	if [ $NoSM = 0 ] ; then
		echo "Master SM activity is progressing. SM is alive."
	else
		echo "ALERT: Master SM activity has not make any progress. CHECK master SM!"
	fi
}

function Multicast_Information {
	echo "MLIDs list: "
	/usr/sbin/saquery -g
	echo ""
	echo "MLIDs members for each multicast group:"
	MLIDS=(`/usr/sbin/saquery -g |grep Mlid | sed 's/\./ /g'|awk '{print $2}'`)
	MLIDC=${#MLIDS[*]}
	for ((i = 0; i< $MLIDC ; i++)); do
	        echo "Members of MLID ${MLIDS[$i]} group:"
	        saquery -m ${MLIDS[$i]}
	        echo "============================================================"
	done
}

function sm_version {
	echo "OpenSM installed packages: "
	rpm -qa |grep opensm
}

# Returns the subnet manager LID
function sm_master_is {

	MasterLID=(`/usr/sbin/sminfo |awk '{print $4}' `)
	echo "IB fabric SM master is: (`/usr/sbin/smpquery nodedesc $MasterLID`) "
	echo "All SMs in the fabric: "
	SMS=(`/usr/sbin/saquery -s |grep base_lid |head -1| sed 's/\./ /g'|awk '{print $2}'`)
	SMC=${#SMS[*]}

	for ((i = 0; i< $SMC ; i++)); do
	        echo ""
		echo ${SMS[$i]}
	         /usr/sbin/smpquery nodedesc ${SMS[$i]}
	         /usr/sbin/sminfo ${SMS[$i]}
	        echo ""
	done
}

# Runs ethtool -i on all interfaces (gives driver information)
function eth-tool-all-interfaces-i {
   for interface in `ls /sys/class/net/ | xargs`
      do
      echo -e "\nInterface: $interface"
      ethtool -i $interface
      echo "--------------------------------------------------"
   done
}

function eth-tool-all-interfaces-k {
   for interface in `ls /sys/class/net/ | xargs`
      do
      echo -e "\nInterface: $interface"
      ethtool -k $interface
      echo "--------------------------------------------------"
   done
}

function eth-tool-all-interfaces-S {
   for interface in `ls /sys/class/net/ | xargs`
      do
      echo -e "\nInterface: $interface"
      ethtool -k $interface
      echo "--------------------------------------------------"
   done
}

function eth-tool-all-interfaces-c {
   for interface in `ls /sys/class/net/ | xargs`
      do
      echo -e "\nInterface: $interface"
      ethtool -c $interface
      echo "--------------------------------------------------"
   done
}

function eth-tool-all-interfaces-g {
   for interface in `ls /sys/class/net/ | xargs`
      do
      echo -e "\nInterface: $interface"
      ethtool -g $interface
      echo "--------------------------------------------------"
   done
}

function eth-tool-all-interfaces-a {
   for interface in `ls /sys/class/net/ | xargs`
      do
      echo -e "\nInterface: $interface"
      ethtool -a $interface
      echo "--------------------------------------------------"
   done
}

function fw-ini-dump {
   for interface in `lspci |grep Mellanox | awk '{print $1}'`
      do
         mstflint -d $interface dc
      done
}

function mstdump-func {
	for interface in `lspci |grep Mellanox | awk '{print $1}'`
		do
	        echo -e "\nInterface: $interface"
			for instance in 1 2 3
				do
					echo -e "\nAttempt: $instance"
					mstdump $interface
					sleep 1
				done
		done
}
########################################################
########################################################
########################################################
# Old Excluded Functions
########################################################
########################################################
########################################################
#------------------------------------------------------------------------------------------------------------------
function zz_proc_net_bonding_files()
{

	find /proc/net/bonding/ |xargs grep ^

}


#------------------------------------------------------------------------------------------------------------------
function zz_sys_class_net_files()
{

	find /sys/class/net/ |xargs grep ^

}

#------------------------------------------------------------------------------------------------------------------
function ib_switches_FW_scan() {

	lid=-1
	default_shaldag_fw="07.02.00"
	default_anafa_fw="01.00.05"

#	usage() {
#		echo    "usage : $0 [OPTIONS]" 
#		echo    "Options"
#		echo    "[-u uniq_lid]		- Scan only uniq_lid"
#		echo    "[-f fw_version]		- Use user defined fw version"
#		echo    "[-t]			- Print output as a text (without colours)"
#		echo    "[-p]			- Print alarm entries only"
#		echo    "[-h]			- Show this help"
#		exit ;
#	}

	aprint_err_pc() {
	awk '
		function blue(s) {
			if (mono)
				printf s
			else 
				printf "\033[1;034m" s "\033[0;39m"
		}
		function red(s) {
			if (mono)
				printf s
	  		else
				printf "\033[1;031m" s "\033[0;39m"
		}
		function green(s) {
			if (mono)
				printf s
		   else
				printf "\033[1;032m" s "\033[0;39m"
		}
		function print_title() {
			if (!(cnt_titles % 15))
				blue(title "\n")
				cnt_titles++
		}

		BEGIN { 
			title = ("hw_dev_rev\thw_dev_id\tfw_version\tfw_build_id\tfw_date\t\tfw_psid")
			i_shaldag_alarm = 0
			fw_good = 0
			cnt_titles = 0
			mono = "'$mono'"
			supress_normal ="'$delp'"
			red("Scan Fabric\n")
			default_shaldag_fw="'$default_shaldag_fw'" 
			default_anafa_fw="'$default_anafa_fw'" 
			red("Default fw_versions are " default_shaldag_fw " for Shaldag and " default_anafa_fw " for Anafa\n")
			tb1="-----------------------------------------------------------------------------------------------" 
     		blue(tb1 "\n")
		};

		/Hca/	{
			red($0 "\n") 
			exit
		}        
		/^Switch/ {
			i_shaldag++
			ind_shaldag = sprintf("%d ",i_shaldag)
			SWITCH = $0;next
		}               

		{
		#	sub (/[\.\.\.]+/," ",$0)
		}
		/hw_dev_rev/ ||	/hw_dev_id/ || /fw_build_id/ {
			data[n++] = $NF "\t\t"
			next
		}
		/fw_version/ {
			if (( $NF == default_shaldag_fw )|| ( $NF == default_anafa_fw )) {
				fw_good = 1
			}
			data[n++] = $NF "\t"
			next
		}
		/fw_date/ || /fw_psid/ {
			data[n++] = $NF "\t"
			next
		}
		/sw_version/ {
			for (i = 0; i < n; i++)
				if (i in data) { 
					table = (table data[i] )
				}
			if (fw_good == 1) {
				if (!supress_normal) {
					print_title()
					red(ind_shaldag)
					green(SWITCH "\n")
					green(table "\n")
					blue(tb1 "\n")
				}
			}
			else {
				print_title()
				red(ind_shaldag)
				red("--> ALERT "SWITCH " ALERT <--\n");  
				red(table "\n")
				i_shaldag_alarm++
				blue(tb1 "\n")
			}
			fw_good = 0
			delete data 
			table = "" 
			n = 0
		}
		END {
			blue(title "\n")
			red("Default fw_versions are " default_shaldag_fw " for Shaldag and " default_anafa_fw " for Anafa\n")
			red("Total : CHIPs scanned : " i_shaldag ". Problems found : " i_shaldag_alarm "\n" )
		}';
	}

	get_topology_send_mad() {

	awk '	
		#$1~/Switch/ && $2 == 24 {
		$1~/Switch/ && ($2 == 36 || $2 == 24) {
			lid = $(NF-2)
			sub (/#/,"\t", $0) 
			print "echo " $0 "; vendstat -N", lid
			next
		}';
	}

	scan_all() {
		ibnetdiscover | get_topology_send_mad |sh |aprint_err_pc ;
		exit;
	}

	scan_one() {
		lid_l=$1
		echo START
		#madstat N $lid_l | \
		smpquery nodeinfo $lid_l | \
		awk -F "." '
		/NodeType/	{
			node_type = $NF
		}
		/LocalPort/	{
			localport = $NF
		}
		/NumPorts/	{
			nports    = $NF
		}
		/node_desc/	{
			node_desc = $NF
		}
		/Guid/	{
			node_guid = $NF
		}
	
		END	{
			if (node_type == "Channel Adapter") {
				printf("echo Could Not Read Hca firmware.\n")
				exit
			}  
	   	printf("echo Switch nports %d localport %d %s 0x%s\n",nports ,localport, node_desc, node_guid)
 			print "vendstat N", '$lid_l'
		}' | sh | aprint_err_pc;
		exit;
	}

#--------- controlling logic for scan_one function ----------
	mono=1

	while getopts u:f:pht opt
		do
		case "$opt" in
	   	u) lid="$OPTARG";;
			f) defaultfw="$OPTARG";;
			t) mono=1;;
			p) delp=1;;
			h) usage;;
			\?) usage;;
  			esac
		done

	if [[ $lid -eq -1 ]];	then
		scan_all
	fi
	scan_one $lid
}

function ib-find-bad-ports {

	IBPATH=${IBPATH:-/usr/sbin}
	LIST=0
	SPEED=1
	WIDTH=1
	RESET=0
	echo ""

	abort_function() {
   	if [[ "XXX$*" != "XXX" ]] ; then
      	echo "$*"
      fi
		exit 1
	}

	trap 'abort_function "CTRL-C hit. Aborting."' 2

	count_1x=0
	checked_ports=0
	count_deg=0

	FILE="/tmp/temp.$$"
	TEMPFILE="/tmp/tempportinfo.$$"

	echo -en "Looking For Degraded Width (1X) Links .......\t"
	echo "done "
	echo -en "Looking For Degraded Speed Links ............\t"

	$IBPATH/ibnetdiscover -p | grep \( | grep -e "^SW" > $FILE

	exec < $FILE
	while read LINE
		do

		checked_ports=$((checked_ports+1))

		PORT="`echo $LINE |awk '{print $(3)}'`"
		GUID="`echo $LINE |awk '{print $(4)}'`"

		$IBPATH/ibportstate -G $GUID $PORT > $TEMPFILE

		ACTIVE_WIDTH="`cat $TEMPFILE | grep LinkWidthActive | head -1 | sed 's/.\.\./ /g' | awk '{print $(NF)}'`"
		ACTIVE_SPEED="`cat $TEMPFILE | grep LinkSpeedActive | head -1 | sed 's/.\.\./ /g' | awk '{print $2}'`"
		ENABLE_SPEED="`cat $TEMPFILE | grep LinkSpeedEnabled |head -1| sed 's/\.\./ /g' | awk '{print $(NF-1)}'`"

		if [ "$ACTIVE_WIDTH" == "1X" ] ; then
			count_1x=$((count_1x + 1))
			echo "GUID:$GUID PORT:$PORT run in 1X width"
		fi

		if [ "$ACTIVE_SPEED" != "$ENABLE_SPEED" ] ; then

			PEER_ENABLE_SPEED="`cat $TEMPFILE  | grep LinkSpeedEnabled |tail -1| sed 's/\.\./ /g' | awk '{print $(NF-1)}'`"

			if [ "$ACTIVE_SPEED" != "$PEER_ENABLE_SPEED" ] ; then

				count_deg=$((count_deg+1))
				echo "GUID:$GUID PORT:$PORT run in degraded speed"
				#ibportstate -G $GUID $PORT reset >/dev/null 2>&1
	        	#ibportstate -G $GUID $PORT enable >/dev/null 2>&1
			fi
		fi
	done

	CHECKED=$checked_ports
	rm -f $FILE $TEMPFILE

	echo -e "done "
	echo ""
	echo ""
	echo "## Summary: $CHECKED ports checked" 
	echo "##	  $count_1x ports with 1x width found "
	echo "##        $count_deg ports with degraded speed found "
}

function ib-find-disabled-ports {
IBPATH=${IBPATH:-/usr/sbin}


checked_ports=0
count_disabled=0

FILE="/tmp/temp.$$"

$IBPATH/ibnetdiscover -p | grep -v \( | grep -e "^SW" > $FILE

exec < $FILE
while read LINE
do

PORT="`echo $LINE |awk '{print $(3)}'`"
GUID="`echo $LINE |awk '{print $(4)}'`"

checked_ports=$((checked_ports+1))
LINK_STATE="`$IBPATH/ibportstate -G $GUID $PORT | grep PhysLinkState | head -1 | sed 's/.\.\.\./ /g' | awk '{print $NF}'`"

if [ "$LINK_STATE" == "Disabled" ] ; then
	$IBPATH/ibswitches | grep $GUID | grep -q sRB-20210G-1UP
	if [ $? == 0 -a $PORT == 24 ] ; then
		Is_10G=1
	else
		count_disabled=$((count_disabled + 1))
		echo "GUID: $GUID PORT: $PORT is disabled"
	fi
fi

done

rm /tmp/temp.$$

echo ""
echo "## Summary: $checked_ports ports checked, $count_disabled disabled ports found"
}

function ib-mc-info-show {
nodes=/tmp/MCnodes.$$
groups=/tmp/MCgroups.$$
nodeLookup=false
groupLookup=false
MAX_GROUPS=64
version=1.2

function mgid2ip()
{
	local ip=`echo $1 | awk '
	{
		mgid=$1
		n=split(mgid, a, ":")
			if (a[2] == "401b") {
			upper=strtonum("0x" a[n-1])
			lower=strtonum("0x" a[n])
			addr=lshift(upper,16)+lower
			addr=or(addr,0xe0000000)
			a1=and(addr,0xff)
			addr=rshift(addr,8)
			a2=and(addr,0xff)
			addr=rshift(addr,8)
			a3=and(addr,0xff)
			addr=rshift(addr,8)
			a4=and(addr,0xff)
			printf("%u.%u.%u.%u", a4, a3, a2, a1) 
		}
		else {
			printf ("IPv6")
		}
	}'`
	echo -en $ip
}
		node=$OPTARG
		nodeLookup=true
		group=$OPTARG
		groupLookup=true

saquery -m | while read line; do
	k=${line%%.*}
	v=${line##*.}
	if [ "$k" == "Mlid" ]; then
		mlid=$v
	elif [ "$k" == "MGID" ]; then
		ip=`mgid2ip $v`
	elif [ "$k" == "NodeDescription" ]; then
		if $groupLookup; then
			echo $mlid $ip $v >> $groups
		fi	
		# Ignore switches and routes
		if [[ "$v" =~ "^ISR[29]|^[42]036|^IB-to-TCP|^sRB-20210G" ]]; then
			continue
		fi
		if $nodeLookup; then
			echo $v >> $nodes
		fi
	fi
done

echo  ----------------------------------
echo  -- Number of MC groups per node --
echo  ----------------------------------
if $nodeLookup ; then
		node=sum
		# Summary how many gruops for each node
		echo "Node Name	MC Groups #"
		sort $nodes | uniq -c | while read line; do
			gcount=`echo $line | cut -d " " -f 1`
			name=`echo $line | cut -d " " -f 2-`
			echo -en "$name	--->  $gcount"
			if [ $gcount -gt $MAX_GROUPS ]; then
				echo "	-- PERFORMANCE DROP WARNING --"
			fi
			echo
		done
fi

echo -------------------------------------
echo -- Number of MC members per groups --
echo -------------------------------------

if $groupLookup ; then	

		group=sum
		#summary how many members for each MC group
		awk '{print $1, $2}' $groups | sort -k1 -n | uniq -c | awk '{printf("%s %s (%s)\n", $2, ($3=="IPv6"?"":$3), $1)}'
fi

#rm -f $nodes $groups
}

function ib-topology-viewer {

swVerbose=false
caVerbose=false
internal=false
discover=true

netfile="/tmp/net"
swfile="/tmp/sw"
swguids="/tmp/swguids"
tempfile1="/tmp/t1"
tempfile2="/tmp/t2"

if [ ! -f $topofile ] ; then
	echo "$topofile doesnt exists!"
	usage
fi

if $internal; then
	if ! $discover; then
		cp $topofile $netfile 
	else
		eval ibnetdiscover -p > $netfile
	fi
else
	if ! $discover; then
	 	cat $topofile |grep -v -i sfb > $netfile
	else
		eval ibnetdiscover -p |grep -v -i sfb > $netfile
	fi
fi

GUIDS=`cat $netfile | grep -e ^SW | awk '{print $4}' | uniq`


if [ "$GUIDS" == "" ] ; then
	echo "No Switch Found"
	exit
fi

for guid in $GUIDS ; do  
	string="$guid..x"
	desc=`cat $netfile| grep -e ^SW | grep $string  | awk -F\' '{print $2}' | uniq`
	echo $desc==$guid >>$tempfile1
done

sort $tempfile1 -o $swfile
echo "-----------------------------------"
echo "-  Printing topollogy connection  -"
echo "-----------------------------------"

for guid in `awk -F== '{print $2}' $swfile`; do
	swDesc=`grep $guid $swfile | awk -F== '{print $1}'` 
	ca=`awk -vg=$guid '{if ($1 ~ "SW" && $4 ~ g && $8 ~ "CA") print $0}' $netfile >$tempfile1`
	caNumber=`cat $tempfile1 | wc -l`
	sw=`awk -vg=$guid '{if ($1 ~ "SW" && $4 ~ g && $8 ~ "SW") print $0}' $netfile >$tempfile2`
	swNumber=`cat $tempfile2 | wc -l`
	notConnected=`awk -vg=$guid '{if ($1 ~ "SW" && $4 ~ g && $7 != "-") print $0}' $netfile |wc -l`
	printf "%-82s\t" "$swDesc($guid)"
	printf "$caNumber"
	printf " HCA ports and "
	printf "$swNumber"
	printf " switch ports.\n"

	if  [ ${swNumber} > 0 ]; then
		if $swVerbose ; then
			cat $tempfile2
			echo ""
		fi
	fi
	if [ [${caNumber} > 0]  ]; then
		if $caVerbose ; then
			cat $tempfile1
			echo ""
		fi
	fi

done

rm -f $netfile
rm -f $swfile
rm -f $swguids
rm -f $tempfile1
rm -f $tempfile2

}

########################################################
########################################################
########################################################
# Main
########################################################
########################################################
########################################################
function generate_html {
	echo '<html>'
	echo '<head>'
	echo '<title>'
	echo $OFILE
	echo '</title>'
	echo '</head>'
	echo '<body>'
	echo '<pre>'
	echo '<a name="index"></a>'
	echo '<h1>Mellanox Technologies</h1>'
	echo '<h2>Linux and OFED System Information Snapshot Utility</h2>'
	echo '<h2>Version : '
	echo $VERSION
	echo '</h2>'
	declare -i STEP=0
	declare -i STOP=4
	############## SERVER COMMANDS #################
	echo '<h2>Native Linux Commands:</h2>'
	echo '<table cols="4" width="100%" border="0" bgcolor="#E0E0FF">'
	echo '<tbody>'
	echo '<tr>'
	for cmd in "${NativeCommands[@]}"
	do
		echo '<td width="25%">'
		echo '<a href="#'$cmd'">'$cmd'</a>'
		STEP+=1
		if ((STEP > STOP)); then
			echo '</tr>'
			echo '<tr>'
			STEP=0
		fi
	done
	echo '</tr>'
	echo '</tbody>'
	echo '</table>'
	STEP=0
	############## InfiniBand Host COMMANDS #################
	echo '<h2>InfiniBand Host Based Commands:</h2>'
	echo '<table cols="4" width="100%" border="0" bgcolor="#E0E0FF">'
	echo '<tbody>'
	echo '<tr>'
	for cmd in "${InfiniBandHostCommands[@]}"
		do
			echo '<td width="25%">'
			echo '<a href="#'$cmd'">'$cmd'</a>'
			STEP+=1
			if ((STEP > STOP)); then
				echo '</tr>'
				echo '<tr>'
				STEP=0
			fi
		done
	echo '</tr>'
	echo '</tbody>'
	echo '</table>'
	STEP=0
	############## Sensitive Commands #################
	echo '<h2>Sensitive Commands:</h2>'
	echo '<table cols="4" width="100%" border="0" bgcolor="#E0E0FF">'
	echo '<tbody>'
	echo '<tr>'
	for cmd in "${SensitiveCommands[@]}"
		do
			echo '<td width="25%">'
			echo '<a href="#'$cmd'">'$cmd'</a>'
			STEP+=1
			if ((STEP > STOP)); then
				echo '</tr>'
				echo '<tr>'
				STEP=0
			fi
		done
	echo '</tr>'
	echo '</tbody>'
	echo '</table>'
	STEP=0
	############## Fabric Scaling Commands #################
	if [[ $1 == '-v' ]]; then
	echo '<h2>Fabric Scaling Commands:</h2>'
	echo '<table cols="4" width="100%" border="0" bgcolor="#E0E0FF">'
	echo '<tbody>'
	echo '<tr>'
	for cmd in "${FabricScalingCommands[@]}"
		do
			echo '<td width="25%">'
			echo '<a href="#'$cmd'">'$cmd'</a>'
			STEP+=1
			if ((STEP > STOP)); then
				echo '</tr>'
				echo '<tr>'
				STEP=0
			fi
		done
	echo '</tr>'
	echo '</tbody>'
	echo '</table>'
	fi
	STEP=0
	############## Driver Commands #################
	echo '<h2>Driver Commands:</h2>'
	echo '<table cols="4" width="100%" border="0" bgcolor="#E0E0FF">'
	echo '<tr>'
	for cmd in "${DriverCommands[@]}"
	do
		echo '<td width="25%">'
		echo '<a href="#'$cmd'">'$cmd'</a>'
		STEP+=1
		if ((STEP > STOP)); then
			echo '</tr>'
			echo '<tr>'
			STEP=0
		fi
	done
	echo '</tr>'
	echo '</tbody>'
	echo '</table>'
	STEP=0
	############## Files To Get #################
	echo '<h2>Files:</h2>'
	echo '<table cols="4" width="100%" border="0" bgcolor="#E0E0FF">'
	echo '<tr>'
	for cmd in "${FilesToGet[@]}"
	do
		echo '<td width="25%">'
		echo '<a href="#'$cmd'">'$cmd'</a>'
		STEP+=1
		if ((STEP > STOP)); then
			echo '</tr>'
			echo '<tr>'
			STEP=0
		fi
	done
	echo '</tr>'
	echo '</tbody>'
	echo '</table>'
	# Methods
	#do_section sm-status
	echo '<a id="sm-status">'
	echo '<h2>sm-status</h2>'
	echo '<code>'
	sm-status
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section sm_version
	echo '<a id="sm_version">'
	echo '<h2>sm_version</h2>'
	echo '<code>'
	sm_version
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section sm_master_is
	echo '<a id="sm_master_is">'
	echo '<h2>sm_master_is</h2>'
	echo '<code>'
	sm_master_is
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section Multicast-Information
	echo '<a id="Multicast-Information">'
	echo '<h2>Multicast-Information</h2>'
	echo '<code>'
	Multicast-Information
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section ib-mc-info-show
	echo '<a id="ib-mc-info-show">'
	echo '<h2>ib-mc-info-show</h2>'
	echo '<code>'
	ib-mc-info-show
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section fw-ini-dump
	echo '<a id="fw-ini-dump">'
	echo '<h2>fw-ini-dump</h2>'
	echo '<code>'
	fw-ini-dump
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section eth-tool-all-interfaces-i
	echo '<a id="eth-tool-all-interfaces-i">'
	echo '<h2>eth-tool-all-interfaces-i</h2>'
	echo '<code>'
	eth-tool-all-interfaces-i
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section eth-tool-all-interfaces-k
	echo '<a id="eth-tool-all-interfaces-k">'
	echo '<h2>eth-tool-all-interfaces-k</h2>'
	echo '<code>'
	eth-tool-all-interfaces-k
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section eth-tool-all-interfaces-S
	echo '<a id="eth-tool-all-interfaces-S">'
	echo '<h2>eth-tool-all-interfaces-S</h2>'
	echo '<code>'
	eth-tool-all-interfaces-S
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section eth-tool-all-interfaces-c
	echo '<a id="eth-tool-all-interfaces-c">'
	echo '<h2>eth-tool-all-interfaces-c</h2>'
	echo '<code>'
	eth-tool-all-interfaces-c
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section eth-tool-all-interfaces-g
	echo '<a id="eth-tool-all-interfaces-g">'
	echo '<h2>eth-tool-all-interfaces-g</h2>'
	echo '<code>'
	eth-tool-all-interfaces-g
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section eth-tool-all-interfaces-a
	echo '<a id="eth-tool-all-interfaces-a">'
	echo '<h2>eth-tool-all-interfaces-a</h2>'
	echo '<code>'
	eth-tool-all-interfaces-a
	echo '</code>'
	echo '</a>'
	echo '<small><a href="#index">[back to index]</a></small>'
	#do_section mstdump
#	echo '<a id="mstdump">'
#	echo '<h2>mstdump</h2>'
#	echo '<code>'
#	mstdump-func
#	echo '</code>'
#	echo '</a>'
#	echo '<small><a href="#index">[back to index]</a></small>'
	
	
	for cmd in "${NativeCommands[@]}"
	do
		echo '<a id="'$cmd'">'
		echo '<h2>'$cmd'</h2>'
		echo '<code>'
		$cmd
		echo '</code>'
		echo '</a>'
		echo '<small><a href="#index">[back to index]</a></small>'
	done
	for cmd in "${SensitiveCommands[@]}"
	do
		echo '<a id="'$cmd'">'
		echo '<h2>'$cmd'</h2>'
		echo '<code>'
		$cmd
		echo '</code>'
		echo '</a>'
		echo '<small><a href="#index">[back to index]</a></small>'
	done
	for cmd in "${InfiniBandHostCommands[@]}"
	do
		echo '<a id="'$cmd'">'
		echo '<h2>'$cmd'</h2>'
		echo '<code>'
		$cmd
		echo '</code>'
		echo '</a>'
		echo '<small><a href="#index">[back to index]</a></small>'
	done
	if [[ $1 == '-v' ]]; then
	for cmd in "${FabricScalingCommands[@]}"
	do
		echo '<a id="'$cmd'">'
		echo '<h2>'$cmd'</h2>'
		echo '<code>'
		$cmd
		echo '</code>'
		echo '</a>'
		echo '<small><a href="#index">[back to index]</a></small>'
	done
	fi
	for cmd in "${DriverCommands[@]}"
	do
		echo '<a id="'$cmd'">'
		echo '<h2>'$cmd'</h2>'
		echo '<code>'
		$cmd
		echo '</code>'
		echo '</a>'
		echo '<small><a href="#index">[back to index]</a></small>'
	done
	for file in "${FilesToGet[@]}"
	do
		echo '<a id="'$file'">'
		echo '<h2>'$file'</h2>'
		echo '<code>'
		cat $file
		echo '</code>'
		echo '</a>'
		echo '<small><a href="#index">[back to index]</a></small>'
	done
}
function check_usage {
	if [[ $1 == '-h' ]]; then
		usage
	fi
}
function main_original {
	# Perform checks before running
	check_root
	check_usage $1
	# Start...
	# Make temporary directory for files
	mkdir ./SIS-Results
	# Create HTML file
	echo "Please wait... this may take a minute depending on your system configuration"
	generate_html $1>./SIS-Results/$OFILE
	# Tarball ibdiagnet results
	SILENCE=$(tar -zcf sysinfo_ibdiagnet_results.tar.gz /var/tmp/ibdiagnet2/&>/dev/null)
	mv sysinfo_ibdiagnet_results.tar.gz ./SIS-Results/sysinfo_ibdiagnet_results.tar.gz
	if [ $1 == "-v" ]; then
		# mstdump file...
		mstdump-func>./SIS-Results/mstdump-all-interfaces.log
	fi
	# Tar the results directory
	SILENCE=$(tar -zcf $ZOFILE SIS-Results)
	# Create md5sum file
	SILENCE=$(md5sum $ZOFILE>$ZOFILE.md5sum)
	echo $ZOFILE created
	# Remove temp dir
	rm -rf ./SIS-Results
}

function main {
# This version of "main" put contents of genetated html file into a standard output
# and not created any temporary dirs. Changes mark as ###
#
	# Perform checks before running
	check_root
	check_usage $1
	# Start...
	# Make temporary directory for files
###	mkdir ./SIS-Results
	# Create HTML file
	echo "Please wait... this may take a minute depending on your system configuration"
###	generate_html $1>./SIS-Results/$OFILE
	generate_html
###	# Tarball ibdiagnet results
###	SILENCE=$(tar -zcf sysinfo_ibdiagnet_results.tar.gz /var/tmp/ibdiagnet2/&>/dev/null)
###	mv sysinfo_ibdiagnet_results.tar.gz ./SIS-Results/sysinfo_ibdiagnet_results.tar.gz
###	if [ $1 == "-v" ]; then
###		# mstdump file...
###		mstdump-func>./SIS-Results/mstdump-all-interfaces.log
###	fi
###	# Tar the results directory
###	SILENCE=$(tar -zcf $ZOFILE SIS-Results)
###	# Create md5sum file
###	SILENCE=$(md5sum $ZOFILE>$ZOFILE.md5sum)
###	echo $ZOFILE created
###	# Remove temp dir
###	rm -rf ./SIS-Results
}



###main $1 2>/dev/null
main

