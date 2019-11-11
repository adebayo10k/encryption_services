#!/bin/bash
#: Title		:encryption_services
#: Date			:2019-07-13
#: Author		:adebayo10k
#: Version		:1.0
#: Description	:script provides encryption services both to other scripts  
#: Description	:and to the command-line user.  
#: Description	:to encrypt one or more files.
#: Description	:to backup configurations, revocation certs and keys in appropriate ways
#: Description	:integrate with existing system of backup, synchronisation and encryption 
#: Description	:ssh into remotes to backup their keys too
#: Options		:
##

function main
{

echo "USAGE: $(basename $0) [<file paths>]" # zero or more strings (representing fullpaths to files)

#requested_mount_dir=${1:-"not_yet_set"} ## whether this script run directly or called by shred_dirs
# might also be useful to validate that no parameters were given from the command line.
# USE [$SHLVL -gt 2] AS AN ADDITIONAL, MORE SPECIFIC TEST OF WHERE THIS SCRIPT WAS CALLED FROM

echo "OUR CURRENT SHELL LEVEL IS: $SHLVL"

# Display a program header and give user option to leave if here in error:
echo
echo -e "		\033[33m===================================================================\033[0m";
echo -e "		\033[33m||                Welcome to ENCRYPTION SERVICES                  ||  author: adebayo10k\033[0m";  
echo -e "		\033[33m===================================================================\033[0m";
echo
echo " Type q to quit NOW, or press ENTER to continue."
echo && sleep 1

# TODO: if the shell level is -ge 2, called from another script so bypass this exit option
read last_chance
case $last_chance in 
[qQ])	echo
		echo "Goodbye!" && sleep 1
		exit 0
			;;
*) 		echo "You're IN..." && echo && sleep 1
	 		;;
esac 


## EXIT CODES:
E_UNEXPECTED_BRANCH_ENTERED=10
E_OUT_OF_BOUNDS_BRANCH_ENTERED=11
E_INCORRECT_NUMBER_OF_ARGS=12
E_UNEXPECTED_ARG_VALUE=13
E_REQUIRED_FILE_NOT_FOUND=20
E_REQUIRED_PROGRAM_NOT_FOUND=21
E_UNKNOWN_RUN_MODE=30
E_UNKNOWN_EXECUTION_MODE=31

export E_UNEXPECTED_BRANCH_ENTERED
export E_OUT_OF_BOUNDS_BRANCH_ENTERED
export E_INCORRECT_NUMBER_OF_ARGS
export E_UNEXPECTED_ARG_VALUE
export E_REQUIRED_FILE_NOT_FOUND
export E_REQUIRED_PROGRAM_NOT_FOUND
export E_UNKNOWN_RUN_MODE
export E_UNKNOWN_EXECUTION_MODE

#################################

# GLOBAL VARIABLE DECLARATIONS:

config_file_fullpath= # a full path to a file
line_type="" # global...
test_line="" # global...

service_index= # service number of selected service

declare -a incoming_array=()

################################################
# independent variables
encryption_system= # public_key | symmetric_key
output_file_format= # ascii | binary

# dependent variables
encryption_system_option= # --encrypt | --symmetric
output_file_extension= # .asc | .gpg

armor_option='--armor'
sender_option='--local-user'
recipient_option='--recipient'
sender_uid=""
recipient_uid=""
declare -a recipient_uid_list=()
################################################

gpg_command='gpg'
output_option='--output'
file_path_placeholder='<filepath_placeholder>'

generic_command=""
file_specific_command=""

plaintext_file_fullpath=""
plaintext_dir_fullpath=""

abs_filepath_regex='^(/{1}[A-Za-z0-9\._-~]+)+$' # absolute file path, ASSUMING NOT HIDDEN FILE, ...
all_filepath_regex='^(/?[A-Za-z0-9\._-~]+)+$' # both relative and absolute file path
email_regex='^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$'
# ^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$
# ^[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:].]{2,4}$ ]]

synchronised_location_holding_dir_fullpath= # OR synchronised_location_parent_directory
public_keyring_default_directory_fullpath=
revocation_certificate_default_directory_fullpath=

this_host=$(hostname) #
synchronised_dir_fullpath= # directory within synchronised_location_holding_dir_fullpath (only written to by this_host)
declare -a synchronised_subdirs=() # set of directories within synchronised_dir_fullpath


new_keygen_OK=
new_key_rev_cert_OK=
rev_cert_encrypt_OK=
rev_certs_moved_OK=
public_key_export_OK=

###############################################################################################


# SET THE SCRIPT ROOT DIRECTORY IN WHICH THIS SCRIPT CURRENTLY FINDS ITSELF

# NOTE: if soft-linked from an executables PATH directory, this gives the path to the link
echo "The absolute path to this script is: $0"

## TODO: UNLESS SCRIPT 'SOMEHOW' SITS IN THE ROOT DIRECTORY, IN WHICH CASE WE'D JUST REMOVE "$(basename $0)"
## remove from end of full path to script: a directory delimiter and the basename
script_root_dir="${0%'/'"$(basename $0)"}"  
echo "Script root directory set to: $script_root_dir"
export script_root_dir

#entry_test
#
#	case $requested_mount_dir in
#	"not_yet_set")	read_fs_to_mount ## script was called without params, so from cmd line
#					;;
#	*) 				echo "requested directory passed into mount_ecrypt_dirs ok" && sleep 1 && echo
#					echo "requested directory is $requested_mount_dir" && sleep 1 && echo
#					query_fs_to_mount "$requested_mount_dir"
#					;;
#	esac 
#
#	#unset $requested_mount_dir


echo "ON ENTRY, script_root_dir WAS SET TO: $script_root_dir"
echo "YOUR CURRENT SHELL LEVEL IS: $SHLVL"

read

#######################################################################
###############################################################################################

echo
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "STARTING THE 'MAIN SECTION' in script $(basename $0)"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo

###############################################################################################
# VVVV CODE THAT ALWAYS RUNS WHEN SCRIPT IS CALLED: VVVV
###############################################################################################

# 1. DETERMINE HOW MANY ARGUMENTS HAVE BEEN PASSED INTO THIS SCRIPT
number_of_incoming_params=$#

echo "Number of arguments passed in = $number_of_incoming_params"

# 2. VERIFY NUMBER OF PARAMS (MUST BE FILE PATHS) && 3. TEST THAT INCOMING STRINGS ARE ALL VALID AND ACCESSIBLE FILE PATHS:

# put the incoming data into an array 
if [ $number_of_incoming_params -gt 0 ]
then
	incoming_array=( "$@" )

	# temporary debug check
	for incoming_string in "${incoming_array[@]}"
	do
		echo "$incoming_string"
	done

	for incoming_string in "${incoming_array[@]}"
	do
		echo "incoming string is now: $incoming_string"
		test_file_path_valid_form "$incoming_string"
		if [ $? -eq 0 ]
		then
			# from now on, we can talk about a plaintext file path...
			plaintext_file_fullpath="$incoming_string"
			echo "The full path to the plaintext file is: $plaintext_file_fullpath"

			## ASSUMING THE FILE IS NOT 'SOMEHOW' SITTING IN THE ROOT DIRECTORY
			plaintext_dir_fullpath=${plaintext_file_fullpath%/*}
			#plaintext_dir_fullpath=$(echo $plaintext_file_fullpath | sed 's/\/[^\/]*$//') ## also works
			echo "The full path to the plaintext file holding directory is: $plaintext_dir_fullpath"
		else
			echo "The valid form test FAILED and returned: $?"
			echo "Nothing to do now, but to exit..." && echo
			exit $E_UNEXPECTED_ARG_VALUE
		fi	

		# if the above test returns ok, plaintext_file_fullpath and plaintext_dir_fullpath are now set
		test_file_path_access "$plaintext_file_fullpath"
		if [ $? -eq 0 ]
		then
			echo "The full path to the plaintext file is: $plaintext_file_fullpath"
		else
			echo "The file path access test FAILED and returned: $?"
			echo "Nothing to do now, but to exit..." && echo
			exit $E_REQUIRED_FILE_NOT_FOUND
		fi	

		test_dir_path_access "$plaintext_dir_fullpath"
		if [ $? -eq 0 ]
		then
			echo "The full path to the plaintext file holding directory is: $plaintext_dir_fullpath"
		else
			echo "The directory path access test FAILED and returned: $?"
			echo "Nothing to do now, but to exit..." && echo
			exit $E_REQUIRED_FILE_NOT_FOUND
		fi

	done

fi

# 3. GET WHICH CONFIGURATION FILE SCRIPT WILL READ FROM AND TEST THAT IT CAN BE ACCESSED AND READ OK

echo
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "STARTING THE 'SET PATH TO CONFIGURATION FILE' PHASE in script $(basename $0)"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo

get_config_file_to_use
unset user_config_file_fullpath

config_file_fullpath=${user_config_file_fullpath:-"default_config_file"}

if [ "$config_file_fullpath" == "default_config_file" ]
then
	config_file_name="encryption_services_config"
	echo "Our configuration filename is set to: $config_file_name" && echo

	#config_dir_fullpath="$(cd $script_dir_fullpath; cd ../; pwd)" ## returns with no trailing /
	config_dir_fullpath="/etc"
	echo "PROVISIONALLY:Our configuration file sits in: $config_dir_fullpath" && echo

	config_file_fullpath="${config_dir_fullpath}/${config_file_name}"
	echo "PROVISIONALLY:The full path to our configuration file is: $config_file_fullpath" && echo

elif [ "$config_file_fullpath" == "$user_config_file_fullpath" ]
then
	config_dir_fullpath="${user_config_file_fullpath%'/'*}" # also, try [[:alphanum:]] or [A-Za-z0-9_-]
	echo "PROVISIONALLY:Our configuration file sits in: $config_dir_fullpath" && echo

	config_file_fullpath="$user_config_file_fullpath"
	echo "PROVISIONALLY:The full path to our configuration file is: $config_file_fullpath" && echo
	#exit 0

else
	echo "path to configuration file set to: $config_file_fullpath so I QUIT"
	echo "failsafe exit. Unable to set up a configuration file" && sleep 2
	echo "Exiting from function \"${FUNCNAME[0]}\" in script $(basename $0)"
	exit $E_OUT_OF_BOUNDS_BRANCH_ENTERED

fi

# WHICHEVER WAY THE CONFIGURATION FILE PATH WAS JUST SET, WE NOW TEST THAT IT IS VALID AND WELL-FORMED:

test_file_path_valid_form "$config_file_fullpath"
if [ $? -eq 0 ]
then
	echo "Configuration file full path is of VALID FORM"
else
	echo "The valid form test FAILED and returned: $?"
	echo "Nothing to do now, but to exit..." && echo
	exit $E_UNEXPECTED_ARG_VALUE
fi	

# if the above test returns ok, ...
test_file_path_access "$config_file_fullpath"
if [ $? -eq 0 ]
then
	echo "The full path to the CONFIGURATION FILE is: $config_file_fullpath"
else
	echo "The CONFIGURATION FILE path access test FAILED and returned: $?"
	echo "Nothing to do now, but to exit..." && echo
	exit $E_REQUIRED_FILE_NOT_FOUND
fi

test_dir_path_access "$config_dir_fullpath"
if [ $? -eq 0 ]
then
	echo "The full path to the CONFIGURATION FILE holding directory is: $config_dir_fullpath"
else
	echo "The CONFIGURATION DIRECTORY path access test FAILED and returned: $?"
	echo "Nothing to do now, but to exit..." && echo
	exit $E_REQUIRED_FILE_NOT_FOUND
fi	


# 3. TEST WHETHER THE CONFIGURATION FILES' CONTENT FORMAT IS VALID
while read lineIn
do
	test_and_set_line_type "$lineIn" 

done < "$config_file_fullpath" 

echo "return code after line tests: $?" && echo

## TODO: if $? -eq 0 ... ANY POINT IN BRINGING BACK A RETURN CODE?

# if tests passed, configuration file is accepted and used from here on
echo "WE CAN USE THIS CONFIGURATION FILE" && echo
export config_file_name
export config_dir_fullpath
export config_file_fullpath


# 4. IMPORT CONFIGURATION INTO VARIABLES

echo
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo "STARTING THE 'IMPORT CONFIGURATION INTO VARIABLES' PHASE in script $(basename $0)"
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo

#TODO: CAN ALL THESE BE DONE IN ONE FUNCTION LATER?, ANYWAY... KEEP IT SIMPLE FOR NOW
# SINGLE FUNCTION WOULD STORE EACH keyword IN AN ARRAY, WHICH WE'D LOOP THROUGH FOR EACH LINE READ
# visualise it again!
get_synchronised_location_holding_dir_fullpath_config # should this be named set..?.
get_public_keyring_default_directory_fullpath_config # should this be named set..?.
get_revocation_certificate_default_directory_fullpath_config # should this be named set..?.


# NOW DO ALL THE DIRECTORY ACCESS TESTS FOR IMPORTED PATH VALUES HERE.
# REMEMBER THAT ORDER IMPORTANT, AS RELATIVE PATHS DEPEND ON ABSOLUTE.
# debug printouts:
echo
echo "FINALLY, synchronised_location_holding_dir_fullpath variable now set to: \
$synchronised_location_holding_dir_fullpath" && echo

# this valid form test works for sanitised directory paths too
test_file_path_valid_form "$synchronised_location_holding_dir_fullpath"
if [ $? -eq 0 ]
then
	echo "SYNCHRONISED LOCATION HOLDING (PARENT) DIRECTORY PATH IS OF VALID FORM"
else
	echo "The valid form test FAILED and returned: $?"
	echo "Nothing to do now, but to exit..." && echo
	exit $E_UNEXPECTED_ARG_VALUE
fi	

# if the above test returns ok, ...
test_dir_path_access "$synchronised_location_holding_dir_fullpath"
if [ $? -eq 0 ]
then
	echo "The full path to the SYNCHRONISED LOCATION HOLDING (PARENT) DIRECTORY is: \
	$synchronised_location_holding_dir_fullpath"
else
	echo "The SYNCHRONISED LOCATION HOLDING (PARENT) DIRECTORY path access test FAILED and returned: $?"
	echo "Nothing to do now, but to exit..." && echo
	exit $E_REQUIRED_FILE_NOT_FOUND
fi	

# NEXT...

echo "FINALLY, public_keyring_default_directory_fullpath variable now set to: \
$public_keyring_default_directory_fullpath" && echo

# this valid form test works for sanitised directory paths too
test_file_path_valid_form "$public_keyring_default_directory_fullpath"
if [ $? -eq 0 ]
then
	echo "PUBLIC KEYRING DEFAULT DIRECTORY PATH IS OF VALID FORM"
else
	echo "The valid form test FAILED and returned: $?"
	echo "Nothing to do now, but to exit..." && echo
	exit $E_UNEXPECTED_ARG_VALUE
fi	

# if the above test returns ok, ...
test_dir_path_access "$public_keyring_default_directory_fullpath"
if [ $? -eq 0 ]
then
	echo "The full path to the PUBLIC KEYRING DEFAULT DIRECTORY is: \
	$public_keyring_default_directory_fullpath"
else
	echo "The PUBLIC KEYRING DEFAULT DIRECTORY path access test FAILED and returned: $?"
	echo "Nothing to do now, but to exit..." && echo
	exit $E_REQUIRED_FILE_NOT_FOUND
fi	

# NEXT...

echo "FINALLY, revocation_certificate_default_directory_fullpath variable now set to: \
$revocation_certificate_default_directory_fullpath" && echo

# this valid form test works for sanitised directory paths too
test_file_path_valid_form "$revocation_certificate_default_directory_fullpath"
if [ $? -eq 0 ]
then
	echo "REVOCATION CERTIFICATE DEFAULT DIRECTORY PATH IS OF VALID FORM"
else
	echo "The valid form test FAILED and returned: $?"
	echo "Nothing to do now, but to exit..." && echo
	exit $E_UNEXPECTED_ARG_VALUE
fi	

# if the above test returns ok, ...
test_dir_path_access "$revocation_certificate_default_directory_fullpath"
if [ $? -eq 0 ]
then
	echo "The full path to the REVOCATION CERTIFICATE DEFAULT DIRECTORY is: \
	$revocation_certificate_default_directory_fullpath"
else
	echo "The REVOCATION CERTIFICATE DEFAULT DIRECTORY path access test FAILED and returned: $?"
	echo "Nothing to do now, but to exit..." && echo
	exit $E_REQUIRED_FILE_NOT_FOUND
fi	

# 3. WE MUST NOW ESTABLISH THAT ALL THE DIRECTORIES NEEDED FOR OUR SYSTEM OF BACKUP AND SYNCHRONISATION \
#    +ALREADY EXIST, AND IF NOT, CREATE THEM:
# TODO:  # mkdir -p // no error if exists (idempotent), make parents structure /a/b/c as needed MAY BE MORE EFFICIENT

synchronised_dir_fullpath="${synchronised_location_holding_dir_fullpath}/${this_host}_gpg"
echo && echo "synchronised_dir_fullpath variable now set to: $synchronised_dir_fullpath"

# temporary rmdir during development, just until all directory creations confirmed working
#rm -R "$synchronised_dir_fullpath"

test_dir_path_access "$synchronised_dir_fullpath"
if [ $? -eq 0 ]
then
	echo "synchronised_dir_fullpath ALREADY EXISTS AND CAN BE ENTERED OK"
else
	echo && echo "synchronised_dir_fullpath DID NOT ALREADY EXIST, SO WILL NOW BE CREATED..."
	# create it..
	mkdir "$synchronised_dir_fullpath"
	if [ $? -eq 0 ]
	then
		echo "synchronised_dir_fullpath CREATION WAS SUCCESSFUL"
	else
		echo "The mkdir of synchronised_dir_fullpath FAILED and returned: $?"
		echo "Nothing to do now, but to exit..." && echo
		exit $E_UNEXPECTED_BRANCH_ENTERED
	fi	
fi

synchronised_subdirs=\
(\
"${synchronised_dir_fullpath}/${this_host}_public_keys_incoming" \
"${synchronised_dir_fullpath}/${this_host}_public_keys_outgoing" \
"${synchronised_dir_fullpath}/${this_host}_revocation_certificates" \
"${synchronised_dir_fullpath}/${this_host}_public_keyring_archive" \
)

for subdir in ${synchronised_subdirs[@]}
do
	test_dir_path_access "$subdir"
	if [ $? -eq 0 ]
	then
		echo "subdir ALREADY EXISTS AND CAN BE ENTERED OK"
	else
		echo && echo "subdir DID NOT ALREADY EXIST, SO WILL NOW BE CREATED..."
		# create it..
		mkdir "$subdir"
		if [ $? -eq 0 ]
		then
			echo "subdir CREATION WAS SUCCESSFUL"
		else
			echo "The mkdir of subdir FAILED and returned: $?"
			echo "Nothing to do now, but to exit..." && echo
			exit $E_UNEXPECTED_BRANCH_ENTERED
		fi	
	fi
done


# 4. CHECK THE STATE OF THE ENCRYPTION ENVIRONMENT:
# 
check_encryption_platform

# issue gpg commands to list keys for now... just to see what's there
bash -c "gpg --list-key"
bash -c "gpg --list-secret-keys"

# 0. FIND OUT WHICH SERVICE IS REQUIRED

get_required_service


# 7. ON RETURN OF CONTROL, CHECK FOR DESIRED POSTCONDITIONS


echo "encryption_services exit code: $?" 

} ## end main
















###############################################################################################
#### vvvvv FUNCTION DECLARATIONS  vvvvv
###############################################################################################
# 

##########################################################################################################
# returns 
function export_public_keys
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	public_key_export_OK=false
	
	echo "public_key_export_OK is set to: $public_key_export_OK"

	# ascii armour export the new public key from its' keyring to the sync'd location
	gpg --armor --output "${synchronised_dir_fullpath}/${this_host}_public_keys_outgoing/pub_key_${this_host}_$(date +'%F@%T').asc" \
	--export "$user_id"
	test_result=$?

	if [ $test_result -eq 0 ]
	then
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE EXPORT OF PUBLIC KEYS WAS SUCCESSFUL"
		public_key_export_OK=true
	else
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE EXPORT OF PUBLIC KEYS FAILED"
		public_key_export_OK=false
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	echo "public_key_export_OK was set to: $public_key_export_OK"
}
##########################################################################################################
# returns 
function rename_and_move_revocation_certificates
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	rev_certs_moved_OK=false
	
	echo "rev_certs_moved_OK is set to: $rev_certs_moved_OK"

	# rename all encrypted revocation certificates to the sync'd location
	mv "$revocation_certificate_default_directory_fullpath"/* "${synchronised_dir_fullpath}/${this_host}_revocation_certificates"
	test_result=$?

	if [ $test_result -eq 0 ]
	then
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE ENCRYPTED REVOCATION CERTS. RENAME AND MOVE WAS SUCCESSFUL"
		rev_certs_moved_OK=true
	else
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE ENCRYPTED REVOCATION CERTS. RENAME AND MOVE FAILED"
		rev_certs_moved_OK=false
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	echo "rev_certs_moved_OK was set to: $rev_certs_moved_OK"
}
##########################################################################################################
# returns 
function encrypt_revocation_certificates
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	rev_cert_encrypt_OK=false
	
	echo "rev_cert_encrypt_OK is set to: $rev_cert_encrypt_OK"


	touch "${synchronised_dir_fullpath}/${this_host}_revocation_certificates/keypair_fingerprint_list"

	for file in "${revocation_certificate_default_directory_fullpath}"/*
	do
		incoming_array+=( "${file}" )
		if [[ $file =~ .rev$ ]]
		then
			fingerprint="${file%.rev}"; fingerprint="${fingerprint##*'/'}"
			#echo "$fingerprint"
			echo "$fingerprint" >> "${synchronised_dir_fullpath}/${this_host}_revocation_certificates/keypair_fingerprint_list"
		fi
	done

	echo && echo "incoming_array HAS NOW BEEN POPULATED WITH REVOCATION CERTS"

	# encrypt whatever we've put in that incoming_array (should normally be just 2 files - the pre and user-generated rev certs)
	# our encryption script takes care of shredding everything it encrypts!
	# TODO: THINK... WE COULD ENCRYPT WITH A DIFFERENT KEY - A KEY FOR THIS PURPOSE ONLY?

	echo && echo "JUST ABOUT TO CALL gpg_file_encryption_service ..."

	gpg_file_encryption_service # we can use ANY available private key for this, not just the newly generated one! tell the user!
	test_result=$?

	if [ $test_result -eq 0 ]
	then
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE REVOCATION CERTIFICATE ENCRYPTION WAS SUCCESSFUL"
		rev_cert_encrypt_OK=true
	else
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE REVOCATION CERTIFICATE ENCRYPTION FAILED"
		rev_cert_encrypt_OK=false
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	echo "rev_cert_encrypt_OK was set to: $rev_cert_encrypt_OK"
}
##########################################################################################################
# returns 
function generate_revocation_certificate
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	new_key_rev_cert_OK=false
	
	echo "new_key_rev_cert_OK is set to: $new_key_rev_cert_OK"

	# generate a revocation certificate (user-generated) for the new key-pair
	# for now we'll just hard code for an ascii (the default) format certificate

	# WE KNOW THAT REVOCATION CERTS AND PRIVATE KEYS SHOULD NEVER EXIST ON THE SAME HOST, BUT WHILE REV CERTS DO \
	# + EXIST ON OUR SYSTEM, WE'LL USE ENCRYPTION AND SHREDDING TO ACHEIVE CONFIDENTIALITY AND INTEGRITY

	# gpg encrypt both user-generated and pre-generated revocation certs in the GnuPG default location	
	
	# we first just need to load up incoming_array
	# we'll also append a list of fingerprints

	gpg --output "${revocation_certificate_default_directory_fullpath}/revoke_cert_${this_host}_$(date +'%F@%T').asc" \
	--gen-revoke "$user_id"
	test_result=$?

	if [ $test_result -eq 0 ]
	then
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE USER-GENERATED REVOCATION CERTIFICATE WAS SUCCESSFUL"
		new_key_rev_cert_OK=true
	else
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE USER-GENERATED REVOCATION CERTIFICATE FAILED"
		new_key_rev_cert_OK=false
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	echo "new_key_rev_cert_OK was set to: $new_key_rev_cert_OK"
}
##########################################################################################################
# nothing returned, as no other function depends on the outcome of this task. just print messages.
function backup_public_keyrings
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	# public keyring backup:
	for pubkeyring in {"pubring.gpg","pubring.kbx"}
	do

		# copy old public keyring (each format) from synchronised location to archive location
		test_file_path_access "${synchronised_dir_fullpath}/${pubkeyring}"
		if [ $? -eq 0 ]
		then
			echo && echo "AN EXISTING \"${pubkeyring}\" PUBLIC KEYRING WAS FOUND IN THE SYNC'D LOCATION"
			# rename and archive this existing public keyring
			mv "${synchronised_dir_fullpath}/${pubkeyring}" \
			"${synchronised_dir_fullpath}/${this_host}_public_keyring_archive/${pubkeyring}_before.$(date +'%F@%T')"
			echo && echo "THE EXISTING \"${pubkeyring}\" PUBLIC KEYRING WAS RENAMED AND ARCHIVED"
		else
			echo && echo "COULDN'T FIND AN EXISTING \"${pubkeyring}\" PUBLIC KEYRING IN THE SYNC'D LOCATION"		
		fi

		# copy new public keyring (each format) from default location to synchronised location
		test_file_path_access "$public_keyring_default_directory_fullpath/${pubkeyring}"
		if [ $? -eq 0 ]
		then
			echo && echo "A NEW \"${pubkeyring}\" PUBLIC KEYRING WAS FOUND IN THE GnuPG DEFAULT LOCATION"
			# copy the new version to the sync'd location
			cp "$public_keyring_default_directory_fullpath/${pubkeyring}" \
			"${synchronised_dir_fullpath}"
			echo && echo "THE LATEST \"${pubkeyring}\" PUBLIC KEYRING HAS NOW BEEN COPIED TO THE SYNC'D LOCATION"
		else
			echo && echo "COULDN'T FIND A NEW \"${pubkeyring}\" PUBLIC KEYRING IN THE GnuPG DEFAULT LOCATION"		
		fi

	done

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}
##########################################################################################################
# set the value of the new_keygen_OK global
function generate_public_keypair
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	#test_uid=$1

	#new_keypair_user_id=
	new_keygen_OK=false 

	#echo "new_keypair_user_id is set to: $new_keypair_user_id"
	echo "new_keygen_OK is set to: $new_keygen_OK"


	gpg --full-gen-key	
	test_result=$?
	
	if [ $test_result -eq 0 ]
	then
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE ENCRYPTION WAS SUCCESSFUL"
		new_keygen_OK=true
	else
		echo && echo "RETURNED VALUE \"$test_result\" THEREFORE ENCRYPTION FAILED"
		new_keygen_OK=false
	fi


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	echo "new_keygen_OK was set to: $new_keygen_OK"

}
##########################################################################################################
# returns zero if user-id (or substring of it) already used in public keyring
function test_uid_in_pub_keyring
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	test_uid=$1
	
	echo "test_uid is set to: $test_uid"

	gpg --list-key | grep "$test_uid" &>/dev/null
	test_result=$?

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	return "$test_result"
}
##########################################################################################################
# returns zero if 
function test_email_valid_form
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	test_email=$1
	
	echo "test_email is set to: $test_email"

	if [[ $test_email =~ $email_regex ]]
	then
		echo "THE FORM OF THE INCOMING PARAMETER IS OF A VALID EMAIL ADDRESS"
		test_result=0
	else
		echo "PARAMETER WAS NOT A MATCH FOR OUR KNOWN EMAIL FORM REGEX: "$email_regex"" && sleep 1 && echo
		echo "Returning with a non-zero test result..."
		test_result=1
		return $E_UNEXPECTED_ARG_VALUE
	fi 


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	return "$test_result"
}
###############################################################################################
function set_working_user_id
{

	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	# in order for script to use a variable (user_id) when creating certificate revocation and public key export commands, \
	# we now assign an identifying email address to the global user_id variable:
	# we're doing it here just to make sure we use the same one during interactive key generation:
	
	while true
	do

		user_id=""

		echo && echo "ENTER THE UNIQUE USER-ID (email address) THAT UR ABOUT TO USE FOR KEY GEN:" && echo
		read user_id
		echo && echo "You specified the user-id: $user_id" && echo

		# test user_id for valid email form
		test_email_valid_form "$user_id"
		valid_email_result=$?
		echo " "

		if [ $valid_email_result -eq 0 ]
		then
			echo && echo "EMAIL ADDRESS \"$user_id\" IS VALID"
			#break
		else
			echo && echo "THAT'S NO VALID EMAIL ADDRESS, TRY AGAIN..."
			continue
		fi

		# ensure the user specified email user-id (or substring of it) doesn't already exist in the public keyring
		test_uid_in_pub_keyring "$user_id"
		uid_in_keyring_result=$?
		echo " "
		
		# positive result is bad
		if [ $uid_in_keyring_result -ne 0 ]
		then
			echo && echo "OK TO USE EMAIL ADDRESS \"$user_id\" "
			break
		else
			echo && echo "THAT'S A VALID EMAIL ADDRESS, BUT IT'S ALREADY BEING USED :( TRY AGAIN..."
			continue # just in case we add more code after this block
		fi

	done


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

###############################################################################################
function generate_and_manage_keys
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo
	
	
	set_working_user_id

	##############################################
	
	echo && echo "[1] EMAIL ADDRESS USER ID VALIDATION COMPLETE... MOVING ON TO:"
	echo && echo "KEY GENERATION"

	echo && echo "[1] KNOWN DEPENDENCIES: "
	echo "NONE"

	echo && echo "[1] EXISTENCE OF KEY GENERATION DEPENDENCY CONFIRMED OK" && echo
	echo && echo "...WAIT ...YOU'RE ABOUT TO BE ASKED FOR SOME KEY GENERATION PARAMETERS..."	
	sleep 12
	
	generate_public_keypair

	##############################################

	echo && echo "[2] KEY GENERATION COMPLETE... MOVING ON TO:"
	echo && echo "KEYRING BACKUP ACTIVITIES"

	echo && echo "[2] KNOWN DEPENDENCIES: "
	echo "1. KEY GENERATION"

	if [ $new_keygen_OK = true ]
	then
		echo && echo "[2] EXISTENCE OF KEY GENERATION DEPENDENCY CONFIRMED OK" && echo
		echo && echo "...WAIT"	
		sleep 12
	else
		# exit, as nothing further can be done
		echo && echo "ABORTING DUE TO FAILURE OF KEY GENERATION..."
		echo && echo "...WAIT"	
		sleep 4
		exit $E_UNEXPECTED_ARG_VALUE
	fi
	
	backup_public_keyrings

	##############################################

	echo && echo "[3] KEYRING BACKUP ACTIVITIES PRESUMED COMPLETE... MOVING ON TO:"
	echo && echo "REVOCATION CERT. GENERATION"

	echo && echo "[3] KNOWN DEPENDENCIES: "
	echo "1. KEY GENERATION"
	echo "2. user_id"

	if [ $new_keygen_OK = true ]
	then
		echo && echo "[3] EXISTENCE OF KEY GENERATION DEPENDENCY CONFIRMED OK" && echo
		echo && echo "...WAIT"	
		sleep 12
	else
		# exit, as nothing further can be done
		echo && echo "ABORTING DUE TO FAILURE OF KEY GENERATION..."
		echo && echo "...WAIT"	
		sleep 4
		exit $E_UNEXPECTED_ARG_VALUE
	fi

	generate_revocation_certificate

	##############################################

	echo && echo "[4] USER-GENERATED REVOCATION CERT. ACTIVITIES COMPLETE... MOVING ON TO:"
	echo && echo "REVOCATION CERT. ENCRYPTION"

	echo && echo "[4] KNOWN DEPENDENCIES: "
	echo "1. REVOCATION CERT. GENERATION"

	if [ $new_key_rev_cert_OK = true ]
	then
		echo && echo "[4] EXISTENCE OF REVOCATION CERT. GENERATION DEPENDENCY CONFIRMED OK" && echo
		echo && echo "...WAIT"	
		sleep 12
	else
		# exit, as nothing further can be done
		echo && echo "ABORTING DUE TO FAILURE OF REVOCATION CERT. GENERATION..."
		echo && echo "...WAIT ...YOU'RE ABOUT TO BE ASKED FOR SOME ENCRYPTION PARAMETERS..."	
		sleep 4
		exit $E_UNEXPECTED_ARG_VALUE
	fi
	
	encrypt_revocation_certificates

	##############################################

	echo && echo "[5] REVOCATION CERT. ENCRYPTION (INCLUDING SHRED) NOW COMPLETE... MOVING ON TO:"
	echo && echo "REVOCATION CERT. RENAME AND MOVE"

	echo && echo "[5] KNOWN DEPENDENCIES: "
	echo "1. REVOCATION CERT. ENCRYPTION"

	if [ $rev_cert_encrypt_OK = true ]
	then
		echo && echo "[5] EXISTENCE OF REVOCATION CERT. ENCRYPTION DEPENDENCY CONFIRMED OK" && echo
		echo && echo "...WAIT"	
		sleep 12
	else
		# exit, as nothing further can be done
		echo && echo "ABORTING DUE TO FAILURE OF REVOCATION CERT. ENCRYPTION..."
		echo && echo "...WAIT"	
		sleep 4
		exit $E_UNEXPECTED_ARG_VALUE
	fi

	rename_and_move_revocation_certificates

	##############################################

	echo && echo "[6] REVOCATION CERT. RENAME AND MOVE NOW COMPLETE... MOVING ON TO:"
	echo && echo "PUBLIC KEYS EXPORT"

	echo && echo "[6] KNOWN DEPENDENCIES: "
	echo "1. KEY GENERATION"
	echo "2. user_id"

	if [ $new_keygen_OK = true ]
	then
		echo && echo "[6] EXISTENCE OF KEY GENERATION DEPENDENCY CONFIRMED OK" && echo
		echo && echo "...WAIT"	
		sleep 12
	else
		# exit, as nothing further can be done
		echo && echo "ABORTING DUE TO FAILURE OF KEY GENERATION"
		echo && echo "...WAIT"	
		sleep 4
		exit $E_UNEXPECTED_ARG_VALUE
	fi

	export_public_keys

	##############################################

	echo && echo "[7] PUBLIC KEYS EXPORT NOW COMPLETE... MOVING ON TO:"
	echo && echo "FINISHING..."

	echo && echo "[7] KNOWN DEPENDENCIES: "
	echo "1. PUBLIC KEYS EXPORT"

	if [ $public_key_export_OK = true ]
	then
		echo && echo "[7] EXISTENCE OF PUBLIC KEYS EXPORT CONFIRMED OK" && echo
		echo && echo "...WAIT"	
		sleep 12
	else
		# exit, as nothing further can be done
		echo && echo "ABORTING DUE TO FAILURE OF PUBLIC KEYS EXPORT"
		echo && echo "...WAIT"	
		sleep 4
		exit $E_UNEXPECTED_ARG_VALUE
	fi

	echo && echo "[7] WE'VE NOW COMPLETED THE WHOLE PROCESS OF KEY GENERATION AND MANAGEMENT...WAIT" && echo
	sleep 4

	##############################################


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo
}

###############################################################################################
###############################################################################################
# test for removal of plaintext file(s)
# 
function verify_file_shred_results
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo


	# :
	for valid_path in "${incoming_array[@]}"
	do
		if [ -f "${valid_path}" ]
		then
			# failure of shred
			echo "FAILED TO CONFIRM THE SHRED REMOVAL OF FILE:"
			echo "${valid_path}" && echo
		else
			# success of shred
			echo "SUCCESSFUL SHRED REMOVAL OF FILE:"
			echo "${valid_path}" && echo

		fi
	done


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

###############################################################################################
# standard procedure once encrypted versions exits: remove the plaintext versions!
function shred_plaintext_files
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo


	echo "OK TO SHRED THE FOLLOWING PLAINTEXT FILE(S)?..." && echo

	# list the encrypted files:
	for valid_path in "${incoming_array[@]}"
	do
		echo "${valid_path}"	
	done

	# for now, confirmation by pressing enter
	read

	# shred the plaintext file and verify its' removal
	for valid_path in "${incoming_array[@]}"
	do
		sudo shred -n 1 -ufv "${valid_path}"	
	done

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo
}

###############################################################################################
# test for encrypted file type
# test for read access to file 
# 
function verify_file_encryption_results
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	valid_path="$1"

	# TODO: FIND SOME BETTER TESTS FOR A GPG ENCRYPTED FILE
	result=$(file "${valid_path}.ENCRYPTED${output_file_extension}" | grep 'PGP') # &2>/dev/null)

	if [ $? -eq 0 ] && [ "$encryption_system" == "public_key" ]
	#if [ $result -eq 0 ]
	then
		echo "PUBLIC KEY ENCRYPTED FILE CREATED SUCCESSFULLY AS:"
		echo "${valid_path}.ENCRYPTED${output_file_extension}"
	elif [ $? -eq 0 ] && [ "$encryption_system" == "symmetric_key" ]
	then
		echo "SYMMETRIC KEY ENCRYPTED FILE CREATED SUCCESSFULLY AS:"
		echo "${valid_path}.ENCRYPTED${output_file_extension}"
	else
		return 1 ## unexpected file type ERROR CODE
	fi

	
	# test encrypted file for expected file type (regular) and read permission
	# TODO: THIS SHOULD BE ONE FOR THE test_file_path_access FUNCTION
	if [ -f "${valid_path}.ENCRYPTED${output_file_extension}" ] \
	&& [ -r "${valid_path}.ENCRYPTED${output_file_extension}" ]
	then
		# encrypted file found and accessible
		echo "Encrypted file found to be readable" && echo
	else
		# -> exit due to failure of any of the above tests:
		echo "Returning from function ${FUNCNAME[0]} in script $(basename $0)"
		return $E_REQUIRED_FILE_NOT_FOUND
	fi


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	return 0
}

###############################################################################################
# the absolute path to the plaintext file is passed in
#
function execute_file_specific_encryption_command
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	valid_path="$1"

	# using [,] delimiter to avoid interference with file path [/]
	file_specific_command=$(echo "$generic_command" | sed 's,'$file_path_placeholder','$valid_path',' \
	| sed 's,'$file_path_placeholder','$valid_path',')

	echo "$file_specific_command"

	# get user confirmation before executing file_specific_command
	# [call a function for this, which can abort the whole encryption process if there's a problem at this point]
	echo && echo "Command look OK?"
	read	# just pause here for now

	# execute file_specific_command if return code from user confirmation = 0
	# execute [here] using bash -c ...
	bash -c "$file_specific_command"


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

###############################################################################################
# this function called if encryption_system="symmetric"
function create_generic_symmetric_key_encryption_command_string
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	echo "OK, WE'RE HERE, READY TO BUILD THAT COMMAND STRING"

# $ gpg --armor --output "$plaintext_file_fullpath.ENCRYPTED.asc" --symmetric "$plaintext_file_fullpath"

	generic_command=

	generic_command+="${gpg_command} "

	if [ $output_file_format == "ascii" ]
	then
		generic_command+="${armor_option} "
		generic_command+="${output_option} ${file_path_placeholder}.ENCRYPTED"
		generic_command+="${output_file_extension} "
	fi

	generic_command+="${encryption_system_option} ${file_path_placeholder}"


	echo "$generic_command"

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}
###############################################################################################
# this function called if encryption_system="public_key"
function create_generic_pub_key_encryption_command_string
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	echo "OK, WE'RE HERE, READY TO BUILD THAT COMMAND STRING"

# $ gpg --armor --output "$plaintext_file_fullpath.ENCRYPTED.asc" \
# --local-user <uid> --recipient <uid> --encrypt "$plaintext_file_fullpath"

	generic_command=

	generic_command+="${gpg_command} "

	if [ $output_file_format == "ascii" ]
	then
		generic_command+="${armor_option} "
		generic_command+="${output_option} ${file_path_placeholder}.ENCRYPTED"
		generic_command+="${output_file_extension} "
	fi

	generic_command+="${sender_option} "
	generic_command+="${sender_uid} "

	for recipient in ${recipient_uid_list[@]}
	do
		generic_command+="${recipient_option} ${recipient} "
	done

	generic_command+="${encryption_system_option} ${file_path_placeholder}"

	echo "$generic_command"

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}


###############################################################################################

function get_recipient_uid
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	while true
	do

		uid=""

		echo "Enter the user-id of a RECIPIENT: or if really none, enter NONE"
		read uid

		if [ "$uid" = "NONE" ]; then break; fi

		# TODO: later, also validate against known public keys in keyring
		# test uid for valid email form
		test_email_valid_form "$uid"
		if [ $? -eq 0 ]
		then
			echo && echo "EMAIL ADDRESS \"$uid\" IS VALID"

			recipient_uid="$uid"
			echo "One recipients user-id is now set to the value: $recipient_uid" && echo
			recipient_uid_list+=( "${recipient_uid}" )
			
			echo "Any more recipients (whose public keys we hold) [y/n]?"
			read more_recipients_answer

			case $more_recipients_answer in
			[yY])	echo "OK, another recipient requested...." && echo
					continue
					;;
			[nN])	echo "OK, no more recipients needed...." && echo
					break
					;;
			*)		echo "UNKNOWN RESPONSE...." && echo && sleep 2
					echo "Entered the FAILSAFE BRANCH...." && echo && sleep 2
					echo "ASSUMING AN AFFIRMATIVE RESPONSE...." && echo && sleep 2
					continue
					;;
			esac

		else
			echo && echo "THAT'S NO VALID EMAIL ADDRESS, TRY AGAIN..." && sleep 2
			continue
		fi
		
	done


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo
}

###############################################################################################
# 
function get_sender_uid
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo


	while true
	do

		uid=""

		echo "Enter the user-id of the SENDER:"
		read uid

		# TODO: later, validate sender_uid HERE. IT MUST CORRESPOND TO ONE OF THE PRIVATE KEYS.
		# test uid for valid email form
		test_email_valid_form "$uid"
		if [ $? -eq 0 ]
		then
			echo && echo "EMAIL ADDRESS \"$uid\" IS VALID"
			
			sender_uid="$uid"
			echo "sender user-id is now set to the value: $sender_uid"
			break
		else
			echo && echo "THAT'S NO VALID EMAIL ADDRESS, TRY AGAIN..."
			continue # just in case we add more code after here
		fi

	done


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo
}

###############################################################################################
#
function set_defaults
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	encryption_system="public_key" #default
	output_file_format="ascii" #default

	if [ $encryption_system == "public_key" ]
	then
		encryption_system_option='--encrypt'
	elif [ $encryption_system == "symmetric_key" ]
	then
		encryption_system_option='--symmetric'
	else
		echo "FAILSAFE BRANCH ENTERED"
		echo "Exiting from function \"${FUNCNAME[0]}\" in script $(basename $0)"
		exit $E_OUT_OF_BOUNDS_BRANCH_ENTERED
	fi

	if [ $output_file_format == "ascii" ]
	then
		output_file_extension=".asc" #default
	elif [ $output_file_format == "binary" ]
	then
		output_file_extension=".gpg"
	else
		echo "FAILSAFE BRANCH ENTERED"
		echo "Exiting from function \"${FUNCNAME[0]}\" in script $(basename $0)"
		exit $E_OUT_OF_BOUNDS_BRANCH_ENTERED
	fi	


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

###############################################################################################
###############################################################################################
###############################################################################################
# [ PUBLIC KEY || SYMMETRIC ] && [ ASCII || BINARY ]
# MIGHT AS WELL ENUMERATE THE 4 POSSIBLE COMBINATIONS IN AN OPTION LIST! - (WITH A DEFAULT ASSUMED)
function set_file_encryption_mode # 
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	while true
	do

		## reset variables:
		mode_answer=""
		
		echo & echo
		echo & echo "::: [ PUBLIC KEY || SYMMETRIC ]  &&  [ ASCII || BINARY ] :::"
		echo & echo ":::  JUST PRESS ENTER FOR DEFAULT [PUBLIC KEY && ASCII]  :::"
		echo & echo

		read mode_answer

		case $mode_answer in
		[1])	# public key && ascii
				set_defaults
				break
				;;
		[2])	# public-key && binary
				:
				continue
				;;
		[3])	# symmetric && ascii
				:
				continue
				;;
		[4]) 	# symmetric && binary
				:
				continue
				;;
		*) 		echo "Normally, we'd just enter 1 - 4..." && sleep 1
				echo "USING THE DEFAULT..." && sleep 1
				set_defaults
				break
				;;
		esac 

	done

	echo
	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

###############################################################################################
# list the keys available on the system
# get the users' gpg user-id 
# test that valid, ultimate trust fingerprint exists for that user-id
function check_gpg_user_keys
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	userid=""

	# issue gpg commands to list keys for now... just as a prompt of user-id details
	bash -c "gpg --list-key"
	bash -c "gpg --list-secret-keys"

	# get the users' gpg UID from terminal
	echo "Enter your user-id (example: order@entropism.org)"

	read userid

	# now check for a key-pair fingerprint. TODO: if not found, user should have the opportunity to try again
	# TODO: THIS IS NOT THE RIGHT TEST, FIND SOMETHING BETTER LATER
	bash -c "gpg --fingerprint "$userid" 2>/dev/null" # suppress stderr (but not stdout for now)
	if [ $? -eq 0 ]
	then
		echo "KEY-PAIR FINGERPRINT IDENTIFIED FOR USER-ID OK"
	else
		echo "FAILED TO FIND THE KEY-PAIR FINGERPRINT FOR THAT USER-ID"
		# -> exit due to failure of any of the above tests:
		echo "Exiting from function \"${FUNCNAME[0]}\" in script $(basename $0)"
		exit $E_REQUIRED_PROGRAM_NOT_FOUND
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

########################################################################################## 
###############################################################################################
# CODE TO ENCRYPT A SET OF FILES:
###############################################################################################

function gpg_file_encryption_service
{

	# 5. BASED ON PREVIOUSLY SELECTED SERVICE OPTION, CALL AN APPROPRIATE SCRIPT (although we'll do stuff here for now)

	# sets the generic_command global
	#create a generic file encryption command string for either public key or symmetric key encryption:

	encrypt_result=
	# 
	check_gpg_user_keys # from user

	set_file_encryption_mode

	if [ $encryption_system = "public_key" ]
	then
		echo "encrytion_system is set to public-key, so we now need to request sender and recipient uids"

		get_sender_uid
		echo "sender user-id is now set to the value: $sender_uid"

		get_recipient_uid
		for recipient in ${recipient_uid_list[@]}
		do
			echo "From our array, a recipient is: ${recipient}"
		done

		create_generic_pub_key_encryption_command_string ## make this a public key specific one

	else # encryption_system must be symmetric [make this into an elif]
		create_generic_symmetric_key_encryption_command_string ##  make this a symmetric key specific one
	fi

	#create, then execute each file specific encryption command, then shred plaintext file:
	for valid_path in "${incoming_array[@]}"
	do
		echo "about to execute on file: $valid_path"
		execute_file_specific_encryption_command "$valid_path" #

		# check that expected output file now exists, is accessible and has expected encypted file properties
		verify_file_encryption_results "${valid_path}"
		encrypt_result=$?
		if [ $encrypt_result -eq 0 ]
		then
			echo && echo "SUCCESSFUL VERIFICATON OF ENCRYPTION encrypt_result: $encrypt_result"
		else			
			echo "FAILURE REPORT...ON STATE...encrypt_result: $encrypt_result"
			exit 1 ### NEED AN EXIT REASON CODE HERE
		fi	
	done

	# 6. SHRED THE PLAINTEXT FILES, NOW THAT ENCRYPTED VERSION HAVE BEEN MADE

	# first checking that the shred program is installed
	which shred #&> /dev/null
	if [ $? -eq 0 ]
	then
		shred_plaintext_files
		verify_file_shred_results		
	else
		echo "FAILED TO FIND THE SHRED PROGRAM ON THIS SYSTEM, SO SKIPPED SHREDDING OF ORIGINAL PLAINTEXT FILES"
	fi	

	return $encrypt_result

}


###############################################################################################
###############################################################################################

# check that the OpenPGP tool gpg is installed on the system
#  
function check_encryption_platform
{
		
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	bash -c "which gpg 2>/dev/null" # suppress stderr (but not stdout for now)
	if [ $? -eq 0 ]
	then
		echo "OpenPGP PROGRAM INSTALLED ON THIS SYSTEM OK"
	else
		echo "FAILED TO FIND THE REQUIRED OpenPGP PROGRAM"
		# -> exit due to failure of any of the above tests:
		echo "Exiting from function \"${FUNCNAME[0]}\" in script $(basename $0)"
		exit $E_REQUIRED_PROGRAM_NOT_FOUND
	fi


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

#########################################################################################################
###############################################################################################
##########################################################################################################
# FINAL OPERATION ON VALUE, SO GLOBAL test_line SET HERE. RENAME CONCEPTUALLY DIFFERENT test_line NAMESAKES
function sanitise_absolute_path_value ##
{

echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	# sanitise values
	# - trim leading and trailing space characters
	# - trim trailing / for all paths [effectively making dir paths and file paths have same form - useful for using common access test]
	test_line="${1}"
	echo "test line on entering "${FUNCNAME[0]}" is: $test_line" && echo

	# TRIM TRAILING AND LEADING SPACES AND TABS
	test_line=${test_line%%[[:blank:]]}
	test_line=${test_line##[[:blank:]]}

	# TRIM TRAILING / FOR ABSOLUTE PATHS:
    while [[ "$test_line" == *'/' ]]
    do
        echo "FOUND ENDING SLASH"
        test_line=${test_line%'/'}
    done 

	echo "test line after trim cleanups in "${FUNCNAME[0]}" is: $test_line" && echo

echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

##########################################################################################################
# A DUAL PURPOSE FUNCTION - CALLED TO EITHER TEST OR TO SET LINE TYPES:
# TESTS WHETHER THE LINE IS OF EITHER VALID comment, empty/blank OR string (variable or value) TYPE,
# SETS THE GLOBAL line_type AND test_line variableS.
function test_and_set_line_type
{

#echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	# TODO: ADD ANOTHER CONFIG FILE VALIDATION TEST:
	# TEST THAT THE LINE FOLLOWING A VARIABLE= ALPHANUM STRING MUST BE A VALUE/ ALPHANUM STRING, ELSE FAIL
	test_line="${1}"
	line_type=""

	#debug printouts:
	#echo "$test_line"

	if [[ "$test_line" == "#"* ]] # line is a comment (OR *"#"* in case space char before the # ? - try it)
	then
		line_type="comment"
		#echo "line_type set to: $line_type"
	elif [[ "$test_line" =~ [[:blank:]] || "$test_line" == "" ]] # line empty or contains only spaces or tab characters
	then
		line_type="empty"
		#echo "line_type set to: $line_type"
	elif [[ "$test_line" =~ [[:alnum:]] ]] # line is a string (not commented)
	then
		echo -n "Alphanumeric string  :  "
		if [[ "$test_line" == *"=" ]]
		then
			line_type="variable_string"
			echo "line_type set to: "$line_type" for "$test_line""
		elif [[ "$test_line" =~ $all_filepath_regex ]]	#
		then
			line_type="value_string"
			echo "line_type set to: "$line_type" for "$test_line""
		else
			echo "Failsafe : Couldn't match the Alphanum string"
			echo "Exiting from function ${FUNCNAME[0]} in script $(basename $0)"
			exit $E_UNEXPECTED_BRANCH_ENTERED
		fi

	else
		echo "Failsafe : Couldn't match this line with ANY line type!"
		echo "Exiting from function ${FUNCNAME[0]} in script $(basename $0)"
		exit $E_UNEXPECTED_BRANCH_ENTERED
	fi

#echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

##########################################################################################################
## VARIABLE 1:
function get_synchronised_location_holding_dir_fullpath_config
{

echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	keyword="synchronised_location_holding_dir_fullpath="
	line_type=""
	value_collection="OFF"

	while read lineIn
	do

		test_and_set_line_type "$lineIn" # interesting for the line FOLLOWING that keyword find

		if [[ $value_collection == "ON" && $line_type == "value_string" ]]
		then
			sanitise_absolute_path_value "$lineIn"
			echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
			echo "test_line has the value: $test_line"
			echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
			set -- $test_line # using 'set' to get test_line out of this subprocess into a positional parameter ($1)

		elif [[ $value_collection == "ON" && $line_type != "value_string" ]] 
		# assume last value has been collected for synchronised_location_holding_dir_fullpath
		then
			value_collection="OFF" # just because..
			break # end this while loop, as last value has been collected for synchronised_location_holding_dir_fullpath
		else
			# value collection must be OFF
			:
		fi
		
		
		# switch value collection ON for the NEXT line read
		# THEREFORE WE'RE ASSUMING THAT A KEYWORD CANNOT EXIST ON THE 1ST LINE OF THE FILE
		# THIS IS NOW ASSUMED TO BE FALSE WHEN IT WAS TRUE FOR LAST LINE (ie NEVER KEYWORDS ON CONSECUTIVE LINES) \
		# - COULD WE HAVE VALIDATED THE CONFIG FILE FOR THIS FOR THIS?
		if [[ "$lineIn" == "$keyword" ]]
		then
			value_collection="ON"
		fi

	done < "$config_file_fullpath"

	# ASSIGN
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	echo "test_line has the value: $1"
	echo "synchronised_location_holding_dir_fullpath has the value: $synchronised_location_holding_dir_fullpath"
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

	synchronised_location_holding_dir_fullpath="$1" # test_line just set globally in sanitise_absolute_path_value function
	set -- # unset that positional parameter we used to get test_line out of that while read subprocess
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	echo "test_line (AFTER set --) has the value: $1"
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"


echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

##########################################################################################################
## VARIABLE 2:
function get_public_keyring_default_directory_fullpath_config
{

echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	keyword="public_keyring_default_directory_fullpath="
	line_type=""
	value_collection="OFF"

	while read lineIn
	do

		test_and_set_line_type "$lineIn" # interesting for the line FOLLOWING that keyword find

		if [[ $value_collection == "ON" && $line_type == "value_string" ]]
		then
			sanitise_absolute_path_value "$lineIn"
			echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
			echo "test_line has the value: $test_line"
			echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
			set -- $test_line # using 'set' to get test_line out of this subprocess into a positional parameter ($1)

		elif [[ $value_collection == "ON" && $line_type != "value_string" ]] 
		# assume last value has been collected for public_keyring_default_directory_fullpath
		then
			value_collection="OFF" # just because..
			break # end this while loop, as last value has been collected for public_keyring_default_directory_fullpath
		else
			# value collection must be OFF
			:
		fi
		
		
		# switch value collection ON for the NEXT line read
		# THEREFORE WE'RE ASSUMING THAT A KEYWORD CANNOT EXIST ON THE 1ST LINE OF THE FILE
		# THIS IS NOW ASSUMED TO BE FALSE WHEN IT WAS TRUE FOR LAST LINE (ie NEVER KEYWORDS ON CONSECUTIVE LINES) \
		# - COULD WE HAVE VALIDATED THE CONFIG FILE FOR THIS FOR THIS?
		if [[ "$lineIn" == "$keyword" ]]
		then
			value_collection="ON"
		fi

	done < "$config_file_fullpath"

	# ASSIGN
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	echo "test_line has the value: $1"
	echo "public_keyring_default_directory_fullpath has the value: $public_keyring_default_directory_fullpath"
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

	public_keyring_default_directory_fullpath="$1" # test_line just set globally in sanitise_absolute_path_value function
	set -- # unset that positional parameter we used to get test_line out of that while read subprocess
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	echo "test_line (AFTER set --) has the value: $1"
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"


echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

##########################################################################################################
## VARIABLE 3:
function get_revocation_certificate_default_directory_fullpath_config
{

echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	keyword="revocation_certificate_default_directory_fullpath="
	line_type=""
	value_collection="OFF"

	while read lineIn
	do

		test_and_set_line_type "$lineIn" # interesting for the line FOLLOWING that keyword find

		if [[ $value_collection == "ON" && $line_type == "value_string" ]]
		then
			sanitise_absolute_path_value "$lineIn"
			echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
			echo "test_line has the value: $test_line"
			echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
			set -- $test_line # using 'set' to get test_line out of this subprocess into a positional parameter ($1)

		elif [[ $value_collection == "ON" && $line_type != "value_string" ]] 
		# assume last value has been collected for revocation_certificate_default_directory_fullpath
		then
			value_collection="OFF" # just because..
			break # end this while loop, as last value has been collected for revocation_certificate_default_directory_fullpath
		else
			# value collection must be OFF
			:
		fi
		
		
		# switch value collection ON for the NEXT line read
		# THEREFORE WE'RE ASSUMING THAT A KEYWORD CANNOT EXIST ON THE 1ST LINE OF THE FILE
		# THIS IS NOW ASSUMED TO BE FALSE WHEN IT WAS TRUE FOR LAST LINE (ie NEVER KEYWORDS ON CONSECUTIVE LINES) \
		# - COULD WE HAVE VALIDATED THE CONFIG FILE FOR THIS FOR THIS?
		if [[ "$lineIn" == "$keyword" ]]
		then
			value_collection="ON"
		fi

	done < "$config_file_fullpath"

	# ASSIGN
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	echo "test_line has the value: $1"
	echo "revocation_certificate_default_directory_fullpath has the value: $revocation_certificate_default_directory_fullpath"
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

	revocation_certificate_default_directory_fullpath="$1" # test_line just set globally in sanitise_absolute_path_value function
	set -- # unset that positional parameter we used to get test_line out of that while read subprocess
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	echo "test_line (AFTER set --) has the value: $1"
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"


echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

##########################################################################################################
##########################################################################################################

# firstly, we test that the parameter we got is of the correct form for an absolute file | sanitised directory path 
# if this test fails, there's no point doing anything further
# 
function test_file_path_valid_form
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	test_file_fullpath=$1
	
	echo "test_file_fullpath is set to: $test_file_fullpath"
	#echo "test_dir_fullpath is set to: $test_dir_fullpath"

	if [[ $test_file_fullpath =~ $abs_filepath_regex ]]
	then
		echo "THE FORM OF THE INCOMING PARAMETER IS OF A VALID ABSOLUTE FILE PATH"
		test_result=0
	else
		echo "PARAMETER WAS NOT A MATCH FOR OUR KNOWN PATH FORM REGEX: "$abs_filepath_regex"" && sleep 1 && echo
		echo "Returning with a non-zero test result..."
		test_result=1
		return $E_UNEXPECTED_ARG_VALUE
	fi 


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	return "$test_result"
}

###############################################################################################
# test for read access to file 
# 
function test_file_path_access
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	test_file_fullpath=$1

	echo "test_file_fullpath is set to: $test_file_fullpath"

	# test for expected file type (regular) and read permission
	if [ -f "$test_file_fullpath" ] && [ -r "$test_file_fullpath" ]
	then
		# test file found and accessible
		echo "Test file found to be readable" && echo
		test_result=0
	else
		# -> return due to failure of any of the above tests:
		test_result=1 # just because...
		echo "Returning from function \"${FUNCNAME[0]}\" with test result code: $E_REQUIRED_FILE_NOT_FOUND"
		return $E_REQUIRED_FILE_NOT_FOUND
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	return "$test_result"
}
###############################################################################################
# test for access to the file holding directory
# # TODO: DO WE NEED ANOTHER TEST FOR PERMISSION TO WRITE TO DIRECTORY?
function test_dir_path_access
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	test_dir_fullpath=$1

	echo "test_dir_fullpath is set to: $test_dir_fullpath"

	if [ -d "$test_dir_fullpath" ] && cd "$test_dir_fullpath" 2>/dev/null
	then
		# directory file found and accessible
		echo "directory "$test_dir_fullpath" found and accessed ok" && echo
		test_result=0
	else
		# -> return due to failure of any of the above tests:
		test_result=1
		echo "Returning from function \"${FUNCNAME[0]}\" with test result code: $E_REQUIRED_FILE_NOT_FOUND"
		return $E_REQUIRED_FILE_NOT_FOUND
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	return "$test_result"
}
###############################################################################################
#########################################################################################################
## SET GLOBAL VARIABLE service_index WRT A SPECIFIC SERVICE
# CALL THE FUNCTIONS AND SCRIPTS THAT COMBINE TO PROVIDE THE REQUESTED SERVICE
# 
function get_required_service
{
	
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	
	while true
	do
		
		service_option=""
		
		echo
		echo ">>>   :::   SELECT [SERVICE]   :::" # use cases
		echo
		echo 
		echo ">>>   [1] = GPG ENCRYPT one or more plaintext files"
		echo 
		echo ">>>   [2] = GPG DECRYPT one or more encrypted files"
		echo
		echo ">>>   [3] = GENERATE a new GPG public key encryption key-pair and MANAGE keys and certificates"
		echo
		echo ">>>   [4] = IMPORT GPG public key and backup keyring"
		echo
		echo ">>>   [5] = GPG ENCRYPT and SIGN one or more documents"
		echo
		echo ">>>   [6] = REVOKE a key and PUBLISH revoked"
		echo
		echo ">>>   [Q/q] = QUIT, leave, return contRol and exeet"
		echo
		echo
		echo ">>>   :::   THE FOLLOWING OPERATIONS BEST DONE MANUALLY, NOT BY THIS PROGRAM   :::" # use cases
		echo
		echo ">>>   [NULL] = IMPORTING public keys into keyrings"
		echo ">>>   [NULL] = SIGNING of imported keys using our private keys"
		echo ">>>   [NULL] = ...."
		echo

		read service_option

		echo "user has selected option: $service_option"

		case $service_option in
		1)		# gpg file encryption service:
				service_index=1
				echo "YOU REQUESTED THE GPG FILE ENCRYPTION SERVICE"

				# NOW WE MUST CHECK FOR PRE-REQUISITES:
				# does incoming_array have one or more elements?
				# ...
				if [ ${#incoming_array[@]} -gt 0 ]
				then
					gpg_file_encryption_service
					# result_code=$?
				else
					# this will soon be possible!
					echo "TRIED TO DO FILE ENCRYPTION WITHOUT ANY INCOMING FILEPATH PARAMETERS"	
					exit "$E_INCORRECT_NUMBER_OF_ARGS"
				fi
				break
				;;

		2)		# gpg decryption:
				service_index=2
				echo "YOU REQUESTED THE GPG FILE DECRYPTION SERVICE"
				continue
				;;

		3)		# generate gpg public-key encryption key-pair and manage keys, keyrings and certificates:
				# backup public keyring
				# generate revocation certificate
				# encrypt and backup revocation certificate
				# backup exported public key
				service_index=3
				echo "YOU REQUESTED THE GPG PUBLIC KEY AND REVOCATION CERTIFICATE BACKUP SERVICE" && echo

				generate_and_manage_keys
				break				
				;;

		4)		# import GPG public key and backup keyring:
				service_index=4
				echo "YOU REQUESTED THE GPG PUBLIC KEY IMPORT AND KEYRING BACKUP SERVICE"
				continue
				;;

		5)		# gpg document encryption and signing:
				service_index=5
				echo "YOU REQUESTED THE GPG DOCUMENT ENCRYPTION AND SIGNING SERVICE"
				continue
				;;

		[Qq])	echo && echo "Goodbye!" && sleep 1
				exit 0
				;;

		*)		# DEFAULT (FAILSAFE) CASE:
				echo "Just a simple 1-5 will do..." && sleep 2
				service_index=0
				continue
				;;
		esac 

	done


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

#########################################################################################################
# IF USE CASES FOR THE COEXISTENCE OF DIFFERENT CONFIGURATION FILES EVER ARISES
# WE CAN USE THIS FUNCTION TO USER OPTIONS:
# USE OPTION MENU, THE $REPLY VARIABLE... FOR BETTER INTERACTION
function get_config_file_to_use
{
	## 
	echo
	echo ":::   [ USING THE DEFAULT CONFIGURATION FILE ]   :::"
	echo
	sleep 2
}
###############################################################################################

main "$@"; exit


# TODO:
# CREATE AND PUSH FLOWCHART ALGORITHM FOR COMMAND GENERATION FUNCTIONS (AN IGNORE FILE)
# CREATE CONFIGURATION IMPORT FUNCTIONS
# CALL SEPARATE SCRIPT FOR EACH DISTINCT SERVICE
# CREATE THE PUBLIC-KEY BACKUP FUNCTIONALITY SCRIPT

# UPDATE THE README.md TO ADD A PRE-REQUISITES SECTION

# UPDATE TO USE OF OPTION SELECTION FUNCTION IF APPROPRIATE


# .. don't forget to unset when returning to calling program

###############################################################################################

## USE CASE - CALLED BY audit_list_maker TO GPG ENCRYPT A SINGLE FILE

# FOR ENCRYPTION OF A SINGLE FILE, ALL es EVER NEEDS TO BE PASSED AS A PARAMETER IS THE ABSOLUTE PATH FILENAME OF THE 
# PLAINTEXT FILE. IT CAN GET EVERYTHING ELSE IT NEEDS EITHER FROM CONFIGURATION FILE DEFAULTS, OR FROM THE USER.
#

# decides whether being called directly or by another script

# takes in, validates and assigns the plaintext filename parameter

# tests its environment - config files, `which gpg`, public key-pair pre-generated...


# gets  and validates any unknown required parameters from the user - sender, recipient UID (based on `hostname`) \
#  if using public key encryption - ANY DEFAULTS FOR THIS COULD BE IN A CONFIGURATION FILE FOR THIS PROGRAM
	# - cryptographic system to be used (whether public key or symmetric key crypto)
	# - the output format whether the binary default for gpg or ascii armoured
	# - the desired output filename for the encrypted file (full path): [DEFAULT = SAME AS INPUT WITH .asc|.pgp]

# if all good, es shows user the command it wants to execute
# $ gpg --armor --output "$plaintext_file_fullpath.asc" --local-user <uid> recipient <uid> --encrypt "$plaintext_file_fullpath"

# if user give ok, es executes the command(s)

# es tests resulting postconditions#

# es reports success to user and returns control

###############################################################################################


#ssh hostname ## this command likely to be read in from file

## definitely control the hosts on which this program can run
#
# hostname will determine which ssh code runs
#

###############################################################################################

# these files need to be backed up and encrypted:
#public keyrings such as:
#~/.gnupg/pubring.gpg 
#~/.gnupg/pubring.kbx
#
#these revocation certs need to be CIA stored, so backup and encryption as well as on separate media
#~/.gnupg/opengpg_revocs.d/
#
#integration with existing system may look like:
#- an option to run this script post-shred an pre-mutables synchronisation

###############################################################################################

# tests whether parameter in of type array, if true returns 0, else returns 1
# declare -a ## returns list of all the current array variables
# grepping with our array works, but not 100% clear on mechanism...	
# TODO: TURN THIS INTO A GENERAL PURPOSE type_array_test FUNCTION IF IT IS NEEDED AGAIN
#declare -a | grep "${incoming_parameter}" 2> /dev/null ##
#if [ $? -eq 0 ]
#then
#	echo "THE INCOMING PARAMETER WAS OF TYPE ARRAY"
#	incoming_array=("${incoming_parameter[@]}")
#else
#	echo "The incoming parameter was NOT of type ARRAY"
#fi
#
#echo ${incoming_parameter[@]}
#
## test whether incoming parameter is of type string
#
#
#
#for ((index=0; index<$number_of_incoming_params; index++));
#	do	
#		position=$((index + 1))
#		echo "position is set to: $position"
#		incoming_array[$index]=${postition}
#	done