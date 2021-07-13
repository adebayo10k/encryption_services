#!/bin/bash
#: Title		:file-encrypter.sh
#: Date			:2019-11-14
#: Author		:adebayo10k
#: Version		:1.0
#: Description	:script provides encryption services both to other scripts  
#: Description	:and to the command-line user.  
#: Description	:to gpg encrypt one or more files passed in as program arguments.
#: Description	:
#: Description	: 
#: Description	:
#: Options		:
##

##################################################################
##################################################################
# THIS STUFF IS HAPPENING BEFORE MAIN FUNCTION CALL:
#===================================

# 1. MAKE SHARED LIBRARY FUNCTIONS AVAILABLE HERE

# make all the shared library functions available to this script
shared_bash_functions_fullpath="${SHARED_LIBRARIES_DIR}/shared-bash-functions.sh"
shared_bash_constants_fullpath="${SHARED_LIBRARIES_DIR}/shared-bash-constants.inc.sh"

for resource in "$shared_bash_functions_fullpath" "$shared_bash_constants_fullpath"
do
	if [ -f "$resource" ]
	then
		echo "Required library resource FOUND OK at:"
		echo "$resource"
		source "$resource"
	else
		echo "Could not find the required resource at:"
		echo "$resource"
		echo "Check that location. Nothing to do now, except exit."
		exit 1
	fi
done


# 2. MAKE SCRIPT-SPECIFIC FUNCTIONS AVAILABLE HERE

# must resolve canonical_fullpath here, in order to be able to include sourced function files BEFORE we call main, and  outside of any other functions defined here, of course.

# at runtime, command_fullpath may be either a symlink file or actual target source file
command_fullpath="$0"
command_dirname="$(dirname $0)"
command_basename="$(basename $0)"

# if a symlink file, then we need a reference to the canonical file name, as that's the location where all our required source files will be.
# we'll test whether a symlink, then use readlink -f or realpath -e although those commands return canonical file whether symlink or not.
# 
canonical_fullpath="$(readlink -f $command_fullpath)"
canonical_dirname="$(dirname $canonical_fullpath)"

# this is just development debug information
if [ -h "$command_fullpath" ]
then
	echo "is symlink"
	echo "canonical_fullpath : $canonical_fullpath"
else
	echo "is canonical"
	echo "canonical_fullpath : $canonical_fullpath"
fi

# included source files for json profile import functions
source "${canonical_dirname}/preset-profile-builder.inc.sh"


# THAT STUFF JUST HAPPENED (EXECUTED) BEFORE MAIN FUNCTION CALL!
##################################################################
##################################################################


function main
{	
	#######################################################################
	# GLOBAL VARIABLE DECLARATIONS:
	#######################################################################

	actual_host=$(hostname)
	unset authorised_host_list
	declare -a authorised_host_list=($HOST_0065 $HOST_0054 $HOST_R001 $HOST_R002)  # allow | deny
	if [[ $(declare -a | grep 'authorised_host_list' 2>/dev/null) ]]
	then
		entry_test
	fi

	no_of_program_parameters=$#
	tutti_param_string="$@"
	#echo $tutti_param_string
	declare -a incoming_array=()

	declare -i max_expected_no_of_program_parameters=0
	declare -i min_expected_no_of_program_parameters=0
	declare -ir actual_no_of_program_parameters=$#
	all_the_parameters_string="$@"

	program_title=""
	original_author=""
	program_dependencies=(jq cowsay vi shred gpg)

	################################################

	declare -a profile_keys_indexed_array=()
	declare -A profile_key_value_assoc_array=()

	# independent variables
	encryption_system= # public_key | symmetric_key
	output_file_format= # ascii | binary
	profile_name=
	profile_description=

	# dependent variables
	encryption_system_option= # --encrypt | --symmetric
	output_file_extension= # .asc | .gpg

	armor_option='--armor'
	sender_option='--local-user'
	recipient_option='--recipient'
	sender_uid=""
	#recipient_uid=""
	declare -a recipient_uid_list=()

	################################################

	gpg_command='gpg'
	output_option='--output'
	file_path_placeholder='<filepath_placeholder>'

	generic_command=""
	file_specific_command=""

	##################################################

	################################################################
	# 'SHOW STOPPER' CHECKING FUNCTION CALLS:	
	################################################################

	# check program dependencies and requirements
	check_program_requirements "${program_dependencies[@]}"

	# verify and validate program positional parameters
	verify_and_validate_program_arguments

	
	###############################################################################################
	# $SHLVL DEPENDENT FUNCTION CALLS:	
	###############################################################################################

	# using $SHLVL to show whether this script was called from another script, or from command line
	echo "OUR CURRENT SHELL LEVEL IS: $SHLVL"

	if [ $SHLVL -le 4 ]
	then
		# Display a descriptive and informational program header:
		display_program_header

		# give user option to leave if here in error:
		get_user_permission_to_proceed
	fi


	###############################################################################################
	# FUNCTIONS CALLED ONLY IF THIS PROGRAM USES A CONFIGURATION FILE:	
	###############################################################################################

	if [ -n "$config_file_fullpath" ]
	then
		:
	fi

	###############################################################################################
	# PROGRAM-SPECIFIC FUNCTION CALLS:	
	###############################################################################################	

	# IMPORT CONFIGURATION INTO PROGRAM VARIABLES
	import_file_encryption_configuration

	echo "profile_name: $profile_name"
	echo && echo
	echo "profile_description: $profile_description"
	echo && echo
	echo "output_file_format: $output_file_format"
	echo && echo
	echo "encryption_system: $encryption_system"
	echo && echo
	echo "sender_uid: $sender_uid"
	echo && echo
	echo "recipient_uid_list:"	
	echo "${recipient_uid_list[@]}"
	echo && echo
	echo "recipient_uid_list size:"
	echo "${#recipient_uid_list[@]}"
	echo && echo
	
	# CHECK THE STATE OF THE ENCRYPTION ENVIRONMENT:
	check_encryption_platform

	# issue gpg commands to list keys for now... just to see what's there
	bash -c "gpg --list-key"
	bash -c "gpg --list-secret-keys"

	if [ ${#incoming_array[@]} -gt 0 ]
	then
		gpg_encrypt_files
		# result_code=$?
	else
		# this will soon be possible!
		msg="TRIED TO DO FILE ENCRYPTION WITHOUT ANY INCOMING FILEPATH PARAMETERS. Exiting now..."
		lib10k_exit_with_error "$E_INCORRECT_NUMBER_OF_ARGS" "$msg"
	fi
	
	
	# 7. ON RETURN OF CONTROL, CHECK FOR DESIRED POSTCONDITIONS
	echo "file-encrypter exit code: $?" 

} ## end main


###############################################################################################
####  FUNCTION DECLARATIONS  
###############################################################################################

function verify_and_validate_program_arguments()
{
#
	# 1. VALIDATE ANY ARGUMENTS HAVE BEEN PASSED INTO THIS SCRIPT
	echo "Number of arguments passed in = $no_of_program_parameters"

	# if one or more args put them into an array 
	if [ $no_of_program_parameters -gt 0 ]
	then
		#echo "IFS: -$IFS+"
		incoming_array=( $tutti_param_string )
		echo "incoming_array[@]: ${incoming_array[@]}"
		verify_program_args
	else
		msg="Incorrect number of command line arguments. Exiting now..."
		lib10k_exit_with_error "$E_INCORRECT_NUMBER_OF_ARGS" "$msg"
	fi

}

################################################################
# program expected one or more absolute paths to plaintext files to be encrypted
# this was checked at start, and the incoming_array created.
# this function now does the file path tests on each of them...
function verify_program_args
{
	# 2. VERIFY THAT ALL INCOMING ARGS ARE VALID AND ACCESSIBLE FILE PATHS 

	# give user the opportunity to confirm argument values?
	# get rid of this if feels like overkill
	echo "incoming_array is of size: ${#incoming_array[@]}" && echo
	for incoming_arg in "${incoming_array[@]}"
	do
		echo "$incoming_arg" && echo
	done
	
	# if any of the args is not in the form of an absolute file path, exit program.
	for incoming_arg in "${incoming_array[@]}"
	do
		echo "incoming argument is now: $incoming_arg"
		test_file_path_valid_form "$incoming_arg"
		return_code=$?
		if [ $return_code -eq 0 ]
		then
			echo $incoming_arg
			echo "VALID FORM TEST PASSED" && echo
		else
			msg="The valid form test FAILED and returned: $return_code. Exiting now..."
			lib10k_exit_with_error "$E_UNEXPECTED_ARG_VALUE" "$msg"
		fi
	done
	
	# if any of the args is not a readable, regular file, exit program
	for incoming_arg in "${incoming_array[@]}"
	do			
		test_file_path_access "$incoming_arg"
		return_code=$?
		if [ $return_code -eq 0 ]
		then
			echo "The full path to the plaintext file is: $incoming_arg"
			echo "REGULAR FILE READ TEST PASSED" && echo
		else
			msg="The file path access test FAILED and returned: $return_code. Exiting now..."
			lib10k_exit_with_error "$E_REQUIRED_FILE_NOT_FOUND" "$msg"
		fi
	done
	
	for incoming_arg in "${incoming_array[@]}"
	do
		#plaintext_dir_fullpath=${incoming_arg%/*}
		#plaintext_dir_fullpath=$(echo $plaintext_file_fullpath | sed 's/\/[^\/]*$//') ## also works
		plaintext_dir_fullpath=$(dirname ${incoming_arg})
		test_dir_path_access "$plaintext_dir_fullpath"
		return_code=$?
		if [ $return_code -eq 0 ]
		then
			echo "The full path to the plaintext file holding directory is: $plaintext_dir_fullpath"
			echo "HOLDING DIRECTORY ACCESS READ TEST PASSED" && echo
		else
			msg="The directory path access test FAILED and returned: $return_code. Exiting now..."
			lib10k_exit_with_error "$E_REQUIRED_FILE_NOT_FOUND" "$msg"
		fi
	done

}
##########################################################################################################
###########################################################################################################
# returns zero if 
function test_email_valid_form
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	test_result=
	test_email=$1
	
	echo "test_email is set to: $test_email"

	if [[ $test_email =~ $EMAIL_REGEX ]]
	then
		echo "THE FORM OF THE INCOMING PARAMETER IS OF A VALID EMAIL ADDRESS"
		test_result=0
	else
		echo "PARAMETER WAS NOT A MATCH FOR OUR KNOWN EMAIL FORM REGEX: "$EMAIL_REGEX"" && sleep 1 && echo
		echo "Returning with a non-zero test result..."
		test_result=1
		return $E_UNEXPECTED_ARG_VALUE
	fi 


	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

	return "$test_result"
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
		shred -n 1 -ufv "${valid_path}"	
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

	# COMMAND FORM:
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

	echo "OK, WE'RE HERE, READY TO BUILD THAT GENERIC COMMAND STRING"

	# THIS IS THE FORM:
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
#
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
#
#################################################################################################
## 
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
#
###############################################################################################
#
function set_command_parameters
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	if [ $output_file_format == "ascii" ]
	then
		output_file_extension=".asc" #default
	elif [ $output_file_format == "binary" ]
	then
		output_file_extension=".gpg"
	else
		msg="FAILSAFE BRANCH ENTERED. Exiting now..."
		lib10k_exit_with_error "$E_OUT_OF_BOUNDS_BRANCH_ENTERED" "$msg"
	fi	

	if [ $encryption_system == "public_key" ]
	then
		echo "encrytion_system is set to public-key"
		encryption_system_option='--encrypt'

		#get_sender_uid
		#echo "sender user-id is now set to the value: $sender_uid"
		#
		#get_recipient_uid
		#for recipient in ${recipient_uid_list[@]}
		#do
		#	echo "From our array, a recipient is: ${recipient}"
		#done

		create_generic_pub_key_encryption_command_string

	elif [ $encryption_system == "symmetric_key" ]
	then
		echo "encrytion_system is set to symmetric-key"
		encryption_system_option='--symmetric'

		create_generic_symmetric_key_encryption_command_string

	else
		msg="FAILSAFE BRANCH ENTERED. Exiting now..."
		lib10k_exit_with_error "$E_OUT_OF_BOUNDS_BRANCH_ENTERED" "$msg"
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo
}
###############################################################################################
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
	echo "To make sure you have keys here with which to ENCRYPT, we'll just look for a FINGERPRINT for your USER-ID" && echo
	echo "Enter your user-id (example: order@entropism.org)"

	read userid && echo

	# now check for a key-pair fingerprint. TODO: if not found, user should have the opportunity to try again
	# TODO: THIS IS NOT THE RIGHT TEST, FIND SOMETHING BETTER LATER
	bash -c "gpg --fingerprint "$userid" 2>/dev/null" # suppress stderr (but not stdout for now)
	if [ $? -eq 0 ]
	then
		echo "KEY-PAIR FINGERPRINT IDENTIFIED FOR USER-ID OK"
	else
		# -> exit due to failure of any of the above tests:
		msg="FAILED TO FIND THE KEY-PAIR FINGERPRINT FOR THAT USER-ID. Exiting now..."
		lib10k_exit_with_error "$E_REQUIRED_PROGRAM_NOT_FOUND" "$msg"
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo
}
########################################################################################## 
###############################################################################################
# CODE TO ENCRYPT A SET OF FILES:
###############################################################################################

function gpg_encrypt_files
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	# sets the generic_command global
	# create a generic file encryption command string for either public key or symmetric key encryption:

	encrypt_result=
	# 
	check_gpg_user_keys # from user
	
	echo "The value of encryption_system is set to: $encryption_system"
	echo "The value of output_file_format is set to: $output_file_format"
	echo "The value of sender_uid is set to: $sender_uid"

	for item in ${recipient_uid_list[@]}
	do
		echo "One value of recipient_uid_list is set to: $item"
	done

	# if ALL the config items set ok, then continue with this command, else abort
	set_command_parameters

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
			msg="FAILURE REPORT. Unexpected encrypt_result: $encrypt_result. Exiting now..."
			lib10k_exit_with_error "$E_UNKNOWN_ERROR" "$msg"
		fi	
	done

	# 6. SHRED THE PLAINTEXT FILES, NOW THAT ENCRYPTED VERSION HAVE BEEN MADE

	# first checking that the shred program is installed
	type shred > /dev/null 2>&1
	if [ $? -eq 0 ]
	then
		shred_plaintext_files
		verify_file_shred_results		
	else
		echo "FAILED TO FIND THE SHRED PROGRAM ON THIS SYSTEM, SO SKIPPED SHREDDING OF ORIGINAL PLAINTEXT FILES"
	fi	

	#return $encrypt_result # resulting from the last successful encryption only! So what use is that?

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo
}


###############################################################################################
###############################################################################################
# check that the OpenPGP tool gpg is installed on the system
#  
function check_encryption_platform
{		
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	type gpg > /dev/null 2>&1
	if [ $? -eq 0 ]
	then
		echo "OpenPGP PROGRAM INSTALLED ON THIS SYSTEM OK"
		# issue gpg commands to list keys for now... just to see what's there
		bash -c "gpg --list-key"
		bash -c "gpg --list-secret-keys"
	else
		# -> exit due to failure of any of the above tests:
		msg="FAILED TO FIND THE REQUIRED OpenPGP PROGRAM. Exiting now..."
		lib10k_exit_with_error "$E_REQUIRED_PROGRAM_NOT_FOUND" "$msg"
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo
}

#########################################################################################################

main "$@"; exit
