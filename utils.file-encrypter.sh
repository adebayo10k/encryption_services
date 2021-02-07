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

function main
{	
	# GLOBAL VARIABLE DECLARATIONS:

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

	###############################################################################################

	no_of_program_parameters=$#
	tutti_param_string="$@"

	echo $tutti_param_string

	
	config_file_fullpath="/etc/file-encrypter.config" # a full path to a file
	line_type="" # global...
	test_line="" # global...

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
	#recipient_uid=""
	declare -a recipient_uid_list=()

	################################################

	gpg_command='gpg'
	output_option='--output'
	file_path_placeholder='<filepath_placeholder>'

	generic_command=""
	file_specific_command=""

    abs_filepath_regex='^(/{1}[A-Za-z0-9\.\ _~:@-]+)+$' # absolute file path, ASSUMING NOT HIDDEN FILE, placing dash at the end!...
	all_filepath_regex='^(/?[A-Za-z0-9\.\ _~:@-]+)+$' # both relative and absolute file path
	email_regex='^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$'
	# ^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$
	# ^[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:].]{2,4}$ ]]

	##################################################

	# SET THE 'SCRIPT ROOT' DIRECTORY IN WHICH THIS SCRIPT CURRENTLY FINDS ITSELF
	# NOTE: if soft-linked from an executables PATH directory, this gives the path to the link
	echo "The absolute path to this script is:		$0"
	echo "Script root directory set to:		$(dirname $0)"
	echo "Script filename set to:			$(basename $0)" && echo

	###############################################################################################
		
	display_program_header	
	get_user_permission_to_proceed
	validate_program_args
	display_current_config_file
	get_user_config_edit_decision
	
	check_config_file_content

	# IMPORT CONFIGURATION INTO PROGRAM VARIABLES
	import_file_encryption_configuration
	
	# CHECK THE STATE OF THE ENCRYPTION ENVIRONMENT:
	#check_encryption_platform

	# issue gpg commands to list keys for now... just to see what's there
	bash -c "gpg --list-key"
	bash -c "gpg --list-secret-keys"

	if [ ${#incoming_array[@]} -gt 0 ]
	then
		gpg_encrypt_files
		# result_code=$?
	else
		# this will soon be possible!
		echo "TRIED TO DO FILE ENCRYPTION WITHOUT ANY INCOMING FILEPATH PARAMETERS"	
		exit "$E_INCORRECT_NUMBER_OF_ARGS"
	fi
	
	
	# 7. ON RETURN OF CONTROL, CHECK FOR DESIRED POSTCONDITIONS
	echo "file-encrypter exit code: $?" 

} ## end main







###############################################################################################
#### vvvvv FUNCTION DECLARATIONS  vvvvv
###############################################################################################
# 





####################################################################################################
function validate_program_args()
{
#
	# 1. VALIDATE ANY ARGUMENTS HAVE BEEN PASSED INTO THIS SCRIPT
	echo "Number of arguments passed in = $no_of_program_parameters"

	# if one or more args put them into an array 
	if [ $no_of_program_parameters -gt 0 ]
	then
		#echo "IFS: -$IFS+"
		incoming_array=( $tutti_param_string )
		echo "incoming_array[0]: ${incoming_array[0]}"
		echo "incoming_array[1]: ${incoming_array[1]}"
		echo "incoming_array[2]: ${incoming_array[2]}"
		verify_program_args
	else
		echo "Incorrect number of command line args. Exiting now..."
		echo "Usage: $(basename $0) [<absolute file path>...]"
		exit $E_INCORRECT_NUMBER_OF_ARGS
	fi

}

####################################################################################################
function display_program_header()
{
	echo "USAGE: $(basename $0) <[<absolute file path>...]" # one or more strings (representing fullpaths to files)

	echo "OUR CURRENT SHELL LEVEL IS: $SHLVL"

	# Display a program header and give user option to leave if here in error:
	echo
	echo -e "		\033[33m===================================================================\033[0m";
	echo -e "		\033[33m||            Welcome to the FILE ENCRYPTER UTILITY               ||  author: adebayo10k\033[0m";  
	echo -e "		\033[33m===================================================================\033[0m";
	echo
}

####################################################################################################
function get_user_permission_to_proceed()
{
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
}

####################################################################################################
function display_current_config_file()
{
	echo && echo CURRENT CONFIGURATION FILE...
	echo && sleep 1

	cat "$config_file_fullpath"
}

####################################################################################################
function get_user_config_edit_decision()
{
	echo " Edit configuration file? [Y/N]"
	echo && sleep 1

	read edit_config
	case $edit_config in 
	[yY])	echo && echo "Opening an editor now..." && echo && sleep 2
    		sudo nano "$config_file_fullpath" # /etc exists, so no need to test access etc.
    		# also, no need to validate config file path here, since we've just edited the config file!
				;;
	[nN])	echo
			echo " Ok, using the  current configuration" && sleep 1
				;;			
	*) 		echo " Give me a Y or N..." && echo && sleep 1
			get_user_config_edit_decision
				;;
	esac 
	
}

####################################################################################################
#
function import_file_encryption_configuration()
{

	echo
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	echo "STARTING THE 'IMPORT CONFIGURATION INTO VARIABLES' PHASE in script $(basename $0)"
	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
	echo

	read

	get_single_value_string_variables # ie encryption system, output file format and sender uid
	get_multiple_value_string_variables # ie recipient_uid_list

	# NOW DO ANY TESTS ON IMPORTED VALUES HERE.

}
##########################################################################################################
# test whether the configuration files' format is valid,
# and that each line contains something we're expecting
function check_config_file_content()
{
	while read lineIn
	do
		# any content problems handled in the test_and_set_line_type function:
        test_and_set_line_type "$lineIn"
        return_code="$?"
        echo "return code for tests on that line was: $return_code"
        if [ $return_code -eq 0 ]
        then
            # if tested line contained expected content
            # :
            echo "That line was expected!" && echo
        else
            echo "That line was NOT expected!"
            echo "Exiting from function \"${FUNCNAME[0]}\" in script \"$(basename $0)\""
            exit 0
        fi

	done < "$config_file_fullpath" 

}
##########################################################################################################
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
			echo "The valid form test FAILED and returned: $return_code"
			echo "Nothing to do now, but to exit..." && echo
			exit $E_UNEXPECTED_ARG_VALUE
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
			echo "The file path access test FAILED and returned: $return_code"
			echo "Nothing to do now, but to exit..." && echo
			exit $E_REQUIRED_FILE_NOT_FOUND
		fi
	done
	
	for incoming_arg in "${incoming_array[@]}"
	do
		plaintext_dir_fullpath=${incoming_arg%/*}
		#plaintext_dir_fullpath=$(echo $plaintext_file_fullpath | sed 's/\/[^\/]*$//') ## also works
		test_dir_path_access "$plaintext_dir_fullpath"
		return_code=$?
		if [ $return_code -eq 0 ]
		then
			echo "The full path to the plaintext file holding directory is: $plaintext_dir_fullpath"
			echo "HOLDING DIRECTORY ACCESS READ TEST PASSED" && echo
		else
			echo "The directory path access test FAILED and returned: $return_code"
			echo "Nothing to do now, but to exit..." && echo
			exit $E_REQUIRED_FILE_NOT_FOUND
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
		echo "FAILSAFE BRANCH ENTERED"
		echo "Exiting from function \"${FUNCNAME[0]}\" in script $(basename $0)"
		exit $E_OUT_OF_BOUNDS_BRANCH_ENTERED
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
		echo "FAILSAFE BRANCH ENTERED"
		echo "Exiting from function \"${FUNCNAME[0]}\" in script $(basename $0)"
		exit $E_OUT_OF_BOUNDS_BRANCH_ENTERED
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

	bash -c "which gpg 2>/dev/null" # suppress stderr (but not stdout for now)
	if [ $? -eq 0 ]
	then
		echo "OpenPGP PROGRAM INSTALLED ON THIS SYSTEM OK"
		# issue gpg commands to list keys for now... just to see what's there
		bash -c "gpg --list-key"
		bash -c "gpg --list-secret-keys"
	else
		echo "FAILED TO FIND THE REQUIRED OpenPGP PROGRAM"
		# -> exit due to failure of any of the above tests:
		echo "Exiting from function \"${FUNCNAME[0]}\" in script $(basename $0)"
		exit $E_REQUIRED_PROGRAM_NOT_FOUND
	fi

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

#########################################################################################################
##########################################################################################################
# keep sanitise functions separate and specialised, as we may add more to specific value types in future 
function sanitise_value ##
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	# sanitise values
	# - trim leading and trailing space characters
	test_line="${1}"
	echo "test line on entering "${FUNCNAME[0]}" is: $test_line" && echo

	# TRIM TRAILING AND LEADING SPACES AND TABS
	test_line=${test_line%%[[:blank:]]}
	test_line=${test_line##[[:blank:]]}

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
		elif [[ "$test_line" =~ $email_regex ]]	#
		then
			line_type="value_string"
			echo "line_type set to: "$line_type" for "$test_line""
		elif [[ "$test_line" =~ ^(public_key|symmetric_key|ascii|binary)$ ]]	#
		then
			line_type="value_string"
			echo "line_type set to: "$line_type" for "$test_line""
		else
            echo "line_type set to: \"UNKNOWN\" for "${test_line}""
			echo "Failsafe : Couldn't match the Alphanum string"
			return $E_UNEXPECTED_BRANCH_ENTERED
		fi
	else
	    echo "line_type set to: \"UNKNOWN\" for "$test_line""
		echo "Failsafe : Couldn't match this line with ANY line type!"
		return $E_UNEXPECTED_BRANCH_ENTERED
	fi

	#echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}
##########################################################################################################
# for any absolute file path value to be imported...
function get_single_value_string_variables
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	for keyword in "encryption_system=" "output_file_format=" "sender_uid="
	do
		line_type=""
		value_collection="OFF"

		while read lineIn
		do
			test_and_set_line_type "$lineIn" # interesting for the line FOLLOWING that keyword find

			if [[ $value_collection == "ON" && $line_type == "value_string" ]]
			then
				sanitise_value "$lineIn"
				echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
				echo "test_line has the value: $test_line"
				echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
				set -- $test_line # using 'set' to get test_line out of this subprocess into a positional parameter ($1)

			elif [[ $value_collection == "ON" && $line_type != "value_string" ]]
			# last value has been collected for this holding directory
			then
				value_collection="OFF" # just because..
				break # end this while loop, as last value has been collected for this holding directory
			else
				# value collection must be OFF
				:
			fi			
			
			# switch value collection ON for the NEXT line read
			# THEREFORE WE'RE ASSUMING THAT A KEYWORD CANNOT EXIST ON THE 1ST LINE OF THE FILE
			if [[ "$lineIn" == "$keyword" ]]
			then
				value_collection="ON"
			fi

		done < "$config_file_fullpath"

		# test_line was just set globally in sanitise_absolute_path_value function
		# ASSIGN
		echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
		echo "test_line has the value: $1"
		echo "the keyword on this for-loop is set to: $keyword"
		echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

		
		if [ "$keyword" == "encryption_system=" ]
		then
			encryption_system="$1"			
		elif [ "$keyword" == "output_file_format=" ]
		then
			output_file_format="$1"
		elif [ "$keyword" == "sender_uid=" ]
		then
			sender_uid="$1"
		else
			echo "Failsafe branch entered"
			exit $E_UNEXPECTED_BRANCH_ENTERED
		fi

		set -- # unset that positional parameter we used to get test_line out of that while read subprocess
		echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
		echo "test_line (AFTER set --) has the value: $1"
		echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

	done

	echo && echo "LEAVING FROM FUNCTION ${FUNCNAME[0]}" && echo

}

##########################################################################################################
## 
function get_multiple_value_string_variables
{
	echo && echo "ENTERED INTO FUNCTION ${FUNCNAME[0]}" && echo

	keyword="recipient_uid_list="

	# NOW MULTIPLE LINE VALUES ASSIGNED TO ARRAY ELEMENT, SO BIT DIFFERENCE LOGIC
	line_type=""
	value_collection="OFF"
	# unset path_list?
	declare -a uid_list=() # local array to store one or more sanitised recipient uids

	while read lineIn
	do

		test_and_set_line_type "$lineIn" # interesting for the line FOLLOWING that keyword find

		if [[ "$value_collection" == "ON" && "$line_type" == "value_string" ]]
		then
			
			sanitise_value "$lineIn"
			uid_list+=("${test_line}")
			# Not sure why we CAN access test_line here, when we had to use 'set' in the other functions?!?
			# Seems to work ok, so no complaining.
			
		elif [[ "$value_collection" == "ON" && "$line_type" != "value_string" ]] # last value has been collected for ...
		then
			
			value_collection="OFF" # just because..
			break # end this while loop, as last value has been collected for ....y
		else
			# value collection must be OFF
			:
		fi
				
		# switch value collection ON for the NEXT line read
		# THEREFORE WE'RE ASSUMING THAT A KEYWORD CANNOT EXIST ON THE 1ST LINE OF THE FILE
		if [[ "$lineIn" == "$keyword" ]]
		then
			value_collection="ON"
		fi
		
	done < "$config_file_fullpath"

	## debug7..
	echo && echo "The values in the uid_list array just before it's cloned by the recipient_uid_list array:"
	for value in "${uid_list[@]}"
	do
		echo -n "$value "

	done

	# ASSIGN THE LOCAL ARRAY BY CLONING
	recipient_uid_list=("${uid_list[@]}")

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
#########################################################################################################

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

## USE CASE - CALLED BY audit-list-maker.sh TO GPG ENCRYPT A SINGLE FILE

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

# tests whether parameter is of type array, if true returns 0, else returns 1
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
