#!/bin/bash

# this function imports the json profile data and then structures
# it into the specific array profile needed by the main file encrypter functions

function import_file_encryption_configuration () 
{
	config_file_fullpath="${HOME}/.config/gpg-encrypt-profiles.json" # a full path to a file

	echo "config_file_fullpath set to $config_file_fullpath"

	# NOTES ON THE jq PROGRAM:
	#==================  
	# the -r option returns unquoted, line-separated string
	# the -j option gives unquoted and no newline
	# no option gives quoted, line-separated strings

	# values that are returned by jq as 'concatenated strings to be arrayed' get an IFS.
	# single string values don't. 
	 # conveniently, the same sed command is applied to both (all) cases though!
	# therefore, for consistent handling, everything was single-quoted.

	
	# IMPORT PROFILE KEY ATTRIBUTES FROM JSON AS A SINGLE IFS STRING:
	#=========================================

	profile_id_string=$(cat "$config_file_fullpath" | jq -r '.[] | .profileID') 
	echo "profile_id_string:"
	echo -e "$profile_id_string"
	echo && echo

	# put the keys into and indexed array and then loop over it to filter for each profile 
	# data, one profile at a time

	#OIFS=$IFS
	#IFS='|'

	profile_id_array=( $profile_id_string )
	echo "profile_id_array:"
	echo "${profile_id_array[@]}"
	echo && echo
	echo "profile_id_array size:"
	echo "${#profile_id_array[@]}"
	echo && echo



	#IFS=$OIFS

	for profile_id in "${profile_id_array[@]}"
	do
		echo "profile_id: $profile_id" && echo && echo
		store_profiles "$profile_id"
	done

	# get user preset profile choice | direct parameter input (implement later)
	get_user_profile_choice
	chosen_profile_id=$?
	echo "chosen_profile_id : $chosen_profile_id"

	exit 0

	# assign profile property values to variables for gpg encryption command
	assign_chosen_profile_values

}

##########################################################
# 
# store each retrieved profile as structured data in memory.
# this avoids going back to read from disk.
# use and indexed array to iterate and assoc array for data var => value
# need to contrive a primary key across these two arrays
# indexed array:
#=========
# 0	=>	"1:profile_name"
# 1	=>	"1:profile_description"
# 2	=>	"1:encryption_system"
#...
# associative array:
#===========
# "1:profile_name"			=>			"1"	
# "1:profile_description"	=>			"local administration"
# "1:encryption_system"	=>			"public key"
#...
function store_profiles()
{
	#read

	id="$1"	
	# the unique profile identifier (aka profile_id)
	id="${id}"
	echo -e "unique id to FILTER from JSON: $id" 

	profile_name_string=$(cat "$config_file_fullpath" | jq -r --arg profile_id "$id" '.[] | select(.profileID==$profile_id) | .profileName') 
	echo "profile_name_string:"
	echo -e "$profile_name_string"
	echo && echo



	profile_description_string=$(cat "$config_file_fullpath" | jq -r --arg profile_id "$id" '.[] | select(.profileID==$profile_id) | .profileDescription') 
	echo "profile_description_string:"
	echo -e "$profile_description_string"
	echo && echo

	encryption_system_string=$(cat "$config_file_fullpath" | jq -r --arg profile_id "$id" '.[] | select(.profileID==$profile_id) | .encryptionSystem') 
	echo "encryption_system_string:"
	echo -e "$encryption_system_string"
	echo && echo

	output_file_format_string=$(cat "$config_file_fullpath" | jq -r --arg profile_id "$id" '.[] | select(.profileID==$profile_id) | .outputFileFormat') 
	echo "output_file_format_string:"
	echo -e "$output_file_format_string"
	echo && echo

	sender_uid_string=$(cat "$config_file_fullpath" | jq -r --arg profile_id "$id" '.[] | select(.profileID==$profile_id) | .senderUID') 
	echo "sender_uid_string:"
	echo -e "$sender_uid_string"
	echo && echo


	recipient_uid_list_string=$(cat "$config_file_fullpath" | jq -r --arg profile_id "$id" '.[] | select(.profileID==$profile_id) | .recipientUIDList[]') 
	echo "recipient_uid_list_string:"
	echo -e "$recipient_uid_list_string"
	echo && echo

	# we actually need an IFS separated string now
	# try jq -j, with sed replacing space with |
	
	#OIFS=$IFS
	#IFS='|'

	recipient_uid_list_array=( $recipient_uid_list_string )
	echo "recipient_uid_list_array:"	
	echo "${recipient_uid_list_array[@]}"
	echo && echo
	echo "recipient_uid_list_array size:"
	echo "${#recipient_uid_list_array[@]}"
	echo && echo

	#IFS=$OIFS

	#read # a pause so we can read the debug output

	# run the actual quiz using our current quiz data
	#ask_quiz_questions

}

##########################################################

function get_user_profile_choice()
{
	echo -e "\033[33mWHICH PROFILE TO RUN?\033[0m" && sleep 1 && echo
	echo -e "\033[33mCHOOSE A PROFILE ID [1-"${#profile_id_array[@]}"].\033[0m" && echo

	read profile_id_choice
    
    # validate user input (TODO: separate these out)
    # 
    if  [[ "$profile_id_choice" =~ ^[0-9]+$ ]] && [ "$profile_id_choice" -ge 1 ] && [ "$profile_id_choice" -le "${#profile_id_array[@]}"  ]  #
    then
      return "$profile_id_choice"
    else
      ## exit with error code and message
      msg="The profile id you entered was too bad. Exiting now..."
	  exit_with_error "$E_UNEXPECTED_BRANCH_ENTERED" "$msg"
    fi
	
}

##########################################################

function assign_chosen_profile_values() 
{

	:
	
}