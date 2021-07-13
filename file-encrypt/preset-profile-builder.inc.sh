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

	profile_id_array=( $profile_id_string )
	echo "profile_id_array:"
	echo "${profile_id_array[@]}"
	echo && echo
	echo "profile_id_array size:"
	echo "${#profile_id_array[@]}"
	echo && echo

	for profile_id in "${profile_id_array[@]}"
	do
		echo "profile_id: $profile_id" && echo && echo
		store_profiles "$profile_id"
	done

	# get user preset profile choice | direct parameter input (implement later)
	get_user_profile_choice
	chosen_profile_id=$?
	echo "chosen_profile_id : $chosen_profile_id"

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
# 0	=>	"1^^profile_name"
# 1	=>	"1^^profile_description"
# 2	=>	"1^^encryption_system"
#...
# associative array:
#===========
# "1^^profile_name"		 	 =>			"local admin"	
# "1^^profile_description"	=>			"local administration"
# "1^^encryption_system" =>			"public key"
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

	primary_key_string="${id}^^profile_name"
	profile_keys_indexed_array+=( "${primary_key_string}" )
	profile_key_value_assoc_array["$primary_key_string"]="$profile_name_string"

	###

	profile_description_string=$(cat "$config_file_fullpath" | jq -r --arg profile_id "$id" '.[] | select(.profileID==$profile_id) | .profileDescription') 
	echo "profile_description_string:"
	echo -e "$profile_description_string"
	echo && echo

	primary_key_string="${id}^^profile_description"
	profile_keys_indexed_array+=( "${primary_key_string}" )
	profile_key_value_assoc_array["$primary_key_string"]="$profile_description_string"

	###

	encryption_system_string=$(cat "$config_file_fullpath" | jq -r --arg profile_id "$id" '.[] | select(.profileID==$profile_id) | .encryptionSystem') 
	echo "encryption_system_string:"
	echo -e "$encryption_system_string"
	echo && echo

	primary_key_string="${id}^^encryption_system"
	profile_keys_indexed_array+=( "${primary_key_string}" )
	profile_key_value_assoc_array["$primary_key_string"]="$encryption_system_string"

	###

	output_file_format_string=$(cat "$config_file_fullpath" | jq -r --arg profile_id "$id" '.[] | select(.profileID==$profile_id) | .outputFileFormat') 
	echo "output_file_format_string:"
	echo -e "$output_file_format_string"
	echo && echo

	primary_key_string="${id}^^output_file_format"
	profile_keys_indexed_array+=( "${primary_key_string}" )
	profile_key_value_assoc_array["$primary_key_string"]="$output_file_format_string"

	###

	sender_uid_string=$(cat "$config_file_fullpath" | jq -r --arg profile_id "$id" '.[] | select(.profileID==$profile_id) | .senderUID') 
	echo "sender_uid_string:"
	echo -e "$sender_uid_string"
	echo && echo

	primary_key_string="${id}^^sender_uid"
	profile_keys_indexed_array+=( "${primary_key_string}" )
	profile_key_value_assoc_array["$primary_key_string"]="$sender_uid_string"

	###

	recipient_uid_list_string=$(cat "$config_file_fullpath" | jq -j --arg profile_id "$id" '.[] | select(.profileID==$profile_id) | .recipientUIDList[]' | sed "s/''/|/g" | sed "s/^'//" | sed "s/'$//") 
	echo "recipient_uid_list_string:"
	echo -e "$recipient_uid_list_string"
	echo && echo

	primary_key_string="${id}^^recipient_uid_list"
	profile_keys_indexed_array+=( "${primary_key_string}" )
	profile_key_value_assoc_array["$primary_key_string"]="$recipient_uid_list_string"

	###

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
	  lib10k_exit_with_error "$E_UNEXPECTED_BRANCH_ENTERED" "$msg"
    fi
	
}

##########################################################

function assign_chosen_profile_values() 
{

	echo "passed out chosen_profile_id : $chosen_profile_id" 

	# order of iteration is not important, so we just need the associative array.

	for key in "${!profile_key_value_assoc_array[@]}"
	do
		echo $key
		test_profile_id="${key%^^*}"
		echo "$test_profile_id"
		test_profile_property_name="${key#*^^}"
		echo "$test_profile_property_name"

		# test key for match with our chosen_profile_id
		if [ "$test_profile_id" -eq "$chosen_profile_id" ]
		then
			# assign values
			echo "MATCH, MATCH"
			case $test_profile_property_name in
				'profile_name')		profile_name="${profile_key_value_assoc_array[$key]}"
					;;
				'profile_description')	profile_description="${profile_key_value_assoc_array[$key]}"
					;;
				'encryption_system')	encryption_system="${profile_key_value_assoc_array[$key]}"
					;;
				'output_file_format')	output_file_format="${profile_key_value_assoc_array[$key]}"
					;;
				'sender_uid')	sender_uid="${profile_key_value_assoc_array[$key]}"
					;;
		 		'recipient_uid_list')	OIFS=$IFS; IFS='|'
										recipient_uid_list=(
											${profile_key_value_assoc_array[$key]}
										)									
										IFS=$OIFS
					;;
				*) 		msg="Unrecognised profile property name. Exiting now..."
	  					lib10k_exit_with_error "$E_UNEXPECTED_ARG_VALUE" "$msg"
					;; 
			esac
		fi
	done
	
}