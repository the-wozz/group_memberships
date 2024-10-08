#!/bin/bash

# what it do: view current group memberships of a device and also 'add'/'remove' from a static group
# requirements: JQ via homebrew OR macOS Sequioa 15
# need to do: checking if inputted static group id is currently in device scope to not allow adding again
date=10/8/24
version=0.8
#C02V81DUHV2F # woz test machine

# Jamf Pro URL
jamfProURL=
# API 'Roles and Clients' client ID = Group Membership Script
jamfAPIClient=
# API 'Roles and Clients' secret
jamfAPIPass=

# variables #
serialNumber=$(/usr/sbin/system_profiler SPHardwareDataType | awk '/Serial/ {print $4}')
# icon to use for Swift Dialog prompts
notificationIcon="https://cdn-icons-png.flaticon.com/512/3666/3666231.png"
# Swift Dialog binary
swiftDialog="/usr/local/bin/dialog"
# Swift Dialog Log File for commands
swiftDialogLog="/var/tmp/dialog.log"
# latest Swift Dialog URL pkg; 2.5.2 as of 10/7/24
swiftDialogURL="https://github.com/swiftDialog/swiftDialog/releases/download/v2.5.2/dialog-2.5.2-4777.pkg"
current_epoch=$(/bin/date +%s)
# OS version check [for JQ]
#majorOSVersion=$()
# end variables #

## functions ##
# gets machine local time
timeStamp() {
    # current LOCAL (to machine) time
    /bin/date "+%F %T"
}

# Jamf Pro URL check
jamfCheck(){
if [[ -z $jamfProURL ]]; then
    echo "ERROR: NO Jamf Pro URL provided! Exiting..."
    exit 1
fi
}

# checks for stored credentials file to run this between clients
storedCredentialCheck(){
    if [ -f /private/var/credentials.json ]; then
        fileLoc=/private/var/credentials.json
        echo "Stored Credentials FOUND!"
        jamfProURL=$(cat $fileLoc | jq -r '.credentials.url')
            #echo "$jamfProURL"
        jamfAPIClient=$(cat $fileLoc | jq -r '.credentials.client')
            #echo "$jamfAPIClient"
        jamfAPIPass=$(cat $fileLoc | jq -r '.credentials.secret')
            #echo "$jamfAPIPass"
    fi
}

# Obtains Jamf Pro API Access Token
getAccessToken() {
    echo "Jamf Access Token: Generating..."

    response=$(/usr/bin/curl --retry 5 --retry-max-time 120 -s -L -X POST "$jamfProURL"/api/oauth/token \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode "client_id=$jamfAPIClient" \
        --data-urlencode 'grant_type=client_credentials' \
        --data-urlencode "client_secret=$jamfAPIPass")
    accessToken=$(echo "$response" | plutil -extract access_token raw -)
 	token_expires_in=$(echo "$response" | plutil -extract expires_in raw -)
 	token_expiration_epoch=$(($current_epoch + $token_expires_in - 1))

    if [[ -z "$accessToken" ]]; then
        echo "***** Jamf Access Token: NOT GENERATED! Issues MAY occur from HERE forward! *****"
    else
        #echo "ACCESS TOKEN ID: $accessToken" #troubleshooting line
        echo "Jamf Access Token: AQUIRED!"
    fi
}

# check Jamf Pro API access token expiration
checkTokenExpiration() {
        echo "Jamf Access TOKEN: Checking Expiration..."
        if [[ "$token_expiration_epoch" -ge "$current_epoch" ]]; then
            echo "Jamf Access TOKEN: Valid"
        else
            echo "Jamf Acces TOKEN: Expired! Requesting NEW token..."
                getAccessToken
        fi
}

# Jamf Pro API Permission: Read Computers
# Need to grab Computer ID (neccessary for certain API calls) from Jamf Pro Inventory record
jamfInventory(){
    # make sure we have a valid access token before grabbing inventory
    checkTokenExpiration

    echo "STATUS: Grabbing Jamf Pro Inventory information for $cleanSerial..."

    inventory=$(/usr/bin/curl -s -L -X GET "$jamfProURL"/JSSResource/computers/serialnumber/"$cleanSerial" \
        -H 'accept: application/json' \
        -H "Authorization: Bearer ${accessToken}" )
    #echo $inventory #troubleshooting line
    # parse Computer ID necessary for FileVault 2 key retrieval (WITHOUT plutil due to issues on Brian's VM...)
     computerID=$(echo "$inventory" | grep -o '"id":*[^"]*' | head -n 1 | sed 's/,*$//g' | cut -f2 -d":")
     # alternate command (plutil, preferred way) to get the computer ID
     #computerID=$(echo "$inventory" | plutil -extract "computer"."general"."id" raw -)
         echo "Computer ID: $computerID"
            if [[ -z "$computerID" ]]; then
                echo "*** ERROR: Jamf Computer ID NOT FOUND! Can not continue. Exiting... ****"
                    exit 1
            fi
}

# Checks if Swift Dialog exists and version, if not-existent (or too old), downloads Swift Dialog
checkSwiftDialog(){
    echo "STATUS: Checking for Swift Dialog..."

    if [[ -e "$swiftDialog" ]]; then
        echo "SWIFT DIALOG: Checking version..."
        sdVer=$(eval "$swiftDialog" -v)
        sdVer2=$(echo "$sdVer" | cut -c 1-5)
        sdURLVer=$(basename "$swiftDialogURL")
        latestSD="${sdURLVer:7:5}"
                # checks if Swift Dialog is older than latest
                if [[ "$sdVer2" < "$latestSD" ]]; then
                    echo "SWIFT DIALOG: Version too old! [$sdVer] | Downloading newer version: ($latestSD)..."
                    downloadSwiftDialog
                else
                    echo "SWIFT DIALOG: Version PASSED [$sdVer]"
                    return
                fi
    else
        echo "$(timeStamp) SWIFT DIALOG: NOT found! Downloading Swift Dialog $latestSD..."
            downloadSwiftDialog
    fi
}

# downloads Swift Dialog via GitHub
downloadSwiftDialog(){
        echo "* SWIFT DIALOG: Flagged for Download! *"

    if [[ -n "$swiftDialogURL" ]]; then
        echo "SWIFT DIALOG: URL Provided! "

        local filename
            filename=$(basename "$swiftDialogURL")
        local temp_file
            temp_file="/tmp/$filename"
        previous_umask=$(umask)
        umask 077

        /usr/bin/curl -Ls "$swiftDialogURL" -o "$temp_file" 2>&1
            if [[ $? -eq 0 ]]; then
                echo "SWIFT DIALOG: DOWNLOADED successfully! Installing..."
                        /usr/sbin/installer -verboseR -pkg "$temp_file" -target / 2>&1
                            if [[ $? -eq 0 ]]; then
                                echo "SWIFT DIALOG: INSTALLED!"
                            else
                                echo "**** ERROR: SWIFT DIALOG: Unable to instal! Can NOT continue! Exiting... *****"
                                exit 1
                            fi

                /bin/rm -Rf "${temp_file}" >/dev/null 2>&1
                umask "${previous_umask}"
            else
                echo "**** ERROR: SWIFT DIALOG: Download FAILED!! Can NOT continue! Exiting... *****"
                exit 1
            fi
    else
        echo "SWIFT DIALOG: ERROR! NO Downlad URL Provided! Exiting..."
        exit 1
    fi
}

# view static groups of a machine
viewStatics(){
    echo "Gathering Jamf Pro Group Memberships..."

    checkTokenExpiration 
    # gets "total groups" number
    totalGroups=$(/usr/bin/curl -s -L -X GET "$jamfProURL"/api/v1/computers-inventory/"$computerID"?section=GROUP_MEMBERSHIPS \
    -H 'accept: application/json' \
    -H "Authorization: Bearer ${accessToken}" | /usr/bin/plutil -extract groupMemberships raw -)
        #echo "total groups: $totalGroups"

    # stores array of memberships, id, name, and grouptype to local file
    /usr/bin/curl -s -L -X GET "$jamfProURL"/api/v1/computers-inventory/"$computerID"?section=GROUP_MEMBERSHIPS \
    -H 'accept: application/json' \
    -H "Authorization: Bearer ${accessToken}" | jq -r '.groupMemberships[]' >> /tmp/full_memberships.json
        modifyArray

    # stores modified array with only id and name to another local file
    /usr/bin/curl -s -L -X GET "$jamfProURL"/api/v1/computers-inventory/"$computerID"?section=GROUP_MEMBERSHIPS \
    -H 'accept: application/json' \
    -H "Authorization: Bearer ${accessToken}" | jq -r '.groupMemberships[]| [.groupId, .groupName] | @tsv' >> /tmp/memberships.json

}

# modifies array to be JQ readable when ouputted from Jamf Pro
# this took wayyy too long :') but should be very beneficial/helpful for JSON processing in future scripts
modifyArray(){
    full_Json=/tmp/full_memberships.json
    # add [ to beginning of file
    echo -e "[\n$(cat $full_Json)" > $full_Json
    # add comma to each }, except last
    /usr/bin/sed -i -e '$!s/}/},/' $full_Json
    # add ] to end of file
    echo "]" >> $full_Json
    # /bin/cat $file | jq
}

# processing of array items into swift dialog list
addToList(){
    echo "Adding each item to Swift Dialog List..."

    # add items to list
    for ((i = 0 ; i < totalGroups ; i++)); do
    groupId=$(cat $full_Json | jq '.['$i']' | jq -r '.groupId')
    groupName=$(cat $full_Json | jq '.['$i']' | jq -r '.groupName')
    smartGroup=$(cat $full_Json | jq '.['$i']' | jq -r '.smartGroup')
        smartGroupdMod=$(if $smartGroup -eq true; then echo Smart 🧠; else echo Static ⚡️; fi)
    # /bin/cat /tmp/memberships.json | while read line || [[ -n $line ]];
    # do
        #echo "$line" # use line to show groups being processed
        echo "listitem: add, title: $groupId - $groupName, statustext: $smartGroupdMod" >> $swiftDialogLog
    done
}

# Jamf Pro API Permission: Read Computer Static Groups
# grabs the name of the Static Group inputted in the previous Swift Dialog window to modify
staticName(){
    # make sure Jamf Access Token is valid before attempting to send the API call
    checkTokenExpiration

    echo "STATUS: Gathering common name of Static Group ID: $staticID2...."

    staticResponse=$(curl -s -L -X GET "$jamfProURL"/JSSResource/computergroups/id/"$staticID2" \
        -H "Authorization: Bearer ${accessToken}" \
        -H 'accept: application/json' | jq -r '.computer_group.name')

    #echo "staticName var: $staticResponse"
    if [[ $decision == *ADD* ]]; then
        echo "message: + $decision $cleanSerial to $staticResponse [$staticID2]?" >> $swiftDialogLog
    else
        echo "message: + $decision $cleanSerial from $staticResponse [$staticID2]?" >> $swiftDialogLog
    fi
}

# Jamf Pro API Permission: Update Computer Static Groups
# add device to static group
staticAdd(){
    # make sure Jamf Access Token is valid before attempting to send the API call
    checkTokenExpiration

    echo "STATUS: ADDING $serialNumber to Static Group: $staticID2"

    staticAdd="<computer_group><computer_additions><computer><serial_number>$cleanSerial</serial_number></computer></computer_additions></computer_group>"

    addResponse=$(/usr/bin/curl -s -o /dev/null -w "%{http_code}" -X PUT "$jamfProURL"/JSSResource/computergroups/id/"$staticID2" \
            -H "Authorization: Bearer ${accessToken}" \
            -H "Content-Type: text/xml" \
            -d "${staticAdd}")
    
    if [[ "$addResponse" == 201 ]]; then
        echo "Success! $cleanSerial added to $staticResponse!"
        verb="**ADDED** to"
        successWindow
    else
        echo "Failure to add $cleanSerial to $staticResponse!"
        exit 1
    fi
}

# Jamf Pro API Permission: Update Computer Static Groups
# remove device from static group
staticRemove(){
    # make sure Jamf Access Token is valid before attempting to send the API call
    checkTokenExpiration

    echo "STATUS: REMOVING $serialNumber from Static Group: $staticID2"

        staticRemove="<computer_group><computer_deletions><computer><serial_number>$cleanSerial</serial_number></computer></computer_deletions></computer_group>"

        removeResponse=$(/usr/bin/curl -s -L -o /dev/null -w "%{http_code}" -X PUT "$jamfProURL"/JSSResource/computergroups/id/"$staticID2" \
            -H "Authorization: Bearer ${accessToken}" \
            -H "Content-Type: text/xml" \
            -d "${staticRemove}")
    echo "removeResponse var: $removeResponse"
    if [[ "$removeResponse" == 201 ]]; then
        echo "Sucess! $cleanSerial removed from $staticResponse!"
        verb="**REMOVED** from"
        successWindow
    else
        echo "Failure to remove $cleanSerial from $staticResponse!"
        exit 1
    fi
}

# checks if the entered group ID is indeed a static group
idCheck() {
    # make sure Jamf Access Token is valid before attempting to send the API call
    checkTokenExpiration

    echo "STATUS: Checking if entered Group ID: [$staticID2] is a 'Static Group'..."

    smartCheck=$(curl -s -L -X GET "$jamfProURL"/JSSResource/computergroups/id/"$staticID2" \
        -H "Authorization: Bearer ${accessToken}" \
        -H 'accept: application/json' | jq -r '.computer_group.is_smart')
    #echo "smartCheck var: $smartCheck"

    serialList=$(curl -s -L -X GET "$jamfProURL"/JSSResource/computergroups/id/"$staticID2" \
        -H "Authorization: Bearer ${accessToken}" \
        -H 'accept: application/json' | jq -r '.computer_group.computers')
    #echo "serialList var: $serialList"

    if [[ "$smartCheck" == true ]]; then
        echo "Smart Group Check: Entered ID IS Smart Group. Can NOT continue!..."
        badID
    fi

    if [[ $cleanSerial == *$serialList* ]] && [[ $decision == ADD ]]; then
        echo "Membership Check: Add Selected AND serial # found in group already! Letting user know."
        exit 0 &
            machineExists
    elif [[ $cleanSerial != *$serialList* ]] && [[ $decision == REMOVE ]]; then
        echo "Membership Check: Serial NOT found AND trying to remove? Exiting and prompting user..."
            exit 1
            # put unable to remove prompt here
    elif [[ $cleanSerial != *$serialList* ]] && [[ $decision == ADD ]]; then
        echo "Membership Check: Serial NOT found! Continue to next check..."
    fi

    if [[ $smartCheck == false ]]; then
        echo "Smart Group Check: Entered ID is Static Group. Proceeding..."
            confirmDialog & sleep 0.2
                staticName
                    wait
    fi
}

## functions: swift dialog prompts ##

# initial dialog window asking for serial number to view group memberhsips
machinePrompt(){
    echo "Prompting for serial number via Swift Dialog"
    inputSerialNumber=$("$swiftDialog" -i "$notificationIcon" -o -p -s \
    -t "Group Memberships" --titlefont size="21" \
    --messagefont size="15" -m "Input a serial number to view current groups and/or change static groups.<br><br><br><br>Server: $jamfProURL" --alignment centre \
    --textfield "Serial Number",prompt="$serialNumber",regex="^^[[:alnum:]]{10}$|^[[:alnum:]]{12}$",regexerror="Serial number must be 10-12 characters" \
    --button1text "Submit" --button2text "Exit")
        case $? in
            0)
                input2=$(echo "$inputSerialNumber" | awk '{print $4}'| tr -d ' ')
                    if [[ -z "$input2" ]]; then
                        cleanSerial=$serialNumber
                        echo "No serial inputted, using machine serial: $serialNumber"
                    else
                        cleanSerial=$(echo "$inputSerialNumber" | awk '{print $4}'| tr -d ' ')
                        echo "Serial Number inputted: $cleanSerial"
                    fi
            ;;
            2)
                echo "User pressed Exit button"
                exit 0
            ;;
            *)
                echo "IDK wat hapeded?"
            ;;
        esac
}

# view all static groups of machine
staticGroupWindow(){
    echo "Displaying Swift Dialog List prompt to user..."
    "$swiftDialog" --hideicon -o -p -s --width 1100 \
    -t "$serialNumber Group Memberships" --titlefont size="20" \
    --messagefont size="15" -m "" --listitem "Total Groups: $totalGroups" \
    --button1text "Modify" --button2text "Exit"
        case $? in
            0)
                echo "User pressed Modify"
                    modifyPrompt
            ;;
            2)
                echo "User pressed Exit button"
                    exit 0
            ;;
            *)
                echo "IDK wat hapeded?"
            ;;
        esac
}

# prompt asking for static group id to add or remove
modifyPrompt(){
    echo "Prompting for Static Device group to modify..."
        staticID=$("$swiftDialog" -i "$notificationIcon" -o -p -s \
    -t "$serialNumber Modify Membership" --titlefont size="21" \
    --messagefont size="13" -m "Enter a Static Group ID to Add or Remove. Next screen will confirm selection." --textfield "Static Group ID" --selecttitle "Action:",radio --selectvalues "Add, Remove" \
    --button1text "Proceed" --button2text "Exit")
        wait
        staticID2=$(echo "$staticID" |  grep "Static Group ID" | awk -F ": " '{print $NF}')
            #echo "staticID2 var: $staticID2"
        actionDecision=$(echo "$staticID" | grep "SelectedOption" | awk -F ": " '{print $NF}')
            #echo "actionDecision var: $actionDecision"
        case $? in
            0)
                    if [[ "$actionDecision" == *Add* ]]; then
                        echo "Add was selected"
                        decision=ADD
                    else
                        echo "Remove was selected"
                        decision=REMOVE
                    fi
                        idCheck 
            ;;
            2)
                echo "User pressed Exit button"
                    exit 0
            ;;
            *)
                echo "IDK wat hapeded?"
                    exit 1
            ;;
        esac
}

# prompt to confirm prior decisions
confirmDialog(){
    echo "Confirming selection of: '$decision'"

    confirmDialogPrompt=$("$swiftDialog" -i "$notificationIcon" -o -p -s \
    -t "Confirm Static Group $decision" --titlefont size="21" \
    --messagefont size="15" -m "Please confirm the following action to be performed:<br>" \
    --buttonstyle stack --button1text "Confirm" --button2text "Exit")
        case $? in
            0)
                echo "User confirmed selection."
                if [ $decision == ADD ]; then
                    echo "Calling 'Add to Static Group' Jamf Pro API function; staticAdd"
                    staticAdd
                else
                    echo "Calling 'Remove from Static Group' Jamf Pro API function; staticRemove"
                    staticRemove
                fi
            ;;
            2)
                echo "User selected Exit."
                exit 0
            ;;
            5)
                echo "User pressed Command+Q. Exiting safely..."
                exit 0
            ;;
            *)
                echo "IDK wat hapeded? Command+Q??"
                exit 1
            ;;
        esac
}

# prompt for incorrectl entered ID in 'Modify' step
badID (){
    echo "Prompting with 'Bad ID' prompt..."

    badIDPrompt=$("$swiftDialog" -i warning --iconsize 80 --centericon -o -p -s --width 500 \
    -t "Incorrect Group ID" --titlefont size="17" \
    --messagefont size="15" -m "Group: $staticID2 was **NOT** a Static Group! <br>Please try again with a **Static** Group ID." --alignment center \
    --buttonstyle stack --button1text Retry --button2text "Exit")
        case $? in
            0)
                echo "User wants to try again."
                    modifyPrompt
            ;;
            2)
                echo "User selected Exit."
                exit 0
            ;;
            5)
                echo "User pressed Command+Q. Exiting safely..."
                exit 0
            ;;
            *)
                echo "IDK wat hapeded? Command+Q??"
                exit 1
            ;;
        esac
}

# prompt for when a entered serial is already apart of an entered group ID
machineExists() {
    echo "Showing machine already exists in group prompt..."

    checkTokenExpiration
    staticResponse=$(curl -s -L -X GET "$jamfProURL"/JSSResource/computergroups/id/"$staticID2" \
        -H "Authorization: Bearer ${accessToken}" \
        -H 'accept: application/json' | jq -r '.computer_group.name')

    machineExistsPrompt=$("$swiftDialog" -i caution --iconsize 80 --centericon -o -p -s --height 350 --width 600 \
    -t "Machine In Group Already" --titlefont size="17" --alignment center \
    --messagefont size="15" -m "<br>$cleanSerial is already in group:<br>$staticResponse [$staticID2].<br>No actions have been performed." \
    --buttonstyle stack --button1text none --button2text "Exit") & exit 0
}

# final Swift Dialog window upon success of adding/removing to Static Group
successWindow(){
    echo "Showing success window to user..."

    checkTokenExpiration
    staticResponse=$(curl -s -L -X GET "$jamfProURL"/JSSResource/computergroups/id/"$staticID2" \
        -H "Authorization: Bearer ${accessToken}" \
        -H 'accept: application/json' | jq -r '.computer_group.name')

    successWindowPrompt=$("$swiftDialog" -i "https://cdn-icons-png.flaticon.com/512/148/148767.png" --iconsize 80 --centericon -o -p -s --height 220 --wdith 400 \
    -t "Success" --titlefont size="17" --alignment center \
    --messagefont size="15" -m "<br><br>$cleanSerial $verb $staticResponse" \
    --buttonstyle stack --button1text none --button2text "Exit") & exit 0
}
## end prompts section ##

# Invalidate Jamf API Access Token
invalidateToken() {
    echo "ACCESS TOKEN: Invalidating..."

	responseCode=$(/usr/bin/curl -s -X POST -w "%{http_code}" "$jamfProURL"/api/v1/auth/invalidate-token -o /dev/null \
        -H "Authorization: Bearer ${accessToken}")

	if [[ "$responseCode" == 204 ]]; then
		echo "ACCESS TOKEN: Successfully invalidated! (oxymoron)"
		accessToken=""
	elif [[ "$responseCode" == 401 ]]; then
		echo "ACCESS TOKEN: Already invalid."
	else
		echo "ACCESS TOKEN: An unknown error occurred invalidating the token?"
	fi
}

# removes files generated during usage of this script
removeFiles(){
    echo "Checking for previous stored local files..."
if [ -e /tmp/memberships.json ] || [ -e /tmp/full_memberships.json ]; then
    echo "FOUND! Deleting old stored files."
    set -x
    /bin/rm -rf /tmp/memberships.json
    /bin/rm -rf /tmp/full_memberships.json
    set +x
fi
}
## end functions ##

### meat ###
echo  "START: $(timeStamp)"
echo "Version: $version[$date]"

storedCredentialCheck
jamfCheck
checkSwiftDialog
removeFiles
machinePrompt
    getAccessToken
    jamfInventory
        viewStatics
            staticGroupWindow & sleep 0.5
                addToList
                    wait

invalidateToken
#removeFiles
echo  "END: $(timeStamp)"
    exit 0
