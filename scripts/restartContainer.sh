#! /bin/bash

#try suffixes

WATCH_TOWER_LABEL_PREFIX=com_centurylinklabs_watchtower
FRESH_CONTAINER_LABEL_PREFIX=${WATCH_TOWER_LABEL_PREFIX}_freshContainer
FRESH_CONTAINER_TIMEOUT=60
FRESH_CONTRAINER_SEMVER_PARSING_ERROR="No Major.Minor.Patch elements found"

usage() {
cat << EOF
Usage ${0}  [-v] [-h] [-s <FRESH_CONTAINER_SERVER>] [-l]

Unifies restart a container by hand with watchtower/freshcontainer semantics..

1- Stops the container specified in docker-compose.yml if running
2- Retrieves the lastest version of the image specified in the yml file that passes the watchtower/freshcontainer constraints, if any
3- Restarts the container
4- Executes the script specified in the .yml watchtower post-update-command, with the right user, if present

Notes
	- only supports 2 spaces indentation schemes in docker-compose.yml
	- v3 format
	- docker-compose.override.yml is honored 
	- Requires jq (https://stedolan.github.io/jq/) to be present
	- the container_name field must match the service name definintion, and
	- for those containers with a fresh container constraints, the version number needs to be specified with a <container_name>_TAG substitution variable
	- the script only looks in the current directory for the .yml file.  (docker semantic walks up directories)

An example docker-compose.yml that takes advantage of all this:
	
version: "3.6"
services:
  mySpecialName:
	container_name: "mySpecialName"
	image:"superDuperImage:${mySpecialName_TAG}"
	labels:
	  com.centurylinklabs.watchtower.lifecycle.post-update: "magicScript.sh"
      com.centurylinklabs.watchtower.lifecycle.post-update.user: "specialUser"
      com.centurylinklabs.watchtower.freshContainer.tag-prefix: "ubuntu-"
      com.centurylinklabs.watchtower.freshContainer.tag-constraint: ">5.4.6"

With this yml, superDuperImage will be update to the latest tag that matches ubuntu-x.y.z and 
x.y.z is the latest semver release in the repository > 5.4.6
and magicScript.sh will be run inside the container, with user 'specialUser'

Flags:
	-v: debug output
	-h: this screen
	-s: specify a fresh container server URL
	-l: finishes by outputting the logs of the restarted container.

EOF
exit 1
}


while getopts 'vhs:l' OPT
do
  case $OPT in
    v) DEBUG=true ;;
    h) usage ;;
    s) FRESH_CONTAINER_SERVER_URL=${OPTARG} ;;
    l) OUTPUT_CONTAINER_LOG=true ;;
  esac
done


function echov()
{
	if ! [[ -z "${DEBUG}" ]]; then
		echo $*
	fi
}

function echovar()
{
	VARNAME=$1
	VARVAL=${!VARNAME}
	echov "${VARNAME}=${VARVAL}"
}


# ---------------------------
# shellcheck disable=SC1003
# Based on https://github.com/jasperes/bash-yaml/blob/master/script/yaml.sh

parse_yaml() {
    local yaml_file=$1
    local prefix=$2
    local s
    local w
    local fs

    s='[[:space:]]*'
    w='[a-zA-Z0-9_.-]*'
    fs="$(echo @ | tr @ '\034')"

    (
        sed -e '/- [^\“]'"[^\']"'.*: /s|\([ ]*\)- \([[:space:]]*\)|\1-\'$'\n''  \1\2|g' |
            sed -ne '/^--/s|--||g; s|\"|\\\"|g; s/[[:space:]]*$//g;' \
                -e 's/\$/\\\$/g' \
                -e "/#.*[\"\']/!s| #.*||g; /^#/s|#.*||g;" \
                -e "s|^\($s\)\($w\)$s:$s\"\(.*\)\"$s\$|\1$fs\2$fs\3|p" \
                -e "s|^\($s\)\($w\)${s}[:-]$s\(.*\)$s\$|\1$fs\2$fs\3|p" |
            awk -F"$fs" '{
            indent = length($1)/2;
            if (length($2) == 0) { conj[indent]="+";} else {conj[indent]="";}
            vname[indent] = $2;
            for (i in vname) {if (i > indent) {delete vname[i]}}
                if (length($3) > 0) {
                    vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
                    printf("%s%s%s%s=(\"%s\")\n", "'"$prefix"'",vn, $2, conj[indent-1], $3);
                }
            }' |
            sed -e 's/_=/+=/g' |
            awk 'BEGIN {
                FS="=";
                OFS="="
            }
            /(-|\.).*=/ {
                gsub("-|\\.", "_", $1)
            }
            { print }'
    ) <"$yaml_file"
}

unset_variables() {
    # Pulls out the variable names and unsets them.
    #shellcheck disable=SC2048,SC2206 #Permit variables without quotes
    local variable_string=($*)
    unset variables
    variables=()
    for variable in "${variable_string[@]}"; do
        tmpvar=$(echo "$variable" | grep '=' | sed 's/=.*//' | sed 's/+.*//')
        variables+=("$tmpvar")
    done
    for variable in "${variables[@]}"; do
        if [ -n "$variable" ]; then
            unset "$variable"
        fi
    done
}

create_variables() {
    local yaml_file="$1"
    local prefix="$2"
    local yaml_string
    yaml_string="$(parse_yaml "$yaml_file" "$prefix")"
    unset_variables "${yaml_string}"
    eval "${yaml_string}"
}

# ---------------------------
# Issue Initial Request
# returns NEXT_TAG, IS_STALE

fetch_next_tag() 
{

	local IMAGE_NAME=$1
	local BASE_TAG=$2
	local CONSTRAINT=$3 # 
	local TAG_PREFIX=$4 # Optional

	unset GOT_RESPONSE
	unset ACCEPTED
	unset ERROR
	
	unset NEXT_TAG
	unset IS_STALE

	if [[ -z "${FRESH_CONTAINER_SERVER_URL}" ]]; then
		echo "FRESH_CONTAINER_SERVER_URL is empty.  Please specify it via -s or an evironment variable"
	fi
	
	if [[ -z "${CONSTRAINT}" ]]; then
		echov "No CONSTRAINT specified"
		NEXT_TAG=${BASE_TAG}
		IS_STALE=true
		return 0;
	fi
		

	if ! [[ -z "${TAG_PREFIX}" ]]; then
		TAG_PREFIX_OPTION="--data-urlencode ${TAG_PREFIX}"
	fi

	if ! [[ -z ${DEBUG} ]]; then
		set -x
	fi	
	RESPONSE_CODE=$(curl -s  -w "%{http_code}\n" \
		--data-urlencode "${CONSTRAINT}" \
		--data-urlencode "image=${IMAGE_NAME}:${BASE_TAG}" \
		${TAG_PREFIX_OPTION} \
		-G \
		-o ${FRESH_CONTAINER_JSON_FILE} \
		--dump-header ${HEADER_FILE} \
		${FRESH_CONTAINER_SERVER_URL}/api/v1/check )
	CURL_RESPONSE_CODE=$?
	if ! [[ -z ${DEBUG} ]]; then
		set +x
	fi
	
	echov "RESPONSE_CODE="${RESPONSE_CODE}

	case ${RESPONSE_CODE} in
		202) ACCEPTED=1
			;;
		200) GOT_RESPONSE=1
			;;
		*)
			ERROR=1
			;;
	esac

	if ! [[ -z "${ERROR}" ]]; then
		echo "Could not retrieve valid tag: HTTP status "${RESPONSE_CODE}" with URL: "${FRESH_CONTAINER_SERVER_URL}/api/v1/check 
		if [[ -f ${FRESH_CONTAINER_JSON_FILE} ]] && \
		 ! [[ -z $(grep "${FRESH_CONTRAINER_SEMVER_PARSING_ERROR}" ${FRESH_CONTAINER_JSON_FILE}) ]]; then
			echo "the tag "${BASE_TAG}" (from the existing container?) could not be parsed into a semantic version"
			return 2
		else
			echo "curl returned ${CURL_RESPONSE_CODE}"
			cat ${HEADER_FILE}
			if [[ -f ${FRESH_CONTAINER_JSON_FILE} ]]; then
				cat ${FRESH_CONTAINER_JSON_FILE}
			fi
			if [[ -z "${DEBUG}" ]]; then
				rm -f ${HEADER_FILE} ${FRESH_CONTAINER_JSON_FILE}
			fi
			return 1
		fi
	fi

	unset ERROR
	TIME=0
	if ! [[ -z "${ACCEPTED}" ]]; then # We got a 202
	
		# get the /jobs URL
		LOCATION=$(cat ${HEADER_FILE} | grep "Location:")
		echov "LOCATION="${LOCATION}
		
		if [[ -z "${LOCATION}" ]]; then
			echo "Could not parse location header for 202 redirect from: "
			cat ${HEADER_FILE}
			return 1
		fi
		
		POLL_URI=$(echo $LOCATION |  awk -F '[ \r]' '{print $2}')
		echov "POLL_URI="${POLL_URI}
		POLL_URL=${FRESH_CONTAINER_SERVER_URL}${POLL_URI}
		echov "POLL_URL="${POLL_URL}

		unset GOT_RESPONSE
		unset ACCEPTED
		unset ERROR

		while [[ ${TIME} -le ${FRESH_CONTAINER_TIMEOUT}  &&  -z "${GOT_RESPONSE}" && -z "${ERROR}" ]]; do
			echo -n  "."
			sleep 1
			TIME=$((${TIME}+1))
			echov "TIME="${TIME}

			rm -f ${HEADER_FILE} ${FRESH_CONTAINER_JSON_FILE}
			if ! [[ -z "${DEBUG}" ]]; then
				set -x
			fi
			RESPONSE_CODE=$(curl -s -G -w "%{http_code}\n" \
				-o ${FRESH_CONTAINER_JSON_FILE} \
				--dump-header ${HEADER_FILE} \
				${POLL_URL})
		        CURL_RESPONSE_CODE=$?

			if ! [[ -z "${DEBUG}" ]]; then
				set +x
			fi

			echov "RESPONSE_CODE="${RESPONSE_CODE}
	
			unset REDIRECT
			case ${RESPONSE_CODE} in
				200)
					if [[ ${POLL_URI} =~ "evaluations" ]]; then  # we only actually get a response on the evaluation call
						GOT_RESPONSE=1
						echo
					fi
					;;
				300) # Loop through to redirect
					REDIRECT=1 ;;
				301) # Loop through to redirect
					REDIRECT=1 ;;
				302) # Loop through to redirect
					REDIRECT=1 ;;
				303) # Loop through to redirect
					REDIRECT=1 ;;
				*)
					ERROR=1
					;;					
			esac

			if ! [[ -z "${ERROR}" ]]; then
				echo
				echo "Could not retrieve valid tag: HTTP status ${RESPONSE_CODE} with URL: ${POLL_URL}"
		                echo "curl returned ${CURL_RESPONSE_CODE}"
                		cat ${HEADER_FILE}
                		if [[ -f ${FRESH_CONTAINER_JSON_FILE} ]]; then
                        		cat ${FRESH_CONTAINER_JSON_FILE}
                		fi
				if [[ -z "${DEBUG}" ]]; then
					rm -f ${HEADER_FILE} ${FRESH_CONTAINER_JSON_FILE}
				fi
				return 1;
			fi
			
			if ! [[ -z "${REDIRECT}" ]]; then
				LOCATION=$(cat ${HEADER_FILE} | grep "Location:")
				echov "LOCATION="${LOCATION}
				POLL_URI=$(echo $LOCATION |  awk -F '[ \r]' '{print $2}')
				echov "POLL_URI="${POLL_URI}
				POLL_URL=${FRESH_CONTAINER_SERVER_URL}${POLL_URI}
				echov "POLL_URL="${POLL_URL}
			fi


			if ! [[ "${RESPONSE_CODE}"=="200" ]]; then
				sleep 1;
			fi
	
		done


	fi

	echo
	if [[ -z ${GOT_RESPONSE} ]]; then
		echo "Could't get a response from ${FRESH_CONTAINER_SERVER_URL}"
		return 3
	fi

	# is there an error in the response?
	ERROR_RESPONSE=$(jq ".Error" ${FRESH_CONTAINER_JSON_FILE})
	echovar ERROR_RESPONSE
	if ! [[ -z ${ERROR_RESPONSE} ]] && [[ ${ERROR_RESPONSE} != "null" ]]; then
		echo "Got error trying to fetch new tags"
		echo ${ERROR_RESPONSE}
		return 1
	fi


	NEXT_TAG=$(jq ".next_version" ${FRESH_CONTAINER_JSON_FILE})
	if [[ $? -ne 0 ]]; then
		echov "Could not parse JSON: "
		cat ${FRESH_CONTAINER_JSON_FILE}
		return 1
	fi
	NEXT_TAG=$(echo ${NEXT_TAG} | tr -d '"')
	IS_STALE=$(jq ".stale" ${FRESH_CONTAINER_JSON_FILE})

	if [[ -z "${DEBUG}" ]]; then
		rm -f ${HEADER_FILE} ${FRESH_CONTAINER_JSON_FILE}
	fi

	if [[ -z "${DEBUG}" ]]; then
		rm -f ${HEADER_FILE} ${FRESH_CONTAINER_JSON_FILE}
	fi

	return 0
}	
	
# ---------------------------
# returns NEXT_TAG, IS_STALE, CONTAINER_MANAGED_BY_FRESH_CONTAINER, TAG_CONSTRAINT, FULL_IMAGE_SPEC
	
computeImageStatusForContainerNamed()
{
	unset NEXT_TAG
	unset IS_STALE
	unset CONTAINER_MANAGED_BY_FRESH_CONTAINER
	unset TAG_CONSTRAINT
	unset FULL_IMAGE_SPEC
	
	local CONTAINER_NAME=$1	
	CONTAINER_PREFIX=services_${CONTAINER_NAME}

	FULL_IMAGE_SPEC_VAR=${CONTAINER_PREFIX}_image
	echov "FULL_IMAGE_SPEC_VAR="${FULL_IMAGE_SPEC_VAR}
	FULL_IMAGE_SPEC=${!FULL_IMAGE_SPEC_VAR} #! Double substitution
	FULL_IMAGE_SPEC=$(echo ${FULL_IMAGE_SPEC} | tr -d '"')
	echov "FULL_IMAGE_SPEC="${FULL_IMAGE_SPEC}
	if [[ -z "${FULL_IMAGE_SPEC}" ]]; then
		echo "Couldn't find image specification for ${CONTAINER_NAME} in variable ${FULL_IMAGE_SPEC_VAR}"
		echo "This likely indicates a parsing problem with docker-compose.yml"
		echo " - version 3 "
		echo " - 2 spaces ident?"
		echo " - mismatched service entry and container names?"
		exit 1
	fi
	
	IMAGE_NAME=$(echo ${FULL_IMAGE_SPEC} | awk -F ':' '{print $1}')
	IMAGE_TAG=$(echo ${FULL_IMAGE_SPEC} | awk -F ':' '{print $2}')
	echovar IMAGE_NAME
	echovar IMAGE_TAG

	# See if we can find a version in the currently running container
	RUNNING_IMAGE=$(docker ps -f name="${CONTAINER_NAME}" | grep ${CONTAINER_NAME} | awk -F' ' '{ print $2 }')
	RUNNING_TAG=$(echo ${RUNNING_IMAGE} | awk -F ':' '{print $2}')
	echovar RUNNING_IMAGE
	echov RUNNING_TAG

	# Get version/script options from parsed variables
	
	TAG_PREFIX_VAR=${CONTAINER_PREFIX}_labels_${FRESH_CONTAINER_LABEL_PREFIX}_tag_prefix
	TAG_PREFIX=${!TAG_PREFIX_VAR}
	TAG_PREFIX=$(echo ${TAG_PREFIX} | tr -d '"')
	echovar TAG_PREFIX
	
	if ! [[ -z "${TAG_PREFIX}" ]]; then
		TAG_PREFIX_OPTION=tagPrefix=${TAG_PREFIX}
	fi


	TAG_CONSTRAINT_VAR=${CONTAINER_PREFIX}_labels_${FRESH_CONTAINER_LABEL_PREFIX}_tag_constraint
	echovar TAG_CONSTRAINT_VAR

	TAG_CONSTRAINT=${!TAG_CONSTRAINT_VAR}
	TAG_CONSTRAINT=$(echo ${TAG_CONSTRAINT} | tr -d '"')
	if ! [[ -z ${TAG_CONSTRAINT} ]]; then
		TAG_CONSTRAINT=constraint=${TAG_CONSTRAINT}
	fi
	echovar TAG_CONSTRAINT

	if ! [[ -z "${TAG_CONSTRAINT}" ]]; then  # We are using fresh container logic
		CONTAINER_MANAGED_BY_FRESH_CONTAINER=true
		# we expect the specified tag to be ${TAG}
		if ! [[ "${IMAGE_TAG}"=="${TAG}" ]]; then
			echo "Found image tag ${IMAGE_TAG}, expected \${TAG}"
			exit 1
		fi

		# Determine base tag so we can invoke fresh container with it
		if [[ -z "${IMAGE_TAG}" ]] || [[ "${IMAGE_TAG}"=="${TAG}" ]]; then
			BASE_TAG=${RUNNING_TAG}	
		else
			BASE_TAG=${IMAGE_TAG}
		fi

		if [[ -z "${BASE_TAG}" ]]; then
			BASE_TAG="1.0.0"
			echo "No currently set up tag found, using 1.0.0"
		fi

		if [[ "${BASE_TAG}" == "latest" ]]; then
                        BASE_TAG="1.0.0"
                        echo "tag 'latest' is currently used, replacing with  1.0.0"
		fi

		
		# retrieve next tag
		fetch_next_tag ${IMAGE_NAME} ${BASE_TAG} ${TAG_CONSTRAINT} ${TAG_PREFIX_OPTION}
		TAG_STATUS=$?
		if [[ ${TAG_STATUS} -ne 0 ]]; then
			echov "Exiting "${TAG_STATUS}
			exit ${TAG_STATUS}
		fi
	else  # just a regular container spec
		NEXT_TAG=${IMAGE_TAG} # just use what is in the yml		
		if ! [[ ${RUNNING_TAG}==${IMAGE_TAG} ]]; then
			echo "Warning: the running image tag ${RUNNING_TAG} is different from ${IMAGE_TAG} specified in your yml file"
		fi
		IS_STALE=true	
	fi




}

#----------------
# services_zabbixAgent_labels_com_centurylinklabs_watchtower_lifecycle_post_update=("\"/etc/zabbixAgentPostStartInContainer.sh\"")
# services_zabbixAgent_labels_com_centurylinklabs_watchtower_lifecycle_post_update_user=("\"root\"")

invokePostUpdateHook() {
	local CONTAINER_NAME=$1	
	CONTAINER_PREFIX=services_${CONTAINER_NAME}

	POST_UPDATE_PREFIX_VAR=${CONTAINER_PREFIX}_labels_${WATCH_TOWER_LABEL_PREFIX}_lifecycle_post_update
	echov "POST_UPDATE_PREFIX_VAR=${POST_UPDATE_PREFIX_VAR}"
	POST_UPDATE_CMD=${!POST_UPDATE_PREFIX_VAR}
	POST_UPDATE_CMD=$(echo ${POST_UPDATE_CMD} | tr -d '"')
	echov "POST_UPDATE_CMD=${POST_UPDATE_CMD}"

	POST_UPDATE_USER_PREFIX_VAR=${CONTAINER_PREFIX}_labels_${WATCH_TOWER_LABEL_PREFIX}_lifecycle_post_update_user
	echov "POST_UPDATE_USER_PREFIX_VAR=${POST_UPDATE_USER_PREFIX_VAR}"
	POST_UPDATE_USER=${!POST_UPDATE_USER_PREFIX_VAR}
	POST_UPDATE_USER=$(echo ${POST_UPDATE_USER} | tr -d '"')
	echov "POST_UPDATE_USER=${POST_UPDATE_USER}"

	unset POST_UPDATE_USER_OPTION
	if ! [[ -z "${POST_UPDATE_USER}" ]]; then
		POST_UPDATE_USER_OPTION="-u ${POST_UPDATE_USER}"
	fi
	
	if ! [[ -z "${POST_UPDATE_CMD}" ]]; then
		docker exec ${POST_UPDATE_USER_OPTION} ${CONTAINER_NAME} sh -c ${POST_UPDATE_CMD}
	fi
}
	
	
#---------------

PID=$(date +%N)


# Parse yml
PARSED_YML_FILE=/tmp/parsedYml-${PID}.sh
FRESH_CONTAINER_JSON_FILE=/tmp/freshContainer-${PID}.json
HEADER_FILE=/tmp/freshContainerHeaders-${PID}.sh

echov "PARSED_YML_FILE=${PARSED_YML_FILE}"
echov "FRESH_CONTAINER_JSON_FILE=${FRESH_CONTAINER_JSON_FILE}"
echov "HEADER_FILE=${HEADER_FILE}"

YML_FILE=./docker-compose.yml
if ! [[ -f ${YML_FILE} ]]; then
	echo "Could not find docker-compose.yml or yaml"
	exit 1
fi

parse_yaml ${YML_FILE} > ${PARSED_YML_FILE}
. ${PARSED_YML_FILE}

# look for override file

YML_OVERRIDE_FILE=./docker-compose.override.yml
if [[ -f ${YML_OVERRIDE_FILE} ]]; then
	echov "parsing ${YML_OVERRIDE_FILE}"
	PARSED_OVERRIDE_YML_FILE=/tmp/parsedOverrideYml-${PID}.sh
	parse_yaml ${YML_OVERRIDE_FILE} > ${PARSED_OVERRIDE_YML_FILE}
	. ${PARSED_OVERRIDE_YML_FILE}
fi




# Get Container Image Name(s) from docker-compose
CONTAINERS=$(cat docker-compose.yml | grep -i container_name: | awk -F' ' '{ print $2 }')

echov "Found Containers: "${CONTAINERS}
CONTAINERS=$(echo ${CONTAINERS} | tr -d '"')

for C in ${CONTAINERS}
do	
	echo "----- Looking for updates for ${C}"
	computeImageStatusForContainerNamed ${C}
	if ! [[ -z "${CONTAINER_MANAGED_BY_FRESH_CONTAINER}" ]]; then
		echo "   Release managed via "${TAG_CONSTRAINT}
		EXPORTED_VAR="${C}_TAG"
		eval ${EXPORTED_VAR}=${NEXT_TAG}
		echov "  Exporting ${EXPORTED_VAR}=${NEXT_TAG}"
		export ${EXPORTED_VAR}
		if [[ "${IS_STALE}" == "true" ]]; then
			echo "   Found new relase ${NEXT_TAG} for ${IMAGE_NAME}"
		else
			echo "   ${IMAGE_NAME}:${NEXT_TAG} is the current version."
		fi
	else
		echo "   will look for statically specified ${FULL_IMAGE_SPEC}"
	fi
		
done
echo "----- Stopping ${CONTAINERS}"
docker-compose down
echo "----- Updating ${CONTAINERS}"
docker-compose pull
echo "----- Restarting ${CONTAINERS}"
docker-compose up -d
echo "----- Post Update Hooks"
for C in ${CONTAINERS}
do
	invokePostUpdateHook ${C}
	if ! [[ -z ${OUTPUT_CONTAINER_LOG} ]]; then
		docker logs --since 2m -f ${C}
		unset OUTPUT_CONTAINER_LOG # only do the first one otherwise things get really confusing
	fi
done

if [[ -z ${DEBUG} ]]; then 
	rm -f ${PARSED_YML_FILE} ${PARSED_OVERRIDE_YML_FILE} 2> /dev/null
fi
