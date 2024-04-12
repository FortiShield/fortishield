#!/bin/bash

# Copyright (C) 2015, KhulnaSoft Ltd.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Global variables
INSTALLDIR=${1}
CONF_FILE="${INSTALLDIR}/etc/ossec.conf"
TMP_ENROLLMENT="${INSTALLDIR}/tmp/enrollment-configuration"
TMP_SERVER="${INSTALLDIR}/tmp/server-configuration"
FORTISHIELD_REGISTRATION_PASSWORD_PATH="etc/authd.pass"
FORTISHIELD_MACOS_AGENT_DEPLOYMENT_VARS="/tmp/fortishield_envs"


# Set default sed alias
sed="sed -ri"
# By default, use gnu sed (gsed).
use_unix_sed="False"

# Special function to use generic sed
unix_sed() {

    sed_expression="$1"
    target_file="$2"
    special_args="$3"

    sed ${special_args} "${sed_expression}" "${target_file}" > "${target_file}.tmp"
    cat "${target_file}.tmp" > "${target_file}"
    rm "${target_file}.tmp"

}

# Update the value of a XML tag inside the ossec.conf
edit_value_tag() {

    file=""

    if [ -z "$3" ]; then
        file="${CONF_FILE}"
    else
        file="${TMP_ENROLLMENT}"
    fi

    if [ -n "$1" ] && [ -n "$2" ]; then
        start_config="$(grep -n "<$1>" "${file}" | cut -d':' -f 1)"
        end_config="$(grep -n "</$1>" "${file}" | cut -d':' -f 1)"
        if [ -z "${start_config}" ] && [ -z "${end_config}" ] && [ "${file}" = "${TMP_ENROLLMENT}" ]; then
            echo "      <$1>$2</$1>" >> "${file}"
        elif [ "${use_unix_sed}" = "False" ] ; then
            ${sed} "s#<$1>.*</$1>#<$1>$2</$1>#g" "${file}"
        else
            unix_sed "s#<$1>.*</$1>#<$1>$2</$1>#g" "${file}"
        fi
    fi
    
    if [ "$?" != "0" ]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') agent-auth: Error updating $2 with variable $1." >> "${INSTALLDIR}/logs/ossec.log"
    fi

}

delete_blank_lines() {

    file=$1
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} '/^$/d' "${file}"
    else
        unix_sed '/^$/d' "${file}"
    fi

}

delete_auto_enrollment_tag() {

    # Delete the configuration tag if its value is empty
    # This will allow using the default value
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "s#.*<$1>.*</$1>.*##g" "${TMP_ENROLLMENT}"
    else
        unix_sed "s#.*<$1>.*</$1>.*##g" "${TMP_ENROLLMENT}"
    fi

    cat -s "${TMP_ENROLLMENT}" > "${TMP_ENROLLMENT}.tmp"
    mv "${TMP_ENROLLMENT}.tmp" "${TMP_ENROLLMENT}"

}

# Change address block of the ossec.conf
add_adress_block() {

    # Remove the server configuration
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "/<server>/,/\/server>/d" "${CONF_FILE}"
    else
        unix_sed "/<server>/,/\/server>/d" "${CONF_FILE}"
    fi

    # Write the client configuration block
    for i in "${!ADDRESSES[@]}";
    do
        {
            echo "    <server>"
            echo "      <address>${ADDRESSES[i]}</address>"
            echo "      <port>1514</port>"
            if [ -n "${PROTOCOLS[i]}" ]; then
                echo "      <protocol>${PROTOCOLS[i]}</protocol>"
            else
                echo "      <protocol>tcp</protocol>"
            fi 
            echo "    </server>"
        } >> "${TMP_SERVER}"
    done

    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "/<client>/r ${TMP_SERVER}" "${CONF_FILE}"
    else
        unix_sed "/<client>/r ${TMP_SERVER}" "${CONF_FILE}"
    fi

    rm -f "${TMP_SERVER}"

}

add_parameter () {

    if [ -n "$3" ]; then
        OPTIONS="$1 $2 $3"
    fi
    echo "${OPTIONS}"

}

get_deprecated_vars () {

    if [ -n "${FORTISHIELD_MANAGER_IP}" ] && [ -z "${FORTISHIELD_MANAGER}" ]; then
        FORTISHIELD_MANAGER=${FORTISHIELD_MANAGER_IP}
    fi
    if [ -n "${FORTISHIELD_AUTHD_SERVER}" ] && [ -z "${FORTISHIELD_REGISTRATION_SERVER}" ]; then
        FORTISHIELD_REGISTRATION_SERVER=${FORTISHIELD_AUTHD_SERVER}
    fi
    if [ -n "${FORTISHIELD_AUTHD_PORT}" ] && [ -z "${FORTISHIELD_REGISTRATION_PORT}" ]; then
        FORTISHIELD_REGISTRATION_PORT=${FORTISHIELD_AUTHD_PORT}
    fi
    if [ -n "${FORTISHIELD_PASSWORD}" ] && [ -z "${FORTISHIELD_REGISTRATION_PASSWORD}" ]; then
        FORTISHIELD_REGISTRATION_PASSWORD=${FORTISHIELD_PASSWORD}
    fi
    if [ -n "${FORTISHIELD_NOTIFY_TIME}" ] && [ -z "${FORTISHIELD_KEEP_ALIVE_INTERVAL}" ]; then
        FORTISHIELD_KEEP_ALIVE_INTERVAL=${FORTISHIELD_NOTIFY_TIME}
    fi
    if [ -n "${FORTISHIELD_CERTIFICATE}" ] && [ -z "${FORTISHIELD_REGISTRATION_CA}" ]; then
        FORTISHIELD_REGISTRATION_CA=${FORTISHIELD_CERTIFICATE}
    fi
    if [ -n "${FORTISHIELD_PEM}" ] && [ -z "${FORTISHIELD_REGISTRATION_CERTIFICATE}" ]; then
        FORTISHIELD_REGISTRATION_CERTIFICATE=${FORTISHIELD_PEM}
    fi
    if [ -n "${FORTISHIELD_KEY}" ] && [ -z "${FORTISHIELD_REGISTRATION_KEY}" ]; then
        FORTISHIELD_REGISTRATION_KEY=${FORTISHIELD_KEY}
    fi
    if [ -n "${FORTISHIELD_GROUP}" ] && [ -z "${FORTISHIELD_AGENT_GROUP}" ]; then
        FORTISHIELD_AGENT_GROUP=${FORTISHIELD_GROUP}
    fi

}

set_vars () {

    export FORTISHIELD_MANAGER
    export FORTISHIELD_MANAGER_PORT
    export FORTISHIELD_PROTOCOL
    export FORTISHIELD_REGISTRATION_SERVER
    export FORTISHIELD_REGISTRATION_PORT
    export FORTISHIELD_REGISTRATION_PASSWORD
    export FORTISHIELD_KEEP_ALIVE_INTERVAL
    export FORTISHIELD_TIME_RECONNECT
    export FORTISHIELD_REGISTRATION_CA
    export FORTISHIELD_REGISTRATION_CERTIFICATE
    export FORTISHIELD_REGISTRATION_KEY
    export FORTISHIELD_AGENT_NAME
    export FORTISHIELD_AGENT_GROUP
    export ENROLLMENT_DELAY
    # The following variables are yet supported but all of them are deprecated
    export FORTISHIELD_MANAGER_IP
    export FORTISHIELD_NOTIFY_TIME
    export FORTISHIELD_AUTHD_SERVER
    export FORTISHIELD_AUTHD_PORT
    export FORTISHIELD_PASSWORD
    export FORTISHIELD_GROUP
    export FORTISHIELD_CERTIFICATE
    export FORTISHIELD_KEY
    export FORTISHIELD_PEM

    if [ -r "${FORTISHIELD_MACOS_AGENT_DEPLOYMENT_VARS}" ]; then
        . ${FORTISHIELD_MACOS_AGENT_DEPLOYMENT_VARS}
        rm -rf "${FORTISHIELD_MACOS_AGENT_DEPLOYMENT_VARS}"
    fi

}

unset_vars() {

    vars=(FORTISHIELD_MANAGER_IP FORTISHIELD_PROTOCOL FORTISHIELD_MANAGER_PORT FORTISHIELD_NOTIFY_TIME \
          FORTISHIELD_TIME_RECONNECT FORTISHIELD_AUTHD_SERVER FORTISHIELD_AUTHD_PORT FORTISHIELD_PASSWORD \
          FORTISHIELD_AGENT_NAME FORTISHIELD_GROUP FORTISHIELD_CERTIFICATE FORTISHIELD_KEY FORTISHIELD_PEM \
          FORTISHIELD_MANAGER FORTISHIELD_REGISTRATION_SERVER FORTISHIELD_REGISTRATION_PORT \
          FORTISHIELD_REGISTRATION_PASSWORD FORTISHIELD_KEEP_ALIVE_INTERVAL FORTISHIELD_REGISTRATION_CA \
          FORTISHIELD_REGISTRATION_CERTIFICATE FORTISHIELD_REGISTRATION_KEY FORTISHIELD_AGENT_GROUP \
          ENROLLMENT_DELAY)

    for var in "${vars[@]}"; do
        unset "${var}"
    done

}

# Function to convert strings to lower version
tolower () {

    echo "$1" | tr '[:upper:]' '[:lower:]'

}


# Add auto-enrollment configuration block
add_auto_enrollment () {

    start_config="$(grep -n "<enrollment>" "${CONF_FILE}" | cut -d':' -f 1)"
    end_config="$(grep -n "</enrollment>" "${CONF_FILE}" | cut -d':' -f 1)"
    if [ -n "${start_config}" ] && [ -n "${end_config}" ]; then
        start_config=$(( start_config + 1 ))
        end_config=$(( end_config - 1 ))
        sed -n "${start_config},${end_config}p" "${INSTALLDIR}/etc/ossec.conf" >> "${TMP_ENROLLMENT}"
    else
        # Write the client configuration block
        {
            echo "    <enrollment>"
            echo "      <enabled>yes</enabled>"
            echo "      <manager_address>MANAGER_IP</manager_address>"
            echo "      <port>1515</port>"
            echo "      <agent_name>agent</agent_name>"
            echo "      <groups>Group1</groups>"
            echo "      <server_ca_path>/path/to/server_ca</server_ca_path>"
            echo "      <agent_certificate_path>/path/to/agent.cert</agent_certificate_path>"
            echo "      <agent_key_path>/path/to/agent.key</agent_key_path>"
            echo "      <authorization_pass_path>/path/to/authd.pass</authorization_pass_path>"
            echo "      <delay_after_enrollment>20</delay_after_enrollment>"
            echo "    </enrollment>" 
        } >> "${TMP_ENROLLMENT}"
    fi

}

# Add the auto_enrollment block to the configuration file
concat_conf() {

    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "/<\/crypto_method>/r ${TMP_ENROLLMENT}" "${CONF_FILE}"
    else
        unix_sed "/<\/crypto_method>/r ${TMP_ENROLLMENT}/" "${CONF_FILE}"
    fi

    rm -f "${TMP_ENROLLMENT}"

}

# Set autoenrollment configuration
set_auto_enrollment_tag_value () {

    tag="$1"
    value="$2"

    if [ -n "${value}" ]; then
        edit_value_tag "${tag}" "${value}" "auto_enrollment"
    else
        delete_auto_enrollment_tag "${tag}" "auto_enrollment"
    fi

}

# Main function the script begin here
main () {

    uname_s=$(uname -s)

    # Check what kind of system we are working with
    if [ "${uname_s}" = "Darwin" ]; then
        sed="sed -ire"
        set_vars
    elif [ "${uname_s}" = "AIX" ] || [ "${uname_s}" = "SunOS" ] || [ "${uname_s}" = "HP-UX" ]; then
        use_unix_sed="True"
    fi

    get_deprecated_vars

    if [ -z "${FORTISHIELD_MANAGER}" ] && [ -n "${FORTISHIELD_PROTOCOL}" ]; then
        PROTOCOLS=( $(tolower "${FORTISHIELD_PROTOCOL//,/ }") )
        edit_value_tag "protocol" "${PROTOCOLS[0]}"
    fi

    if [ -n "${FORTISHIELD_MANAGER}" ]; then
        if [ ! -f "${INSTALLDIR}/logs/ossec.log" ]; then
            touch -f "${INSTALLDIR}/logs/ossec.log"
            chmod 660 "${INSTALLDIR}/logs/ossec.log"
            chown root:fortishield "${INSTALLDIR}/logs/ossec.log"
        fi

        # Check if multiples IPs are defined in variable FORTISHIELD_MANAGER
        ADDRESSES=( ${FORTISHIELD_MANAGER//,/ } ) 
        PROTOCOLS=( $(tolower "${FORTISHIELD_PROTOCOL//,/ }") )
        # Get uniques values if all protocols are the same
        if ( [ "${#PROTOCOLS[@]}" -ge "${#ADDRESSES[@]}" ] && ( ( ! echo "${PROTOCOLS[@]}" | grep -q -w "tcp" ) || ( ! echo "${PROTOCOLS[@]}" | grep -q -w "udp" ) ) ) || [ ${#PROTOCOLS[@]} -eq 0 ] || ( ! echo "${PROTOCOLS[@]}" | grep -q -w "udp" ) ; then
            ADDRESSES=( $(echo "${ADDRESSES[@]}" |  tr ' ' '\n' | cat -n | sort -uk2 | sort -n | cut -f2- | tr '\n' ' ') ) 
        fi
        
        add_adress_block
    fi

    edit_value_tag "port" "${FORTISHIELD_MANAGER_PORT}"

    if [ -n "${FORTISHIELD_REGISTRATION_SERVER}" ] || [ -n "${FORTISHIELD_REGISTRATION_PORT}" ] || [ -n "${FORTISHIELD_REGISTRATION_CA}" ] || [ -n "${FORTISHIELD_REGISTRATION_CERTIFICATE}" ] || [ -n "${FORTISHIELD_REGISTRATION_KEY}" ] || [ -n "${FORTISHIELD_AGENT_NAME}" ] || [ -n "${FORTISHIELD_AGENT_GROUP}" ] || [ -n "${ENROLLMENT_DELAY}" ] || [ -n "${FORTISHIELD_REGISTRATION_PASSWORD}" ]; then
        add_auto_enrollment
        set_auto_enrollment_tag_value "manager_address" "${FORTISHIELD_REGISTRATION_SERVER}"
        set_auto_enrollment_tag_value "port" "${FORTISHIELD_REGISTRATION_PORT}"
        set_auto_enrollment_tag_value "server_ca_path" "${FORTISHIELD_REGISTRATION_CA}"
        set_auto_enrollment_tag_value "agent_certificate_path" "${FORTISHIELD_REGISTRATION_CERTIFICATE}"
        set_auto_enrollment_tag_value "agent_key_path" "${FORTISHIELD_REGISTRATION_KEY}"
        set_auto_enrollment_tag_value "authorization_pass_path" "${FORTISHIELD_REGISTRATION_PASSWORD_PATH}"
        set_auto_enrollment_tag_value "agent_name" "${FORTISHIELD_AGENT_NAME}"
        set_auto_enrollment_tag_value "groups" "${FORTISHIELD_AGENT_GROUP}"
        set_auto_enrollment_tag_value "delay_after_enrollment" "${ENROLLMENT_DELAY}"
        delete_blank_lines "${TMP_ENROLLMENT}"
        concat_conf
    fi

            
    if [ -n "${FORTISHIELD_REGISTRATION_PASSWORD}" ]; then
        echo "${FORTISHIELD_REGISTRATION_PASSWORD}" > "${INSTALLDIR}/${FORTISHIELD_REGISTRATION_PASSWORD_PATH}"
        chmod 640 "${INSTALLDIR}"/"${FORTISHIELD_REGISTRATION_PASSWORD_PATH}"
        chown root:fortishield "${INSTALLDIR}"/"${FORTISHIELD_REGISTRATION_PASSWORD_PATH}"
    fi

    # Options to be modified in ossec.conf
    edit_value_tag "notify_time" "${FORTISHIELD_KEEP_ALIVE_INTERVAL}"
    edit_value_tag "time-reconnect" "${FORTISHIELD_TIME_RECONNECT}"

    unset_vars

}

# Start script execution
main "$@"
