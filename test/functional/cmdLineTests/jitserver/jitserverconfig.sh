# Copyright IBM Corp. and others 2023
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License 2.0 which accompanies this
# distribution and is available at https://www.eclipse.org/legal/epl-2.0/
# or the Apache License, Version 2.0 which accompanies this distribution and
# is available at https://www.apache.org/licenses/LICENSE-2.0.
#
# This Source Code may also be made available under the following
# Secondary Licenses when the conditions for such availability set
# forth in the Eclipse Public License, v. 2.0 are satisfied: GNU
# General Public License, version 2 with the GNU Classpath
# Exception [1] and GNU General Public License, version 2 with the
# OpenJDK Assembly Exception [2].
#
# [1] https://www.gnu.org/software/classpath/license.html
# [2] https://openjdk.org/legal/assembly-exception.html
#
# SPDX-License-Identifier: EPL-2.0 OR Apache-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0 OR GPL-2.0-only WITH OpenJDK-assembly-exception-1.0
#

START_PORT=38400
END_PORT=60000

DIFF=$(($END_PORT-$START_PORT+1))
RANDOM=$$

random_port () {
    if [ ! -x "ss" ]; then
        RANDOM_PORT=$(($(($RANDOM%$DIFF))+$START_PORT))
        >&2 echo "Command ss is not available, returning random port $RANDOM_PORT"
        echo $RANDOM_PORT
        exit 0
    fi

    retVal=0
    while [ $retVal -eq 0 ]
    do
        RANDOM_PORT=$(($(($RANDOM%$DIFF))+$START_PORT))
        >&2 echo "Trying $RANDOM_PORT"
        # Test if $RANDOM_PORT is in use at all by checking if the (header-suppressed, filtered)
        # output of ss is non-empty
        if [ -n "$( ss -Hplunt \( src = :$RANDOM_PORT \) )" ]; then
            retVal=1
        fi
    done

    >&2 echo "Found unused port $RANDOM_PORT"
    echo "$RANDOM_PORT"
}
