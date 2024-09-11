#!/bin/bash
#
# This is a git pre-commit-msg hook which automatically add a 
# DCO signed-off message if one is missing.
#

MESSAGE_FILE="$1"
GIT_AUTHOR=$(git var GIT_AUTHOR_IDENT)
SIGNOFF_BY=$(echo $GIT_AUTHOR | sed -n 's/^\(.*>\).*$/Signed-off-by: \1/p')

# Verify if a DCO signoff message exists.
# Append a DCO signoff message if one doesn't exist.
if ! $(grep -qs "^$SIGNOFF_BY" "$MESSAGE_FILE") ; then
  echo -e "\n$SIGNOFF_BY" >> "$MESSAGE_FILE"
fi
exit 0
