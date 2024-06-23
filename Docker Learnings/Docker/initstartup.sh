#!/bin/bash
echo "in init startup.sh"
for file in ${DCTM_CMIS_DIR}/*
do
  # append the basename of the file to the target folder
  target_file="${DCTM_CMIS_EXT_DIR}/$(basename "$file")"
  if [ "$(basename "$file")" != "initstartup.sh" ]; then
     if [ ! -f "$target_file" ]; then
        # copy file if it does not exist in target folder
        cp -p "$file" "$target_file"
        #copy file if it is newer than the one in the target folder considering timezone difference.
     elif [ "$(date -r "$file" +%s)" -gt "$(date -r "$target_file" +%s)" ]; then
        cp -pf "$file" "$target_file"
     fi     
  fi
done