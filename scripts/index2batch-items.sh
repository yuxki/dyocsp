#!/bin/bash
if [ "$#" != "3" ]; then
  echo "Usage: $(basename "$0") <table_name> <ca_name> <index_file>"
  exit 1
fi

if [ ! -f "$3" ]; then
  echo "No such file: $3"
  exit 1
fi

echo -n "{\"$1\":["
items="$(awk '
  BEGIN {
    FS=" "
  }
  {
    type = $1
    exp_date = $2

    if (index($3, "Z") > 0) {
      split($3, rd_cr_pair, ",")
      rev_date = rd_cr_pair[1]
      crl_reason = rd_cr_pair[2]
      serial = $4
      file = $5
    }
    else {
      rev_date = ""
      crl_reason = ""
      serial = $3
      file = $4
    }

    match($0, r"/")
    name = substr($0, RSTART)
  }
  {
    printf("{\"PutRequest\":{\"Item\":{\"ca\":{\"S\": \"%s\"},\"serial\":{\"S\": \"%s\"},\"rev_type\":{\"S\": \"%s\"},\"exp_date\":{\"S\": \"%s\"},\"rev_date\":{\"S\": \"%s\"},\"file_name\":{\"S\": \"%s\"},\"subject_name\":{\"S\": \"%s\"},\"crl_reason\":{\"S\": \"%s\"}}}},", ca, serial, type, exp_date, rev_date, file, name, crl_reason)
  }' "ca=$2" "$3")"
items="${items::-1}"
echo -n "$items"
echo -n "]}"
