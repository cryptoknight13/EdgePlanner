#!/bin/bash

# path to fast downward #
#VAL_PATH=$(locate VAL/validate|head -n 1)
if [ -n "$VAL_BIN_PATH" ]; then
    VAL_PATH="$VAL_BIN_PATH"
elif [ "$(uname -s)" = "Linux" ]; then
    VAL_PATH="../../../../../VAL/build/linux64/Release/bin/Validate"
else
    VAL_PATH="../../../../../VAL/build/macos64/Release/bin/Validate"
fi
# validate plan given domain and problem
#output=$(${VAL_PATH} $1 $2 $3 | grep "Successful plans:"|wc -l)

out=$VAL_PATH $1 $2 $3 
print(out)

#if [ ${output} -gt 0 ]; then
#    echo "True"
#else
#    echo "False"
#fi
