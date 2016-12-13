#!/bin/bash

n_errs=`flawfinder -DQ $1 | wc -l`
if [ "$n_errs" = "0" ]; then
  echo "No prob bob"
else 
  echo "Houston we have a problem"
fi