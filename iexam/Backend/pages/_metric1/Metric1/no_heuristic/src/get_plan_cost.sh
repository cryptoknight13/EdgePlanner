#!/bin/bash


cat sas_plan |grep "\; cost ="|awk '{print $4}'
rm sas_plan
