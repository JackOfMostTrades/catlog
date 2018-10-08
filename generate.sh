#!/bin/sh

protoc -I=. --python_out=src/catlog ./catlog.proto
wget -O src/catlog/all_logs_list.json https://www.gstatic.com/ct/log_list/all_logs_list.json
