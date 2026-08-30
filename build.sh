#!/bin/bash

mvn clean dependency:copy-dependencies -DoutputDirectory=target/lib -DincludeScope=runtime package 
