#!/usr/bin/env python
#coding:utf-8

import cgi

print "Content-Type: text/html"     # HTML is following
print                               # blank line, end of headers

print "<html>"
print "<head>"
print "<meta http-equiv='Content-Type' content='text/html; charset=utf-8' />"
print "<title>CGI script output</title>"
print "</head>"
print "<body>"
print "<H1>這是我的第一個應用程式</H1>"
print "哈嚕，大家早安!"
print cgi.print_environ()
print cgi.print_environ_usage()
print "</body>"
