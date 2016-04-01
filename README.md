# SNMPPLUX
An SNMPv1, v2c and v3 dictionary attack tool. Please see: https://penturalabs.wordpress.com/2016/04/01/snmpplux/

Pentura continually develop new tools and scripts to improve the effectiveness of the team. One such tool called SNMPPLUX is an offshoot of a larger development project (ORR).
SNMPPLUX is a USM compliant SNMPv1, SNMPv2c and SNMPv3 authentication scanner powered by pysnmp, re, sys, getopt, array, time and multiprocessing python modules.
As well as providing SNMPv1 and v2c community dictionary attacks is will also provide username and password dictionary attacks for SNMPv3 for the following authentication types:
• SNMPv3 Auth None
• SNMPv3 Auth MD5 Priv None
• SNMPv3 Auth MD5 Priv DES
• SNMPv3 Auth SHA Priv AES128
• SNMPv3 Auth SHA Priv AES192
• SNMPv3 Auth SHA Priv AES256
• SNMPv3 Auth SHA Priv DES
• SNMPv3 Auth SHA Priv 3DES

Whilst multiprocessing is currently used to speed up testing with parallel processes the future plan is to include distributed processing to enable testing of large networks. A library version of this code is also utilised as part of the ORR project.

The current source code for this tool is included below on an as is basis. It may need to be reformatted to remove syntax and indenting errors introduced by providing the source in this format. Please see the License/Disclaimer below before using this software
