# Static analysis malicious files
*Analysis malicious files in deep with clamscan and yara rules.*

This tool written in python langage makes the link between clam and yara. It can help you to score suspect file, can build visual tree graph for fast display embeded files (parent type, type, suspect or dangerous content), and can compute indicator of compromission. It uses clamav in order to extract embeded files and make json tree, then it sends all embbeded files to yara with context (in externs variables) in order to check rules. If a rules matched, it gives score of this rule. The max rule score is added to top of tree, you can add globale score that use all score found for make coefficient score. Extra feature, the tool can extract specific pattern (URL, HOST, IP, ...).

## Features
- Clamscan extracts embedded files and makes json report
- Clamscan check password on zip encrypted (ref: https://blog.didierstevens.com/2017/02/15/quickpost-clamav-and-zip-file-decryption/)
- Analyse json report and make json trees to consolidate informations
- Extract patterns (pattern.db) with the ability to use the yara rules
- Scan embedded files and root file with yara rules (+context informations in externs variables: type, parent type, pattern extract, ...)
  - 2 level of yara rules (order), for gain fast and avoid multi rules (same) for each extension
    - First level: format-specific rule 
      - check file type (reg, chm, exe, dll, ...) and potential risk according by extension (script, autopen, ...).Then push (by external variable) check only element linked with extension for level 2
      - check file origin: embed file
    - Second level: global rules same for multi format
      - check if unknown file type (extension): entropy, ...
      - check suspect content file: obfuscate, cypher, packed, ...
      - check dangerous elements (Mitre Attack): registry, command, ... 
      - check IOC familly malware (MISP import)
- Compute risk score
  - Put max score on top of tree
  - Add global score with coefficient mechanism (coef.conf) to max score
- Create PNG graph for fast analysis
- Output result tree json in a file

## Usage
~~~
Static analysis by clamav and yara rules -- Contact: lionel.prat9@gmail.com
Usage: analysis.py [-c /usr/local/bin/clamscan] [-d /tmp/extract_emmbedded] [-p pattern.db] [-s /tmp/graph.png] [-j /tmp/result.json] [-m coef_path] [-g] [-v] -f path_filename -y yara_rules_path1/ -a yara_rules_path2/ -b password.pwdb 


	 -h/--help : how to use

	 -f/--filename= : path of filename to analyse

	 -y/--yara_rules_path= : path of rules yara level 1

         -a/--yara_rules_path2= : path of rules yara level 2

	 -b/--password= : path of password clamav (.pwdb see: https://blog.didierstevens.com/2017/02/15/quickpost-clamav-and-zip-file-decryption/)

	 -p/--pattern= : path of pattern filename for data miner

	 -c/--clamscan_path= : path of binary clamscan [>=0.99.3]

	 -m/--coef_path= : path of coef config file

	 -d/--directory_tmp= : path of directory to extract emmbedded file(s)

	 -j/--json_save= : path filename where save json result (JSON)

	 -g/--graph : generate graph of analyz

	 -s/--save_graph= : path where to saves the graph (PNG)

	 -v/--verbose= : verbose mode

	 example: analysis.py -c ./clamav-devel/clamscan/clamscan -f /home/analyz/strange/invoice.rtf -y /home/analyz/yara_rules1/ -a /home/analyz/yara_rules2/ -b /home/analyz/password.pwdb -g

lionel@local:~/static_analysis$ python analysis.py -c clamav-devel/clamscan/clamscan -g -f tests/pdf/jaff.pdf -y yara_rules/  -j /tmp/log.json -p pattern.db
Static analysis by clamav and yara rules -- Contact: lionel.prat9@gmail.com
Create directory temp for emmbedded file: /tmp/tmpUee2rj

Extract emmbedded file(s) with clamav...
Analyz result...
Find resultat in json file:/tmp/tmpUee2rj/clamav-028bf4c91d9aac94faca83886b9286c2.tmp...
Phase one finish!


~~~

## PNG report example for jaff
![alt text](https://github.com/lprat/static_analysis/raw/master/images/analysis_result.png "Tree analysis created")

## JSON report example for jaff
```json
{
    "ContainedObjects": [
        {
            "ContainedObjects": [
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/package/2006/content-types\"><Default', 't')"
                        }
                    ], 
                    "FileMD5": "ac4128108023cf8d9a6233069bd79f7a", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 1636, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.000"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship', 'p')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\"', '\"')"
                        }
                    ], 
                    "FileMD5": "77bf61733a633ea617a4db76ef769a4d", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 590, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.001"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship', 'p')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/2006/relationships/vbaProject\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships/webSettings\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings\"', '\"')"
                        }
                    ], 
                    "FileMD5": "83bb79d7c3592786e13acb56729962ce", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 1213, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.002"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/drawing/2014/chartex\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/markup-compatibility/2006\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/math\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/wordprocessingml/2006/main\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2012/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2015/wordml/symex\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordprocessingGroup\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordprocessingInk\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2006/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordprocessingShape\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/drawingml/2006/main\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/drawingml/2006/main\"><a:graphicData', 'a')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/drawingml/2006/picture\"><pic:pic', 'c')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/drawingml/2006/picture\"><pic:nvPicPr><pic:cNvPr', 'r')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/drawing/2010/main\"', '\"')"
                        }
                    ], 
                    "FileMD5": "452348b0a8f499c7f125ba299731db0a", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 4362, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.003"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship', 'p')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/2006/relationships/wordVbaData\"', '\"')"
                        }
                    ], 
                    "FileMD5": "dd79e6440b0515bfcf771c2c5286a2c8", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 277, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.004"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ContainedObjects": [
                        {
                            "ExtractInfo": [], 
                            "FileMD5": "1b51a805a2682c24956f156ff25370ff", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 292, 
                            "FileType": "CL_TYPE_TEXT_ASCII", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000010/cbff003cd69100e2ee9bd33df50c21ed_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000010/cbff003cd69100e2ee9bd33df50c21ed_0"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ExtractInfo": [
                                {
                                    "URI": "('http://\\x00\\xec', '\\xec')"
                                }
                            ], 
                            "FileMD5": "0df7f5507fcccc3bc22787fe7872e97a", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 584, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000010/d95679752134a2d9eb61dbd7b91c4bcc_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000010/d95679752134a2d9eb61dbd7b91c4bcc_0"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ExtractInfo": [], 
                            "FileMD5": "8b485527ad9d96fe72d3fba385f0ad95", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 97, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000010/88144fbcb62650fa72c360688f4772c7_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000010/88144fbcb62650fa72c360688f4772c7_0"
                            ], 
                            "RiskScore": 5, 
                            "Yara": [
                                {
                                    "OLE_EMBEDDED_OFFICE": {
                                        "description": "MS Forms Embedded object", 
                                        "score": 5
                                    }
                                }
                            ]
                        }, 
                        {
                            "ExtractInfo": [], 
                            "FileMD5": "711e41c84dfaa4cbd891ef22cc4e4670", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 599, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000010/8fa14cdd754f91cc6554c9e71929cce7_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000010/8fa14cdd754f91cc6554c9e71929cce7_0"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ExtractInfo": [
                                {
                                    "EMAIL": "('Templat@eDeriv', '')"
                                }
                            ], 
                            "FileMD5": "8a01d7813c6dc6dddf8398f15e45756f", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 1897, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000001/5f51988f4ee5c4069990859c24855c57_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000001/5f51988f4ee5c4069990859c24855c57_0"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ExtractInfo": [], 
                            "FileMD5": "fcc31d50fc38f37137eb5b2cf2992049", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 1504, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000001/bad8252681321a1d94d0718a0815fac9_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000001/bad8252681321a1d94d0718a0815fac9_0"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ExtractInfo": [
                                {
                                    "EMAIL": "('OptionButton1k@0', '')"
                                }, 
                                {
                                    "EMAIL": "('OptionButton2l@0', '')"
                                }
                            ], 
                            "FileMD5": "0eed2de1ef79e6ce4a26385fd5179d5e", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 6394, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000001/ae4f6474bee50ccdf1a6b853ba8ad32a_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000001/ae4f6474bee50ccdf1a6b853ba8ad32a_0"
                            ], 
                            "RiskScore": 4, 
                            "Yara": [
                                {
                                    "Autorun_VBA_OFFICE": {
                                        "description": "Macro autorun", 
                                        "score": 4
                                    }
                                }
                            ]
                        }, 
                        {
                            "ExtractInfo": [
                                {
                                    "EMAIL": "('Hr2d2_@c3po', '')"
                                }, 
                                {
                                    "EMAIL": "('cF@reshID', '')"
                                }, 
                                {
                                    "EMAIL": "('ob@jWMISe', '')"
                                }
                            ], 
                            "FileMD5": "828a327f1ddc838d4a8c19619cebfee8", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 3030, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000001/007ccaa83aa7674f1166352c3605b85c_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000001/007ccaa83aa7674f1166352c3605b85c_0"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ExtractInfo": [
                                {
                                    "EMAIL": "('tp@d', '')"
                                }
                            ], 
                            "FileMD5": "c81239f4227f76858b5e2a5bd59afa0e", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 9634, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000001/a63bcda17f702e84c1b7056f6d8c5f3a_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000001/a63bcda17f702e84c1b7056f6d8c5f3a_0"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ExtractInfo": [
                                {
                                    "EMAIL": "('SF@Cs', '')"
                                }, 
                                {
                                    "EMAIL": "('VBE@a', '')"
                                }
                            ], 
                            "FileMD5": "54c9cc25c5082fee750c4e05196a595b", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 945, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000001/736007832d2167baaae763fd3a3f3cf1_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000001/736007832d2167baaae763fd3a3f3cf1_0"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ExtractInfo": [], 
                            "FileMD5": "d34c4883d74d420deb12df91f806b869", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 1158, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000001/69bb302a1ba85bde463b0b6faaea307a_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000001/69bb302a1ba85bde463b0b6faaea307a_0"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ExtractInfo": [
                                {
                                    "EMAIL": "('co,lI@BA', '')"
                                }, 
                                {
                                    "EMAIL": "('agReturn@Immedi', '')"
                                }, 
                                {
                                    "EMAIL": "('Vb@Method', '')"
                                }, 
                                {
                                    "EMAIL": "('g43ff4@f.net', '')"
                                }
                            ], 
                            "FileMD5": "0ceca08df2cc3d69bdf6852ca2e341ce", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 6783, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/000001/f9cce95db5c816a935906a713c78aff5_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/000001/f9cce95db5c816a935906a713c78aff5_0"
                            ], 
                            "RiskScore": 5, 
                            "Yara": [
                                {
                                    "Filesystem_Vba_OFFICE": {
                                        "description": "Macro acces file system object with AutoOpen", 
                                        "score": 5
                                    }
                                }
                            ]
                        }, 
                        {
                            "ExtractInfo": [], 
                            "FileMD5": "504c824e56e508c488c2f87a63d847d9", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 155, 
                            "FileType": "CL_TYPE_BINARY_DATA", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/7fdc011725f5de6d8e10d5fc95398f30_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/7fdc011725f5de6d8e10d5fc95398f30_0"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ExtractInfo": [], 
                            "FileMD5": "f2a98e8d16b27939c3cbdef3bebbdc1c", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2||||->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                            "FileSize": 666, 
                            "FileType": "CL_TYPE_TEXT_ASCII", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-1850c820caed3a2ef0bd9f90767cee2d.tmp/46f86faa6bbf9ac94a7e459509a20ed0_0", 
                                "/tmp/tmpUee2rj/clamav-47fe5aa763775ab138ffb62ea46690b5.tmp/46f86faa6bbf9ac94a7e459509a20ed0_0"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ContainedObjects": [], 
                            "ExtractInfo": [], 
                            "FileMD5": "bcbe7dbf9f99c4e0e534c3a2ac4f6ab4", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2", 
                            "FileSize": 382, 
                            "FileType": "CL_TYPE_UNKNOWN", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-48b2068c734e0dd2524018b91bdc11f1.tmp"
                            ], 
                            "RiskScore": 4, 
                            "Yara": [
                                {
                                    "Autorun_VBA_OFFICE": {
                                        "description": "Macro autorun", 
                                        "score": 4
                                    }
                                }
                            ]
                        }, 
                        {
                            "ContainedObjects": [], 
                            "ExtractInfo": [], 
                            "FileMD5": "ef4e50431c649c188d1a98d2f303d7a5", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2", 
                            "FileSize": 340, 
                            "FileType": "CL_TYPE_UNKNOWN", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-e2dd3b37165650823319a0a29d38ef8f.tmp"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ContainedObjects": [], 
                            "ExtractInfo": [], 
                            "FileMD5": "0d51f172a35e98a1bb73438b694e52ab", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2", 
                            "FileSize": 650, 
                            "FileType": "CL_TYPE_UNKNOWN", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-9ccce68e0439e9037ff734e27b28b998.tmp"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ContainedObjects": [], 
                            "ExtractInfo": [], 
                            "FileMD5": "95a55e38861c99daf23ce36d40a101d9", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2", 
                            "FileSize": 5682, 
                            "FileType": "CL_TYPE_UNKNOWN", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-f1a4e0a4bbef215ddbd1d85d2681e7bd.tmp"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ContainedObjects": [], 
                            "ExtractInfo": [], 
                            "FileMD5": "6ed1b03a4828d15bca41ac0d6604e763", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2", 
                            "FileSize": 1240, 
                            "FileType": "CL_TYPE_UNKNOWN", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-a5674c419d8687d2de2fb5db2fafc049.tmp"
                            ], 
                            "RiskScore": 0, 
                            "Yara": []
                        }, 
                        {
                            "ContainedObjects": [], 
                            "ExtractInfo": [], 
                            "FileMD5": "621e099c1b10736db897668de89afb0b", 
                            "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_MSOLE2", 
                            "FileSize": 3384, 
                            "FileType": "CL_TYPE_UNKNOWN", 
                            "PathFile": [
                                "/tmp/tmpUee2rj/clamav-f1803c916e78e329874565085182796e.tmp"
                            ], 
                            "RiskScore": 5, 
                            "Yara": [
                                {
                                    "Filesystem_Vba_OFFICE": {
                                        "description": "Macro acces file system object with AutoOpen", 
                                        "score": 5
                                    }
                                }
                            ]
                        }
                    ], 
                    "ExtractInfo": [
                        {
                            "EMAIL": "('Templat@eDeriv', '')"
                        }, 
                        {
                            "EMAIL": "('tp@d', '')"
                        }, 
                        {
                            "EMAIL": "('Hr2d2_@c3po', '')"
                        }, 
                        {
                            "EMAIL": "('cF@reshID', '')"
                        }, 
                        {
                            "EMAIL": "('ob@jWMISe', '')"
                        }, 
                        {
                            "EMAIL": "('SF@Cs', '')"
                        }, 
                        {
                            "EMAIL": "('co,lI@BA', '')"
                        }, 
                        {
                            "EMAIL": "('agReturn@Immedi', '')"
                        }, 
                        {
                            "EMAIL": "('Vb@Method', '')"
                        }, 
                        {
                            "EMAIL": "('g43ff4@f.net', '')"
                        }, 
                        {
                            "EMAIL": "('OptionButton1k@0', '')"
                        }, 
                        {
                            "EMAIL": "('OptionButton2l@0', '')"
                        }, 
                        {
                            "EMAIL": "('VBE@a', '')"
                        }, 
                        {
                            "URI": "('http://\\x00\\xec', '\\xec')"
                        }
                    ], 
                    "FileMD5": "d45c11614628b38df9301bccf18c67f4", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 39936, 
                    "FileType": "CL_TYPE_MSOLE2", 
                    "HasMacros": true, 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.005"
                    ], 
                    "RiskScore": 5, 
                    "Streams": [
                        "o", 
                        "_1_compobj", 
                        "_3_vbframe", 
                        "f", 
                        "projectwm", 
                        "window1", 
                        "thisdocument", 
                        "_vba_project", 
                        "module1", 
                        "module3", 
                        "module2", 
                        "strix", 
                        "dir", 
                        "project"
                    ], 
                    "Yara": [
                        {
                            "Autorun_VBA_OFFICE": {
                                "description": "Macro autorun", 
                                "score": 4
                            }
                        }, 
                        {
                            "OLE_EMBEDDED_OFFICE": {
                                "description": "MS Forms Embedded object", 
                                "score": 5
                            }
                        }, 
                        {
                            "Contains_VBA_macro_code": {
                                "description": "Detect a MS Office document with embedded VBA macro code", 
                                "score": 4
                            }
                        }, 
                        {
                            "Filesystem_Vba_OFFICE": {
                                "description": "Macro acces file system object with AutoOpen", 
                                "score": 5
                            }
                        }
                    ]
                }, 
                {
                    "ExtractInfo": [
                        {
                            "EMAIL": "('Im,@K', '')"
                        }, 
                        {
                            "IPV6": "::"
                        }
                    ], 
                    "FileMD5": "e932c3ba84ba2136bbe887b1254afb01", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 20595, 
                    "FileType": "CL_TYPE_GRAPHICS", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.006"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/drawingml/2006/main\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/thememl/2012/main\"', '\"')"
                        }
                    ], 
                    "FileMD5": "3191d541839e4d100931377c4c66e0a1", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 6850, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.007"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/markup-compatibility/2006\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/math\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/wordprocessingml/2006/main\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2012/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2015/wordml/symex\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/schemaLibrary/2006/main\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word\"', '\"')"
                        }
                    ], 
                    "FileMD5": "0e05f5fa4d7d9ba3d121e3256b258612", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 10483, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.008"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/drawing/2014/chartex\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/markup-compatibility/2006\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/math\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/wordprocessingml/2006/main\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2012/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2015/wordml/symex\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordprocessingGroup\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordprocessingInk\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2006/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordprocessingShape\"', '\"')"
                        }
                    ], 
                    "FileMD5": "50cc63ff6a12de92356de52f57adf3e3", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 1828, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.009"
                    ], 
                    "RiskScore": 4, 
                    "Yara": [
                        {
                            "Autorun_VBA_OFFICE": {
                                "description": "Macro autorun", 
                                "score": 4
                            }
                        }
                    ]
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship', 'p')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXmlProps\"', '\"')"
                        }
                    ], 
                    "FileMD5": "7e5e23715ab49ce56f9130d4c6534a30", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 296, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.010"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/customXml\"><ds:schemaRefs><ds:schemaRef', 'f')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/bibliography\"/></ds:schemaRefs></ds:datastoreItem>', '')"
                        }
                    ], 
                    "FileMD5": "17882ebab97c0d9c2098e1e489d6b49c", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 341, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.011"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/bibliography\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/bibliography\"', '\"')"
                        }
                    ], 
                    "FileMD5": "217ee5ba5f9835428ff1ab7501faf018", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 306, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.012"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes\"><Template>Normal.dotm</Template><TotalTime>0</TotalTime><Pages>2</Pages><Words>1</Words><Characters>6</Characters><Application>Microsoft', 't')"
                        }
                    ], 
                    "FileMD5": "e4dc388c5b665ba7030de6e50cde8add", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 993, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.013"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/package/2006/metadata/core-properties\"', '\"')"
                        }, 
                        {
                            "URI": "('http://purl.org/dc/elements/1.1/\"', '\"')"
                        }, 
                        {
                            "URI": "('http://purl.org/dc/terms/\"', '\"')"
                        }, 
                        {
                            "URI": "('http://purl.org/dc/dcmitype/\"', '\"')"
                        }, 
                        {
                            "URI": "('http://www.w3.org/2001/XMLSchema-instance\"><dc:title></dc:title><dc:subject></dc:subject><dc:creator>1</dc:creator><cp:keywords></cp:keywords><dc:description></dc:description><cp:lastModifiedBy>1</cp:lastModifiedBy><cp:revision>2</cp:revision><dcterms:created', 'd')"
                        }
                    ], 
                    "FileMD5": "abd46fbaf5ad78913bc85bfe69385a8c", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 959, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.014"
                    ], 
                    "RiskScore": 6, 
                    "Yara": [
                        {
                            "XMLHTTP_Vba_OFFICE": {
                                "description": "Macro use XMLHTTP", 
                                "score": 4
                            }
                        }, 
                        {
                            "Download_Vba_OFFICE": {
                                "description": "Macro use download function with AutoOpen", 
                                "score": 6
                            }
                        }
                    ]
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/markup-compatibility/2006\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/wordprocessingml/2006/main\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2012/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2015/wordml/symex\"', '\"')"
                        }
                    ], 
                    "FileMD5": "3cdd557e84bbb1f9815c181f8ed4c245", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 29715, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.015"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/markup-compatibility/2006\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/wordprocessingml/2006/main\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2012/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2015/wordml/symex\"', '\"')"
                        }
                    ], 
                    "FileMD5": "d6147024db17aa5d980f14b31fb1461f", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 1299, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.016"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }, 
                {
                    "ExtractInfo": [
                        {
                            "URI": "('http://schemas.openxmlformats.org/markup-compatibility/2006\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/officeDocument/2006/relationships\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.openxmlformats.org/wordprocessingml/2006/main\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2010/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2012/wordml\"', '\"')"
                        }, 
                        {
                            "URI": "('http://schemas.microsoft.com/office/word/2015/wordml/symex\"', '\"')"
                        }
                    ], 
                    "FileMD5": "261ba76e04bd8ddbd0f4e7a50d02f4c7", 
                    "FileParentType": "->CL_TYPE_PDF->CL_TYPE_OOXML_WORD->CL_TYPE_TEXT_ASCII", 
                    "FileSize": 576, 
                    "FileType": "CL_TYPE_TEXT_ASCII", 
                    "PathFile": [
                        "/tmp/tmpUee2rj/clamav-db2fb8735edd56037594f963ea05195f.tmp/zip.017"
                    ], 
                    "RiskScore": 0, 
                    "Yara": []
                }
            ], 
            "CoreProperties": {
                "Attributes": {
                    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties", 
                    "dc": "http://purl.org/dc/elements/1.1/", 
                    "dcmitype": "http://purl.org/dc/dcmitype/", 
                    "dcterms": "http://purl.org/dc/terms/", 
                    "xsi": "http://www.w3.org/2001/XMLSchema-instance"
                }, 
                "Author": {
                    "Value": [
                        1
                    ]
                }, 
                "ContentStatus": {
                    "Value": [
                        "Microsoft.XMLHTTPLOVEISAdodb.streaMLOVEISshell.ApplicationLOVEISWscript.shellLOVEISProcessLOVEISGeTLOVEISTeMPLOVEISTypeLOVEISopenLOVEISwriteLOVEISresponseBodyLOVEISsavetofileLOVEIS\\drefudre.exe"
                    ]
                }, 
                "Created": {
                    "Value": [
                        "2017-05-15T09:18:00Z"
                    ]
                }, 
                "Description": {}, 
                "Keywords": {}, 
                "LastAuthor": {
                    "Value": [
                        1
                    ]
                }, 
                "Modified": {
                    "Value": [
                        "2017-05-15T09:18:00Z"
                    ]
                }, 
                "Revision": {
                    "Value": [
                        2
                    ]
                }, 
                "Subject": {}, 
                "Title": {}
            }, 
            "CorePropertiesFileCount": 1, 
            "ExtendedProperties": {
                "AppVersion": {
                    "Value": [
                        "16.0000"
                    ]
                }, 
                "Application": {
                    "Value": [
                        "Microsoft Office Word"
                    ]
                }, 
                "Attributes": {
                    "vt": "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes", 
                    "xmlns": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
                }, 
                "Characters": {
                    "Value": [
                        6
                    ]
                }, 
                "CharactersWithSpaces": {
                    "Value": [
                        6
                    ]
                }, 
                "Company": {}, 
                "DocSecurity": {
                    "Value": [
                        0
                    ]
                }, 
                "HyperlinksChanged": {
                    "Value": [
                        false
                    ]
                }, 
                "Lines": {
                    "Value": [
                        1
                    ]
                }, 
                "LinksUpToDate": {
                    "Value": [
                        false
                    ]
                }, 
                "Pages": {
                    "Value": [
                        2
                    ]
                }, 
                "Paragraphs": {
                    "Value": [
                        1
                    ]
                }, 
                "ScaleCrop": {
                    "Value": [
                        false
                    ]
                }, 
                "SharedDocs": {
                    "Value": [
                        false
                    ]
                }, 
                "Template": {
                    "Value": [
                        "Normal.dotm"
                    ]
                }, 
                "TotalTime": {
                    "Value": [
                        0
                    ]
                }, 
                "Words": {
                    "Value": [
                        1
                    ]
                }
            }, 
            "ExtendedPropertiesFileCount": 1, 
            "ExtractInfo": [
                {
                    "EMAIL": "('Im,@K', '')"
                }, 
                {
                    "IPV6": "::"
                }, 
                {
                    "IPV6": "::"
                }, 
                {
                    "IPV6": "::"
                }
            ], 
            "FileMD5": "f115d1fe4f579841c054b03d1ba29c97", 
            "FileParentType": "->CL_TYPE_PDF", 
            "FileSize": 55486, 
            "FileType": "CL_TYPE_OOXML_WORD", 
            "PathFile": [
                "/tmp/tmpUee2rj/clamav-045d58bc73c112b37f188cb704ca54f6.tmp/pdf00_01i"
            ], 
            "RiskScore": 4, 
            "Yara": [
                {
                    "Contains_VBA_macro_code": {
                        "description": "Detect a MS Office document with embedded VBA macro code", 
                        "score": 4
                    }
                }
            ]
        }, 
        {
            "ExtractInfo": [
                {
                    "URI": "(\"http://www.geoplugin.net/json.gp?jsoncallback=JSON_CALLBACK').then(function\", 'n')"
                }
            ], 
            "FileMD5": "4f1d0119bae3797e905b2e8f2f92df90", 
            "FileParentType": "->CL_TYPE_PDF", 
            "FileSize": 6432, 
            "FileType": "CL_TYPE_TEXT_ASCII", 
            "PathFile": [
                "/tmp/tmpUee2rj/clamav-045d58bc73c112b37f188cb704ca54f6.tmp/pdf01_01i"
            ], 
            "RiskScore": 0, 
            "Yara": []
        }, 
        {
            "ExtractInfo": [], 
            "FileMD5": "19874245d5e732f1073758e3a9431e5d", 
            "FileParentType": "->CL_TYPE_PDF", 
            "FileSize": 67, 
            "FileType": "CL_TYPE_TEXT_ASCII", 
            "PathFile": [
                "/tmp/tmpUee2rj/clamav-045d58bc73c112b37f188cb704ca54f6.tmp/pdf03_01i"
            ], 
            "RiskScore": 0, 
            "Yara": []
        }, 
        {
            "ExtractInfo": [], 
            "FileMD5": "caf34a525d2c871e6df8233afb84beea", 
            "FileParentType": "->CL_TYPE_PDF", 
            "FileSize": 16, 
            "FileType": "CL_TYPE_TEXT_ASCII", 
            "PathFile": [
                "/tmp/tmpUee2rj/clamav-045d58bc73c112b37f188cb704ca54f6.tmp/pdf04"
            ], 
            "RiskScore": 0, 
            "Yara": []
        }, 
        {
            "ContainedObjects": [], 
            "ExtractInfo": [], 
            "FileMD5": "d41d8cd98f00b204e9800998ecf8427e", 
            "FileParentType": "->CL_TYPE_PDF", 
            "FileSize": 0, 
            "FileType": "CL_TYPE_UNKNOWN", 
            "PathFile": [
                "/tmp/tmpUee2rj/clamav-045d58bc73c112b37f188cb704ca54f6.tmp/pdf02"
            ], 
            "RiskScore": 0, 
            "Yara": []
        }
    ], 
    "ExtractInfo": [
        {
            "EMAIL": "('Z7@0j', '')"
        }
    ], 
    "FileMD5": "eb680f46c268e6eac359b574538de569", 
    "FileSize": 53257, 
    "FileType": "CL_TYPE_PDF", 
    "GlobalRiskScore": 6, 
    "GlobalRiskScoreCoef": 1, 
    "Magic": "CLAMJSONv0", 
    "PDFStats": {
        "CreationDate": "D:20170515122212+03'00'", 
        "Creator": "8026155", 
        "DeflateObjectCount": 4, 
        "EmbeddedFileCount": 1, 
        "ImageCount": 1, 
        "JavaScriptObjectCount": 3, 
        "JavascriptObjects": [
            7, 
            13, 
            14
        ], 
        "ModificationDate": "D:20170515122212+03'00'", 
        "ObjectsWithoutDictionaries": [
            3
        ], 
        "OpenActionCount": 1, 
        "PDFVersion": "1.4", 
        "PageCount": 1, 
        "Producer": "\u5469\u7865\u5374\u6168\u7072\u2092\u2e35\u2e35\u3031\ua920\u3032\u3030\u322d\u3130\u2036\u5469\u7865\u2074\u7247"
    }, 
    "RiskScore": 0, 
    "RootFileType": "CL_TYPE_PDF", 
    "TempDirExtract": "/tmp/tmpUee2rj", 
    "Yara": []
}
```

## Requirements

- clamav
- python: yara, pydot, hashlib, zlib, json, pyparsing
- For Image OCR: tesseract-ocr-all (deb)
## Install

~~~
Recompile clamav with json options and HARDENING compilation
./remake_clamav.sh
~~~

### Docker install

~~~
git clone https://github.com/lprat/static_file_analysis
cd static_file_analysis/docker
mkdir /tmp/samples && cp file_to_analyz.pdf /tmp/samples
docker-compose run sfa
$python analysis.py -c /opt/static_file_analysis/clamav-devel/clamscan/clamscan -g -f /tmp/file_to_analyz.pdf -y yara_rules/  -j /tmp/log.json -p pattern.db -v &> /tmp/
log
~~~

### Docker install API REST

~~~
git clone https://github.com/lprat/static_file_analysis
cd static_file_analysis/docker
#edit file docker-compose_api.yaml and change ENV APIKEY & UPDATE PROXY (if need)
docker-compose -f docker-compose_api.yml run sfa
~~~

## Configure

- coef.conf : file configuration for evaluating coefficient score
- pattern.db : file configuration with extracting pattern
- yara_rules/ : directory which contains yara rules

## Make your own yara rules

To create yara rules with this tool, you must use meta field:
- description: description of the rule
- weight: the score of the rule
- var_match: optionnal, you can add extern var if rule match for subsequent check (variable global - on all files)
- check_level2: optionnal, you can add extern var used to choice level 2 check (value: "check_command_bool,check_registry_bool") (variable local - only on current files)

You can use extern variables build with clamav context and send them to yara with python script (analysis.py):
- PathFile: filename and path
- FileParentType: parent type of file, it's written as clamav output
- FileType: Type of current file, it's written as clamav output
- FileSize: Size of current fuke
- FileMD5: MD5 of current file
- CDBNAME: Original name of current file (exemple in MACRO file, or CHM file...)
- zip_crypt_bool: Zip file with password (crypted)
- EMBED_FILES: if zip file with password, variable contains filenames in zip file
- image2text: if image file you can extract text with ocr (tesseract => !! attention Leptonica have CVE-2018..., on debian, tesseract compiled with hardening option security)
- serr: Debug flux of clamav
- now_7_int: timstamp of now-7j
- All variables make in json report of clamav
- All informations extracted by pattern match

Check in path yara_rules for view samples! 

## Use tool in CRITS

I added this tool in CRITS services. I created pull request in CRITS service but it's not validated yet , but you can use my github repository so far.

[Collaborative Research Into Threats - CRITS](https://crits.github.io/)

[Github CRITS services](https://github.com/crits/crits_services)

[My Github account of modified CRITS services](https://github.com/lprat/crits_services/tree/extract_embedded_service)

## Use API REST

Run docker compose or docker run for launch api

~~~
docker-compose -f ./docker-compose_api.yml run sfa
or
docker run -ti -e "API_KEY=myapikey" -p 8000:8000 docker_sfa
~~~

Request on port 8000:

~~~
curl -k  -F 'file=@/home/lionel/malwares/calc.xll' -H "x-api-key: mykeyapi" https://127.0.0.1:8000/api/sfa_check_file
Return score of file in field "risk_score" or '-1' if error to scan
~~~

## Trick for pdf analysis
$pdftk infector1.pdf output infector1_uncompress.pdf uncompress

## Extra
In Sigma_rules, you can find rule format SIGMA for detect files to analyse.

## Greetz

Stéphane L. for contributing!

## Contact

lionel.prat9@gmail.com
