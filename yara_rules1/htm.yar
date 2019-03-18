rule html_file {
    meta:
        author = "Lionel PRAT"
        description = "File content html code"
        version = "0.1"
        weight = 1
        var_match = "html_file_bool"
    strings:
        $magic1 = "<html>"
        $magic2 = "</html>"
    condition:
        ($magic1 and $magic2) or PathFile matches /.*\.htm[.]{0,1}$/i or CDBNAME matches /.*\.htm[.]{0,1}$/i
}
