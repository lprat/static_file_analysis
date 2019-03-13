rule ACE_file {
    meta:
        author = "Florian Roth - based on Nick Hoffman' rule - Morphick Inc -- Modified by Lionel PRAT"
        description = "Looks for ACE Archives"
        date = "2015-09-09"
        weight = 5
        tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194"
    strings:
        $header = { 2a 2a 41 43 45 2a 2a }

    condition:
        $header at 7
}

