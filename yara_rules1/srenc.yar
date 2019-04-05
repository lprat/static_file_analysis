rule screnc {
        meta:
                description = "Files encrypted by ScrEnc malware"
                author = "Lionel PRAT"
                version = "0.1"
                weight = 10
                reference = "https://app.any.run/tasks/c716073b-3864-4054-8119-f308864d5e09"
                tag = "attack.initial_access,attack.defense_evasion,attack.execution"
        condition:
            FileType matches /CL_TYPE_SCRENC/
}

