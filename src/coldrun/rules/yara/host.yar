// Text-level rules for any script language. Each flags behaviour aimed at the
// host, never traffic to a target. meta.severity feeds the verdict.

rule download_exec
{
    meta:
        severity = "high"
        description = "Pipes or substitutes something downloaded straight into a shell or interpreter"
    strings:
        $pipe   = /(curl|wget|fetch)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b/
        $pipepy = /(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(python[23]?|perl|ruby|node)\b/
        $subst  = /(bash|sh|zsh|python[23]?|perl|eval)\s+(-c\s+)?["']?[<$]\(\s*(curl|wget)\b/
    condition:
        any of them
}

rule persistence_cron
{
    meta:
        severity = "high"
        description = "Installs a cron job, so the script keeps running after it ends"
    strings:
        $append = /\(\s*crontab\s+-l/
        $stdin  = /crontab\s+-\s*$/
        $file   = /crontab\s+["']?[\/.~$][^\n]{0,80}$/
        $spool  = /\/var\/spool\/cron\//
        $etc    = /\/etc\/cron\.(d|daily|hourly|weekly|monthly)\//
    condition:
        any of them
}

rule persistence_shell_rc
{
    meta:
        severity = "high"
        description = "Appends to a shell start-up file, so it runs every time a terminal opens"
    strings:
        $redirect = />>?\s*["']?(\$HOME|\$\{HOME\}|~)\/\.(bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|zlogin|config\/fish\/config\.fish)\b/
        $python   = /\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv)["'][^\n]{0,40}["']a["']/
        $tee      = /tee\s+-a\s+["']?(\$HOME|\$\{HOME\}|~)\/\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv)\b/
    condition:
        any of them
}

rule persistence_service
{
    meta:
        severity = "high"
        description = "Registers a systemd unit, autostart entry or other boot-time hook"
    strings:
        $unit    = />\s*["']?(\/etc\/systemd\/system|\/usr\/lib\/systemd\/system|\$HOME\/\.config\/systemd\/user|~\/\.config\/systemd\/user)\/[^\n]{0,60}\.(service|timer)/
        $enable  = /systemctl\s+(--user\s+)?(enable|link)\b/
        $desktop = /\.config\/autostart\/[^\n]{0,60}\.desktop/
        $rclocal = /\/etc\/rc\.local/
        $preload = /\/etc\/ld\.so\.preload/
        $pyunit  = /(systemd\/system|systemd\/user)\/[^\n]{0,60}\.service["'][^\n]{0,40}["']w["']/
    condition:
        any of them
}

rule credential_paths
{
    meta:
        severity = "medium"
        description = "Touches SSH keys, cloud or browser credential files on the host"
    strings:
        $dot     = /(~|\$HOME|\$\{HOME\}|HOME|expanduser)[^\n]{0,30}\/\.(ssh\/(id_[a-z0-9]+|authorized_keys|config)|aws\/credentials|gnupg|docker\/config\.json|kube\/config|netrc|git-credentials|config\/gcloud|azure|bash_history|zsh_history)\b/
        $browser = /(Login Data|key4\.db|logins\.json|cookies\.sqlite|\.mozilla\/firefox|google-chrome\/Default|BraveSoftware|chromium\/Default)/
        $keys    = /\/\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/
    condition:
        any of them
}

rule obfuscated_shell
{
    meta:
        severity = "high"
        description = "Decodes or unescapes a command at runtime before running it"
    strings:
        $evalb64  = /eval\s+["']?\$\(\s*(echo|printf)\b[^\n]{0,300}base64\s+(-d|--decode|-D)\b/
        $b64pipe  = /(base64\s+(-d|--decode|-D)|openssl\s+enc\s+-d|xxd\s+-r)\b[^\n]{0,80}\|\s*(sudo\s+)?(ba|z|da)?sh\b/
        $hexcmd   = /\$\(\s*printf\s+["'](\\x[0-9a-fA-F]{2}){6,}/
        $evalrev  = /eval\s+["']?\$\(\s*(echo|printf)\b[^\n]{0,200}\|\s*rev\b/
    condition:
        any of them
}

rule encoded_blob
{
    meta:
        severity = "medium"
        description = "Carries a large encoded blob and decodes it, a payload the reader cannot review"
    strings:
        $blob   = /["'][A-Za-z0-9+\/=]{200,}["']/
        $decode = /(base64\s+(-d|--decode|-D)|b64decode|b32decode|a85decode|b85decode|fromhex|unhexlify|zlib\.decompress|marshal\.loads)/
    condition:
        $blob and $decode
}
