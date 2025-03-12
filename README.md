# Rapid7 Automatic Agent Install

Rapid7 agent installation with enrichment logs, audit.d installation and configuration.

1. Download the script
`git clone git@github.com:esmeraldino-lk/Rapid7LinuxAutoInstall.git`
2. Use to install:
`/bin/bash rapid7-agent-install.sh [RAPID7 INSTALL TOKEN]`
4. Verify auditd and rapid7_agent status
`systemctl status auditd`
`systemctl status ir_agent`
